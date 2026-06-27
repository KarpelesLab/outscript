package outscript

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"

	"github.com/KarpelesLab/base58"
)

// SolanaKey is a 32-byte public key used to identify accounts on the Solana network.
type SolanaKey [32]byte

// SolanaSystemProgram is the address of the Solana System Program.
var SolanaSystemProgram = mustParseSolanaKey("11111111111111111111111111111111")

func mustParseSolanaKey(s string) SolanaKey {
	k, err := ParseSolanaKey(s)
	if err != nil {
		panic(err)
	}
	return k
}

// ParseSolanaKey parses a base58-encoded string into a SolanaKey.
func ParseSolanaKey(s string) (SolanaKey, error) {
	buf, err := base58.Bitcoin.Decode(s)
	if err != nil {
		return SolanaKey{}, fmt.Errorf("failed to decode solana key: %w", err)
	}
	if len(buf) != 32 {
		return SolanaKey{}, fmt.Errorf("invalid solana key: expected 32 bytes, got %d", len(buf))
	}
	var k SolanaKey
	copy(k[:], buf)
	return k, nil
}

// String returns the base58 encoding of the key.
func (k SolanaKey) String() string {
	return base58.Bitcoin.Encode(k[:])
}

// IsZero reports whether the key is all zeros.
func (k SolanaKey) IsZero() bool {
	return k == SolanaKey{}
}

// SolanaAccountMeta describes an account referenced by an instruction.
type SolanaAccountMeta struct {
	Pubkey     SolanaKey
	IsSigner   bool
	IsWritable bool
}

// SolanaInstruction is a high-level instruction before account compilation.
type SolanaInstruction struct {
	ProgramID SolanaKey
	Accounts  []SolanaAccountMeta
	Data      []byte
}

// SolanaTransferInstruction returns a System Program transfer instruction
// that moves lamports from one account to another.
func SolanaTransferInstruction(from, to SolanaKey, lamports uint64) SolanaInstruction {
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data[0:4], 2) // Transfer instruction index
	binary.LittleEndian.PutUint64(data[4:12], lamports)
	return SolanaInstruction{
		ProgramID: SolanaSystemProgram,
		Accounts: []SolanaAccountMeta{
			{Pubkey: from, IsSigner: true, IsWritable: true},
			{Pubkey: to, IsSigner: false, IsWritable: true},
		},
		Data: data,
	}
}

// SolanaMessageHeader contains the counts needed to distinguish signer and
// readonly accounts in a transaction message.
type SolanaMessageHeader struct {
	NumRequiredSignatures       uint8
	NumReadonlySignedAccounts   uint8
	NumReadonlyUnsignedAccounts uint8
}

// SolanaCompiledInstruction is an instruction with account references replaced
// by indices into the message's account key array.
type SolanaCompiledInstruction struct {
	ProgramIDIndex uint8
	AccountIndices []uint8
	Data           []byte
}

// SolanaMessage is the message portion of a legacy Solana transaction.
type SolanaMessage struct {
	Header          SolanaMessageHeader
	AccountKeys     []SolanaKey
	RecentBlockhash SolanaKey
	Instructions    []SolanaCompiledInstruction
}

// SolanaAddressTableLookup describes a lookup into an address lookup table
// for v0 versioned transactions.
type SolanaAddressTableLookup struct {
	AccountKey      SolanaKey
	WritableIndexes []uint8
	ReadonlyIndexes []uint8
}

// SolanaMessageV0 is a versioned (v0) message with address lookup table support.
type SolanaMessageV0 struct {
	Header              SolanaMessageHeader
	AccountKeys         []SolanaKey
	RecentBlockhash     SolanaKey
	Instructions        []SolanaCompiledInstruction
	AddressTableLookups []SolanaAddressTableLookup
}

// SolanaTx represents a Solana transaction (legacy or versioned).
// When MessageV0 is non-nil, the transaction is a v0 versioned transaction.
type SolanaTx struct {
	Signatures [][]byte
	Message    SolanaMessage    // used for legacy transactions
	MessageV0  *SolanaMessageV0 // non-nil for v0 versioned transactions
}

// solanaAccountInfo tracks the merged permissions for a single account during compilation.
type solanaAccountInfo struct {
	key        SolanaKey
	isSigner   bool
	isWritable bool
}

// NewSolanaTx compiles a set of high-level instructions into a transaction.
// The fee payer is always placed first in the account list as a writable signer.
func NewSolanaTx(feePayer, recentBlockhash SolanaKey, instructions ...SolanaInstruction) (*SolanaTx, error) {
	// Collect and deduplicate accounts, merging permissions.
	seen := make(map[SolanaKey]*solanaAccountInfo)

	// Fee payer is always signer + writable.
	seen[feePayer] = &solanaAccountInfo{key: feePayer, isSigner: true, isWritable: true}

	for _, ix := range instructions {
		for _, acc := range ix.Accounts {
			if info, ok := seen[acc.Pubkey]; ok {
				info.isSigner = info.isSigner || acc.IsSigner
				info.isWritable = info.isWritable || acc.IsWritable
			} else {
				seen[acc.Pubkey] = &solanaAccountInfo{
					key:        acc.Pubkey,
					isSigner:   acc.IsSigner,
					isWritable: acc.IsWritable,
				}
			}
		}
		// Program IDs are added as non-signer, readonly (unless already present with higher perms).
		if _, ok := seen[ix.ProgramID]; !ok {
			seen[ix.ProgramID] = &solanaAccountInfo{
				key:        ix.ProgramID,
				isSigner:   false,
				isWritable: false,
			}
		}
	}

	// Sort accounts into 4 groups:
	// 1. signer + writable
	// 2. signer + readonly
	// 3. non-signer + writable
	// 4. non-signer + readonly
	// Within each group, maintain stable order (fee payer always first overall).
	var signerWritable, signerReadonly, nonsignerWritable, nonsignerReadonly []solanaAccountInfo
	for _, info := range seen {
		if info.key == feePayer {
			continue // handled separately
		}
		switch {
		case info.isSigner && info.isWritable:
			signerWritable = append(signerWritable, *info)
		case info.isSigner && !info.isWritable:
			signerReadonly = append(signerReadonly, *info)
		case !info.isSigner && info.isWritable:
			nonsignerWritable = append(nonsignerWritable, *info)
		default:
			nonsignerReadonly = append(nonsignerReadonly, *info)
		}
	}

	// Stable sort each group by key bytes for deterministic ordering.
	sortByKey := func(s []solanaAccountInfo) {
		sort.SliceStable(s, func(i, j int) bool {
			return slices.Compare(s[i].key[:], s[j].key[:]) < 0
		})
	}
	sortByKey(signerWritable)
	sortByKey(signerReadonly)
	sortByKey(nonsignerWritable)
	sortByKey(nonsignerReadonly)

	// Build the final account list.
	feePayerInfo := *seen[feePayer]
	allAccounts := make([]solanaAccountInfo, 0, len(seen))
	allAccounts = append(allAccounts, feePayerInfo)
	allAccounts = append(allAccounts, signerWritable...)
	allAccounts = append(allAccounts, signerReadonly...)
	allAccounts = append(allAccounts, nonsignerWritable...)
	allAccounts = append(allAccounts, nonsignerReadonly...)

	if len(allAccounts) > 256 {
		return nil, fmt.Errorf("transaction has %d accounts, maximum is 256", len(allAccounts))
	}

	// Build index map.
	indexMap := make(map[SolanaKey]uint8, len(allAccounts))
	accountKeys := make([]SolanaKey, len(allAccounts))
	for i, acc := range allAccounts {
		indexMap[acc.key] = uint8(i)
		accountKeys[i] = acc.key
	}

	// Compute header counts.
	numSigners := 1 + len(signerWritable) + len(signerReadonly) // +1 for fee payer
	numReadonlySigned := len(signerReadonly)
	numReadonlyUnsigned := len(nonsignerReadonly)

	// Compile instructions.
	compiled := make([]SolanaCompiledInstruction, len(instructions))
	for i, ix := range instructions {
		indices := make([]uint8, len(ix.Accounts))
		for j, acc := range ix.Accounts {
			indices[j] = indexMap[acc.Pubkey]
		}
		compiled[i] = SolanaCompiledInstruction{
			ProgramIDIndex: indexMap[ix.ProgramID],
			AccountIndices: indices,
			Data:           ix.Data,
		}
	}

	msg := SolanaMessage{
		Header: SolanaMessageHeader{
			NumRequiredSignatures:       uint8(numSigners),
			NumReadonlySignedAccounts:   uint8(numReadonlySigned),
			NumReadonlyUnsignedAccounts: uint8(numReadonlyUnsigned),
		},
		AccountKeys:     accountKeys,
		RecentBlockhash: recentBlockhash,
		Instructions:    compiled,
	}

	return &SolanaTx{
		Signatures: make([][]byte, numSigners),
		Message:    msg,
	}, nil
}

// NewSolanaTxV0 compiles a set of high-level instructions into a v0 versioned
// transaction with address lookup table support. The lookups parameter specifies
// which address lookup tables to reference. Accounts resolved through lookup
// tables are not included in the static account key list.
func NewSolanaTxV0(feePayer, recentBlockhash SolanaKey, lookups []SolanaAddressTableLookup, instructions ...SolanaInstruction) (*SolanaTx, error) {
	// Compile static accounts the same way as legacy transactions.
	seen := make(map[SolanaKey]*solanaAccountInfo)
	seen[feePayer] = &solanaAccountInfo{key: feePayer, isSigner: true, isWritable: true}

	for _, ix := range instructions {
		for _, acc := range ix.Accounts {
			if info, ok := seen[acc.Pubkey]; ok {
				info.isSigner = info.isSigner || acc.IsSigner
				info.isWritable = info.isWritable || acc.IsWritable
			} else {
				seen[acc.Pubkey] = &solanaAccountInfo{
					key:        acc.Pubkey,
					isSigner:   acc.IsSigner,
					isWritable: acc.IsWritable,
				}
			}
		}
		if _, ok := seen[ix.ProgramID]; !ok {
			seen[ix.ProgramID] = &solanaAccountInfo{
				key:        ix.ProgramID,
				isSigner:   false,
				isWritable: false,
			}
		}
	}

	var signerWritable, signerReadonly, nonsignerWritable, nonsignerReadonly []solanaAccountInfo
	for _, info := range seen {
		if info.key == feePayer {
			continue
		}
		switch {
		case info.isSigner && info.isWritable:
			signerWritable = append(signerWritable, *info)
		case info.isSigner && !info.isWritable:
			signerReadonly = append(signerReadonly, *info)
		case !info.isSigner && info.isWritable:
			nonsignerWritable = append(nonsignerWritable, *info)
		default:
			nonsignerReadonly = append(nonsignerReadonly, *info)
		}
	}

	sortByKey := func(s []solanaAccountInfo) {
		sort.SliceStable(s, func(i, j int) bool {
			return slices.Compare(s[i].key[:], s[j].key[:]) < 0
		})
	}
	sortByKey(signerWritable)
	sortByKey(signerReadonly)
	sortByKey(nonsignerWritable)
	sortByKey(nonsignerReadonly)

	feePayerInfo := *seen[feePayer]
	allAccounts := make([]solanaAccountInfo, 0, len(seen))
	allAccounts = append(allAccounts, feePayerInfo)
	allAccounts = append(allAccounts, signerWritable...)
	allAccounts = append(allAccounts, signerReadonly...)
	allAccounts = append(allAccounts, nonsignerWritable...)
	allAccounts = append(allAccounts, nonsignerReadonly...)

	if len(allAccounts) > 256 {
		return nil, fmt.Errorf("transaction has %d accounts, maximum is 256", len(allAccounts))
	}

	indexMap := make(map[SolanaKey]uint8, len(allAccounts))
	accountKeys := make([]SolanaKey, len(allAccounts))
	for i, acc := range allAccounts {
		indexMap[acc.key] = uint8(i)
		accountKeys[i] = acc.key
	}

	numSigners := 1 + len(signerWritable) + len(signerReadonly)
	numReadonlySigned := len(signerReadonly)
	numReadonlyUnsigned := len(nonsignerReadonly)

	compiled := make([]SolanaCompiledInstruction, len(instructions))
	for i, ix := range instructions {
		indices := make([]uint8, len(ix.Accounts))
		for j, acc := range ix.Accounts {
			indices[j] = indexMap[acc.Pubkey]
		}
		compiled[i] = SolanaCompiledInstruction{
			ProgramIDIndex: indexMap[ix.ProgramID],
			AccountIndices: indices,
			Data:           ix.Data,
		}
	}

	msg := &SolanaMessageV0{
		Header: SolanaMessageHeader{
			NumRequiredSignatures:       uint8(numSigners),
			NumReadonlySignedAccounts:   uint8(numReadonlySigned),
			NumReadonlyUnsignedAccounts: uint8(numReadonlyUnsigned),
		},
		AccountKeys:         accountKeys,
		RecentBlockhash:     recentBlockhash,
		Instructions:        compiled,
		AddressTableLookups: lookups,
	}

	return &SolanaTx{
		Signatures: make([][]byte, numSigners),
		MessageV0:  msg,
	}, nil
}

// messageBytes returns the serialized message bytes, dispatching to the
// correct message version.
func (tx *SolanaTx) messageBytes() ([]byte, error) {
	if tx.MessageV0 != nil {
		return tx.MessageV0.MarshalBinary()
	}
	return tx.Message.MarshalBinary()
}

// messageHeader returns the header from the active message version.
func (tx *SolanaTx) messageHeader() SolanaMessageHeader {
	if tx.MessageV0 != nil {
		return tx.MessageV0.Header
	}
	return tx.Message.Header
}

// messageAccountKeys returns the static account keys from the active message version.
func (tx *SolanaTx) messageAccountKeys() []SolanaKey {
	if tx.MessageV0 != nil {
		return tx.MessageV0.AccountKeys
	}
	return tx.Message.AccountKeys
}

// Sign signs the transaction message with the provided Ed25519 private keys.
// Keys are matched to signature slots by their public key.
func (tx *SolanaTx) Sign(keys ...ed25519.PrivateKey) error {
	msgBytes, err := tx.messageBytes()
	if err != nil {
		return err
	}

	header := tx.messageHeader()
	accountKeys := tx.messageAccountKeys()
	numSigners := int(header.NumRequiredSignatures)
	if numSigners > len(accountKeys) {
		return fmt.Errorf("invalid header: %d required signers but only %d account keys", numSigners, len(accountKeys))
	}
	for _, key := range keys {
		pub := key.Public().(ed25519.PublicKey)
		var pubKey SolanaKey
		copy(pubKey[:], pub)

		idx := -1
		for i := 0; i < numSigners; i++ {
			if accountKeys[i] == pubKey {
				idx = i
				break
			}
		}
		if idx < 0 {
			return fmt.Errorf("key %s is not a required signer", pubKey)
		}
		sig := ed25519.Sign(key, msgBytes)
		tx.Signatures[idx] = sig
	}
	return nil
}

// Verify checks that all required signatures are present and valid Ed25519
// signatures over the serialized message.
func (tx *SolanaTx) Verify() error {
	msgBytes, err := tx.messageBytes()
	if err != nil {
		return fmt.Errorf("failed to serialize message: %w", err)
	}

	header := tx.messageHeader()
	accountKeys := tx.messageAccountKeys()
	numSigners := int(header.NumRequiredSignatures)
	if numSigners > len(accountKeys) {
		return fmt.Errorf("invalid header: %d required signers but only %d account keys", numSigners, len(accountKeys))
	}
	if len(tx.Signatures) < numSigners {
		return fmt.Errorf("expected %d signatures, got %d", numSigners, len(tx.Signatures))
	}

	for i := 0; i < numSigners; i++ {
		sig := tx.Signatures[i]
		if len(sig) != 64 {
			return fmt.Errorf("signature %d is missing or has invalid length %d", i, len(sig))
		}
		pubkey := accountKeys[i]
		if !ed25519.Verify(ed25519.PublicKey(pubkey[:]), msgBytes, sig) {
			return fmt.Errorf("signature %d (signer %s) verification failed", i, pubkey)
		}
	}
	return nil
}

// Hash returns the transaction ID, which is the first signature (64 bytes).
func (tx *SolanaTx) Hash() ([]byte, error) {
	if len(tx.Signatures) == 0 || len(tx.Signatures[0]) == 0 {
		return nil, errors.New("transaction has no signature")
	}
	return slices.Clone(tx.Signatures[0]), nil
}

// MarshalBinary serializes the transaction into the Solana wire format.
func (tx *SolanaTx) MarshalBinary() ([]byte, error) {
	msgBytes, err := tx.messageBytes()
	if err != nil {
		return nil, err
	}

	buf := solanaEncodeCompactU16(len(tx.Signatures))
	for _, sig := range tx.Signatures {
		if len(sig) == 0 {
			buf = append(buf, make([]byte, 64)...)
		} else {
			if len(sig) != 64 {
				return nil, fmt.Errorf("invalid signature length: %d", len(sig))
			}
			buf = append(buf, sig...)
		}
	}
	buf = append(buf, msgBytes...)
	return buf, nil
}

// UnmarshalBinary deserializes a transaction from the Solana wire format.
func (tx *SolanaTx) UnmarshalBinary(data []byte) error {
	r := data

	sigCount, n, err := solanaDecodeCompactU16(r)
	if err != nil {
		return fmt.Errorf("reading signature count: %w", err)
	}
	if sigCount > 256 {
		return fmt.Errorf("signature count %d exceeds maximum of 256", sigCount)
	}
	r = r[n:]

	tx.Signatures = make([][]byte, sigCount)
	for i := 0; i < sigCount; i++ {
		if len(r) < 64 {
			return io.ErrUnexpectedEOF
		}
		tx.Signatures[i] = slices.Clone(r[:64])
		r = r[64:]
	}

	// Detect versioned transaction: MSB of first message byte is set.
	if len(r) > 0 && r[0]&0x80 != 0 {
		version := r[0] & 0x7f
		if version != 0 {
			return fmt.Errorf("unsupported transaction version: %d", version)
		}
		tx.MessageV0 = &SolanaMessageV0{}
		return tx.MessageV0.UnmarshalBinary(r)
	}
	return tx.Message.UnmarshalBinary(r)
}

// MarshalBinary serializes the message into the Solana wire format.
func (msg *SolanaMessage) MarshalBinary() ([]byte, error) {
	buf := []byte{
		msg.Header.NumRequiredSignatures,
		msg.Header.NumReadonlySignedAccounts,
		msg.Header.NumReadonlyUnsignedAccounts,
	}

	buf = append(buf, solanaEncodeCompactU16(len(msg.AccountKeys))...)
	for _, key := range msg.AccountKeys {
		buf = append(buf, key[:]...)
	}

	buf = append(buf, msg.RecentBlockhash[:]...)

	buf = append(buf, solanaEncodeCompactU16(len(msg.Instructions))...)
	for _, ix := range msg.Instructions {
		buf = append(buf, ix.ProgramIDIndex)
		buf = append(buf, solanaEncodeCompactU16(len(ix.AccountIndices))...)
		buf = append(buf, ix.AccountIndices...)
		buf = append(buf, solanaEncodeCompactU16(len(ix.Data))...)
		buf = append(buf, ix.Data...)
	}

	return buf, nil
}

// UnmarshalBinary deserializes a message from the Solana wire format.
func (msg *SolanaMessage) UnmarshalBinary(data []byte) error {
	r := data

	if len(r) < 3 {
		return io.ErrUnexpectedEOF
	}
	msg.Header.NumRequiredSignatures = r[0]
	msg.Header.NumReadonlySignedAccounts = r[1]
	msg.Header.NumReadonlyUnsignedAccounts = r[2]
	r = r[3:]

	keyCount, n, err := solanaDecodeCompactU16(r)
	if err != nil {
		return fmt.Errorf("reading account key count: %w", err)
	}
	if keyCount > 256 {
		return fmt.Errorf("account key count %d exceeds maximum of 256", keyCount)
	}
	r = r[n:]

	msg.AccountKeys = make([]SolanaKey, keyCount)
	for i := 0; i < keyCount; i++ {
		if len(r) < 32 {
			return io.ErrUnexpectedEOF
		}
		copy(msg.AccountKeys[i][:], r[:32])
		r = r[32:]
	}

	if err := validateSolanaHeader(msg.Header, keyCount); err != nil {
		return err
	}

	if len(r) < 32 {
		return io.ErrUnexpectedEOF
	}
	copy(msg.RecentBlockhash[:], r[:32])
	r = r[32:]

	ixCount, n, err := solanaDecodeCompactU16(r)
	if err != nil {
		return fmt.Errorf("reading instruction count: %w", err)
	}
	r = r[n:]
	// Sanity cap: every instruction needs at least one byte (the program id
	// index), so the count cannot exceed the remaining bytes.
	if ixCount > len(r) {
		return fmt.Errorf("instruction count %d exceeds remaining bytes %d", ixCount, len(r))
	}

	msg.Instructions = make([]SolanaCompiledInstruction, ixCount)
	for i := 0; i < ixCount; i++ {
		if len(r) < 1 {
			return io.ErrUnexpectedEOF
		}
		msg.Instructions[i].ProgramIDIndex = r[0]
		r = r[1:]

		accCount, n, err := solanaDecodeCompactU16(r)
		if err != nil {
			return fmt.Errorf("reading account index count: %w", err)
		}
		r = r[n:]
		if len(r) < accCount {
			return io.ErrUnexpectedEOF
		}
		msg.Instructions[i].AccountIndices = slices.Clone(r[:accCount])
		r = r[accCount:]

		dataLen, n, err := solanaDecodeCompactU16(r)
		if err != nil {
			return fmt.Errorf("reading instruction data length: %w", err)
		}
		r = r[n:]
		if len(r) < dataLen {
			return io.ErrUnexpectedEOF
		}
		msg.Instructions[i].Data = slices.Clone(r[:dataLen])
		r = r[dataLen:]

		// Validate that program and account indexes reference real account
		// keys. For the legacy format the addressable set is exactly the
		// static account key list.
		if int(msg.Instructions[i].ProgramIDIndex) >= keyCount {
			return fmt.Errorf("instruction %d program id index %d out of range (%d account keys)", i, msg.Instructions[i].ProgramIDIndex, keyCount)
		}
		for _, ai := range msg.Instructions[i].AccountIndices {
			if int(ai) >= keyCount {
				return fmt.Errorf("instruction %d account index %d out of range (%d account keys)", i, ai, keyCount)
			}
		}
	}

	return nil
}

// MarshalBinary serializes the v0 message into the Solana wire format.
// The first byte is 0x80 (version prefix for v0), followed by the message body
// and address table lookups.
func (msg *SolanaMessageV0) MarshalBinary() ([]byte, error) {
	buf := []byte{
		0x80, // version prefix: 0x80 | 0 = v0
		msg.Header.NumRequiredSignatures,
		msg.Header.NumReadonlySignedAccounts,
		msg.Header.NumReadonlyUnsignedAccounts,
	}

	buf = append(buf, solanaEncodeCompactU16(len(msg.AccountKeys))...)
	for _, key := range msg.AccountKeys {
		buf = append(buf, key[:]...)
	}

	buf = append(buf, msg.RecentBlockhash[:]...)

	buf = append(buf, solanaEncodeCompactU16(len(msg.Instructions))...)
	for _, ix := range msg.Instructions {
		buf = append(buf, ix.ProgramIDIndex)
		buf = append(buf, solanaEncodeCompactU16(len(ix.AccountIndices))...)
		buf = append(buf, ix.AccountIndices...)
		buf = append(buf, solanaEncodeCompactU16(len(ix.Data))...)
		buf = append(buf, ix.Data...)
	}

	buf = append(buf, solanaEncodeCompactU16(len(msg.AddressTableLookups))...)
	for _, lookup := range msg.AddressTableLookups {
		buf = append(buf, lookup.AccountKey[:]...)
		buf = append(buf, solanaEncodeCompactU16(len(lookup.WritableIndexes))...)
		buf = append(buf, lookup.WritableIndexes...)
		buf = append(buf, solanaEncodeCompactU16(len(lookup.ReadonlyIndexes))...)
		buf = append(buf, lookup.ReadonlyIndexes...)
	}

	return buf, nil
}

// UnmarshalBinary deserializes a v0 message from the Solana wire format.
func (msg *SolanaMessageV0) UnmarshalBinary(data []byte) error {
	r := data

	// Consume version prefix byte.
	if len(r) < 1 {
		return io.ErrUnexpectedEOF
	}
	if r[0]&0x80 == 0 {
		return errors.New("not a versioned message: MSB not set")
	}
	version := r[0] & 0x7f
	if version != 0 {
		return fmt.Errorf("unsupported message version: %d", version)
	}
	r = r[1:]

	if len(r) < 3 {
		return io.ErrUnexpectedEOF
	}
	msg.Header.NumRequiredSignatures = r[0]
	msg.Header.NumReadonlySignedAccounts = r[1]
	msg.Header.NumReadonlyUnsignedAccounts = r[2]
	r = r[3:]

	keyCount, n, err := solanaDecodeCompactU16(r)
	if err != nil {
		return fmt.Errorf("reading account key count: %w", err)
	}
	if keyCount > 256 {
		return fmt.Errorf("account key count %d exceeds maximum of 256", keyCount)
	}
	r = r[n:]

	msg.AccountKeys = make([]SolanaKey, keyCount)
	for i := 0; i < keyCount; i++ {
		if len(r) < 32 {
			return io.ErrUnexpectedEOF
		}
		copy(msg.AccountKeys[i][:], r[:32])
		r = r[32:]
	}

	if err := validateSolanaHeader(msg.Header, keyCount); err != nil {
		return err
	}

	if len(r) < 32 {
		return io.ErrUnexpectedEOF
	}
	copy(msg.RecentBlockhash[:], r[:32])
	r = r[32:]

	ixCount, n, err := solanaDecodeCompactU16(r)
	if err != nil {
		return fmt.Errorf("reading instruction count: %w", err)
	}
	r = r[n:]
	// Sanity cap: every instruction needs at least one byte (the program id
	// index), so the count cannot exceed the remaining bytes.
	if ixCount > len(r) {
		return fmt.Errorf("instruction count %d exceeds remaining bytes %d", ixCount, len(r))
	}

	msg.Instructions = make([]SolanaCompiledInstruction, ixCount)
	for i := 0; i < ixCount; i++ {
		if len(r) < 1 {
			return io.ErrUnexpectedEOF
		}
		msg.Instructions[i].ProgramIDIndex = r[0]
		r = r[1:]

		accCount, n, err := solanaDecodeCompactU16(r)
		if err != nil {
			return fmt.Errorf("reading account index count: %w", err)
		}
		r = r[n:]
		if len(r) < accCount {
			return io.ErrUnexpectedEOF
		}
		msg.Instructions[i].AccountIndices = slices.Clone(r[:accCount])
		r = r[accCount:]

		dataLen, n, err := solanaDecodeCompactU16(r)
		if err != nil {
			return fmt.Errorf("reading instruction data length: %w", err)
		}
		r = r[n:]
		if len(r) < dataLen {
			return io.ErrUnexpectedEOF
		}
		msg.Instructions[i].Data = slices.Clone(r[:dataLen])
		r = r[dataLen:]
	}

	// Address table lookups (v0-specific).
	lookupCount, n, err := solanaDecodeCompactU16(r)
	if err != nil {
		return fmt.Errorf("reading address table lookup count: %w", err)
	}
	r = r[n:]
	// Sanity cap: every lookup needs at least one byte, so the count cannot
	// exceed the remaining bytes.
	if lookupCount > len(r) {
		return fmt.Errorf("address table lookup count %d exceeds remaining bytes %d", lookupCount, len(r))
	}

	msg.AddressTableLookups = make([]SolanaAddressTableLookup, lookupCount)
	for i := 0; i < lookupCount; i++ {
		if len(r) < 32 {
			return io.ErrUnexpectedEOF
		}
		copy(msg.AddressTableLookups[i].AccountKey[:], r[:32])
		r = r[32:]

		wCount, n, err := solanaDecodeCompactU16(r)
		if err != nil {
			return fmt.Errorf("reading writable indexes count: %w", err)
		}
		r = r[n:]
		if len(r) < wCount {
			return io.ErrUnexpectedEOF
		}
		msg.AddressTableLookups[i].WritableIndexes = slices.Clone(r[:wCount])
		r = r[wCount:]

		rCount, n, err := solanaDecodeCompactU16(r)
		if err != nil {
			return fmt.Errorf("reading readonly indexes count: %w", err)
		}
		r = r[n:]
		if len(r) < rCount {
			return io.ErrUnexpectedEOF
		}
		msg.AddressTableLookups[i].ReadonlyIndexes = slices.Clone(r[:rCount])
		r = r[rCount:]
	}

	// Validate instruction indexes. For v0 the addressable account set is the
	// static account keys followed by accounts loaded from address lookup
	// tables (all writable indexes, then all readonly indexes). The lookup
	// counts are only known after the lookups have been parsed, which is why
	// this validation happens here rather than during instruction parsing.
	addressable := keyCount
	for _, l := range msg.AddressTableLookups {
		addressable += len(l.WritableIndexes) + len(l.ReadonlyIndexes)
	}
	for i := range msg.Instructions {
		if int(msg.Instructions[i].ProgramIDIndex) >= addressable {
			return fmt.Errorf("instruction %d program id index %d out of range (%d addressable accounts)", i, msg.Instructions[i].ProgramIDIndex, addressable)
		}
		for _, ai := range msg.Instructions[i].AccountIndices {
			if int(ai) >= addressable {
				return fmt.Errorf("instruction %d account index %d out of range (%d addressable accounts)", i, ai, addressable)
			}
		}
	}

	return nil
}

// validateSolanaHeader checks that the message header account counts are
// internally consistent with the number of account keys. This prevents
// out-of-bounds indexing in Sign/Verify when handling a crafted message.
func validateSolanaHeader(h SolanaMessageHeader, numKeys int) error {
	if int(h.NumRequiredSignatures) > numKeys {
		return fmt.Errorf("NumRequiredSignatures %d exceeds account key count %d", h.NumRequiredSignatures, numKeys)
	}
	if int(h.NumReadonlySignedAccounts) > int(h.NumRequiredSignatures) {
		return fmt.Errorf("NumReadonlySignedAccounts %d exceeds NumRequiredSignatures %d", h.NumReadonlySignedAccounts, h.NumRequiredSignatures)
	}
	if int(h.NumRequiredSignatures)+int(h.NumReadonlyUnsignedAccounts) > numKeys {
		return fmt.Errorf("NumRequiredSignatures + NumReadonlyUnsignedAccounts (%d) exceeds account key count %d", int(h.NumRequiredSignatures)+int(h.NumReadonlyUnsignedAccounts), numKeys)
	}
	return nil
}

// solanaEncodeCompactU16 encodes an integer as Solana's compact-u16 format.
// Values 0-0x7f use 1 byte, 0x80-0x3fff use 2 bytes, 0x4000-0xffff use 3 bytes.
func solanaEncodeCompactU16(v int) []byte {
	if v < 0 || v > 0xffff {
		panic("compact-u16 value out of range")
	}
	if v < 0x80 {
		return []byte{byte(v)}
	}
	if v < 0x4000 {
		return []byte{byte(v&0x7f) | 0x80, byte(v >> 7)}
	}
	return []byte{byte(v&0x7f) | 0x80, byte((v>>7)&0x7f) | 0x80, byte(v >> 14)}
}

// solanaDecodeCompactU16 decodes a compact-u16 value and returns the value,
// number of bytes consumed, and any error.
func solanaDecodeCompactU16(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	b0 := data[0]
	if b0 < 0x80 {
		return int(b0), 1, nil
	}
	if len(data) < 2 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	b1 := data[1]
	if b1 < 0x80 {
		// Reject non-canonical encodings: a 2-byte form whose high group is
		// zero should have been encoded in a single byte.
		if b1 == 0 {
			return 0, 0, errors.New("non-canonical compact-u16")
		}
		return int(b0&0x7f) | int(b1)<<7, 2, nil
	}
	if len(data) < 3 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	b2 := data[2]
	if b2 > 3 {
		return 0, 0, errors.New("compact-u16 overflow")
	}
	// Reject non-canonical encodings: a 3-byte form whose high group is zero
	// should have been encoded in two bytes.
	if b2 == 0 {
		return 0, 0, errors.New("non-canonical compact-u16")
	}
	return int(b0&0x7f) | int(b1&0x7f)<<7 | int(b2)<<14, 3, nil
}
