# outscript

[![Go Reference](https://pkg.go.dev/badge/github.com/KarpelesLab/outscript.svg)](https://pkg.go.dev/github.com/KarpelesLab/outscript)
[![Coverage Status](https://coveralls.io/repos/github/KarpelesLab/outscript/badge.svg?branch=master)](https://coveralls.io/github/KarpelesLab/outscript?branch=master)

A Go package for generating output scripts, parsing/encoding addresses, and building/signing transactions across multiple cryptocurrency networks.

## Install

```bash
go get github.com/KarpelesLab/outscript
```

## Supported Networks

| Network | Address Formats | Transactions |
|---------|----------------|--------------|
| Bitcoin | p2pkh, p2pk, p2wpkh, p2sh:p2wpkh, p2wsh, p2tr | BtcTx |
| Bitcoin Cash | p2pkh, p2pk (CashAddr) | BtcTx |
| Litecoin | p2pkh, p2pk, p2wpkh, p2sh:p2wpkh | BtcTx |
| Dogecoin | p2pkh, p2pk | BtcTx |
| Namecoin | p2pkh, p2sh | BtcTx |
| Monacoin | p2pkh, p2sh, p2wpkh | BtcTx |
| Dash | p2pkh, p2sh | BtcTx |
| Electraproto | p2pkh, p2sh, p2wpkh | BtcTx |
| EVM (Ethereum, etc.) | EIP-55 checksummed | EvmTx |
| Massa | AU (user) / AS (smart contract) | - |
| Solana | Base58 (32 bytes) | SolanaTx |
| Cardano | Shelley bech32 (addr / addr_test / stake) | CardanoTx |

## Usage

### Address Generation

Generate addresses from a public key:

```go
// Bitcoin (secp256k1)
key := secp256k1.PrivKeyFromBytes(seed)
s := outscript.New(key.PubKey())

addr, _ := s.Address("p2wpkh", "bitcoin")    // bc1q...
addr, _ = s.Address("p2pkh", "litecoin")      // L...
addr, _ = s.Address("eth")                     // 0x...

// Solana / Massa (ed25519)
key := ed25519.NewKeyFromSeed(seed)
s := outscript.New(key.Public())

addr, _ = s.Address("solana", "solana")        // base58
addr, _ = s.Address("massa", "massa")          // AU...

// Cardano (ed25519). Address("cardano") yields a Shelley enterprise address
// (payment credential only); pass "cardano-testnet" for the testnet form.
addr, _ = s.Address("cardano")                 // addr1...
addr, _ = s.Address("cardano", "cardano-testnet") // addr_test1...

// Base (payment+stake) and reward addresses need two key hashes:
ph := outscript.CardanoKeyHash(paymentPub)
sh := outscript.CardanoKeyHash(stakePub)
addr, _ = outscript.CardanoBaseAddress(ph, sh, "cardano")   // addr1...
addr, _ = outscript.CardanoRewardAddress(sh, "cardano")     // stake1...
```

### Address Parsing

```go
// Bitcoin-family
out, _ := outscript.ParseBitcoinBasedAddress("bitcoin", "bc1q...")
out, _ = outscript.ParseBitcoinBasedAddress("auto", "1A1zP1...")  // auto-detect network

// EVM
out, _ := outscript.ParseEvmAddress("0x2AeB8ADD...")

// Solana
out, _ := outscript.ParseSolanaAddress("83astBRguLMdt2h5U1Tpdq5tjFoJ...")

// Massa
out, _ := outscript.ParseMassaAddress("AU16f3K8uWS8cSJaXb7...")

// Cardano (addr / addr_test / stake / stake_test)
out, _ := outscript.ParseCardanoAddress("addr1vx2fxv2umyhttkxyxp8...")
raw := out.Bytes() // raw address bytes (header + credentials), for use as a tx output address
```

### Bitcoin Transactions

```go
tx := &outscript.BtcTx{Version: 2}

// Add inputs
tx.In = append(tx.In, &outscript.BtcTxInput{
    TXID:     txid,
    Vout:     0,
    Sequence: 0xffffffff,
})

// Add outputs
tx.AddNetOutput("bitcoin", "bc1q...", 50000)

// Sign (supports p2pkh, p2wpkh, p2sh:p2wpkh, p2wsh, p2tr, etc.)
tx.Sign(&outscript.BtcTxSign{
    Key:    privKey,
    Scheme: "p2wpkh",
    Amount: 100000, // input value, required for segwit
})

// P2TR (BIP-341 key-path, SIGHASH_DEFAULT). PrevScript is required —
// BIP-341 sighashes commit to every input's scriptPubKey. Tapscript /
// script-path spends are not yet supported.
//
// Key can be either:
//   - *secp256k1.PrivateKey: the library applies the BIP-341 tweak itself.
//   - anything implementing TaprootSigner: TSS / MuSig2 / FROST / HSM /
//     mock signers that already know their tweaked key. The library
//     feeds them the 32-byte sighash and trusts them to return a 64-byte
//     BIP-340 signature.
tx.Sign(&outscript.BtcTxSign{
    Key:        privKey,
    Scheme:     "p2tr",
    Amount:     100000,
    PrevScript: prevScriptPubKey, // 0x5120 <32-byte x-only output key>
})

// Offline helpers for TSS integrations (compute the aggregate output key
// and the sighash without invoking the signer):
//   tweakedX, parity, _ := outscript.TaprootTweak(internalXOnly)
//   digest, _          := tx.TaprootSighash(keys, inputIdx)

// Serialize
data, _ := tx.MarshalBinary()

// Estimate size for fee calculation
size := tx.ComputeSize()
```

### EVM Transactions

```go
tx := &outscript.EvmTx{
    Type:      outscript.EvmTxEIP1559,
    ChainId:   1,
    Nonce:     0,
    GasTipCap: big.NewInt(1_000_000_000),
    GasFeeCap: big.NewInt(20_000_000_000),
    Gas:       21000,
    To:        "0x...",
    Value:     big.NewInt(1_000_000_000_000_000_000),
    Data:      nil,
}

// Or build contract calls with ABI encoding
tx.Call("transfer(address,uint256)", recipientAddr, amount)

// Sign and serialize
tx.Sign(privKey)
data, _ := tx.MarshalBinary()

// Recover sender from signed transaction
sender, _ := tx.SenderAddress()
```

Supported EVM transaction types: Legacy, EIP-2930, EIP-1559, EIP-4844.

### EVM ABI Encoding

Encode calldata without a full ABI definition:

```go
data, _ := outscript.EvmCall("transfer(address,uint256)", recipientAddr, amount)
data, _ = outscript.EvmCall("approve(address,uint256)", spender, big.NewInt(0))
```

Or use `AbiBuffer` directly for more control:

```go
buf := outscript.NewAbiBuffer(nil)
buf.EncodeAbi("balanceOf(address)", addr)
calldata := buf.Call("balanceOf(address)")
```

### Solana Transactions

```go
from := must(outscript.ParseSolanaKey("..."))
to := must(outscript.ParseSolanaKey("..."))
blockhash := must(outscript.ParseSolanaKey("..."))

// Build a transfer instruction
ix := outscript.SolanaTransferInstruction(from, to, 1_000_000) // lamports

// Compile into a transaction (handles account dedup, sorting, and compilation)
tx := outscript.NewSolanaTx(from, blockhash, ix)

// Sign with Ed25519
tx.Sign(privKey)

// Serialize
data, _ := tx.MarshalBinary()

// Transaction ID is the first signature
txid, _ := tx.Hash()
```

### Cardano Transactions

Builds Shelley/Conway-era transactions: CBOR-encoded body (inputs, outputs, fee,
optional TTL), ADA and native-asset outputs, and Ed25519 vkey witnesses. The
transaction id and signing digest are `blake2b-256` of the transaction body.

```go
toAddr, _ := outscript.ParseCardanoAddress("addr1vx2fxv2umyhttkxyxp8...")

tx := &outscript.CardanoTx{
    Inputs: []*outscript.CardanoInput{
        {TxID: prevTxID /* 32 bytes */, Index: 0},
    },
    Outputs: []*outscript.CardanoOutput{
        {Address: toAddr.Bytes(), Amount: 1_000_000}, // lovelace
    },
    Fee: 170_000,
    TTL: 41_000_000, // optional (slot); 0 omits it
}

// Sign with one or more standard Ed25519 keys (appends a vkey witness per key)
tx.Sign(privKey)

data, _ := tx.MarshalBinary() // CBOR transaction
txid, _ := tx.Hash()          // blake2b-256 of the body
```

Cardano HD wallets (CIP-1852) use BIP32-Ed25519 *extended* keys, which store an
already-expanded 64-byte secret and cannot be used with `crypto/ed25519`. Sign
with those (or any external/HSM signer) through the `CardanoSigner` interface:

```go
// secret is the 64-byte extended secret (e.g. the first 64 bytes of an xprv)
ext, _ := outscript.NewCardanoExtendedKey(secret)
tx.SignWith(ext) // produces a standard Ed25519 signature, verifiable as usual
```

#### HD key derivation (CIP-1852 / BIP32-Ed25519)

Derive keys from BIP-39 entropy using the Icarus master-key scheme and the
CIP-1852 path `m/1852'/1815'/account'/role/index`:

```go
master, _ := outscript.CardanoIcarusMasterKey(entropy, nil) // nil = no passphrase
H := outscript.CardanoHarden

// payment key m/1852'/1815'/0'/0/0 and stake key m/1852'/1815'/0'/2/0
spend, _ := master.DerivePath(H(1852), H(1815), H(0), 0, 0)
stake, _ := master.DerivePath(H(1852), H(1815), H(0), 2, 0)

ph := outscript.CardanoKeyHash(spend.CardanoPublicKey())
sh := outscript.CardanoKeyHash(stake.CardanoPublicKey())
addr, _ := outscript.CardanoBaseAddress(ph, sh, "cardano") // addr1...

// spend can sign transactions directly via SignWith.
// Watch-only soft derivation (no private key) is available from an xpub:
xpub := master.DerivePath(H(1852), H(1815), H(0), 0).ExtendedPublicKey()
child, _ := xpub.DeriveChild(0)
```

Native tokens are added via `CardanoOutput.Assets` (`CardanoAsset{PolicyID,
AssetName, Amount}`). Plutus scripts, certificates, staking actions and metadata
are out of scope.

### Block Rewards

Calculate block rewards and cumulative supply:

```go
reward, _ := outscript.BlockReward("bitcoin", 840000)      // 3.125 BTC in satoshis
total, _ := outscript.CumulativeReward("bitcoin", 840000)   // total minted through block 840000
```

Supported: bitcoin, bitcoin-cash, bitcoin-testnet, litecoin, namecoin, monacoin, dogecoin, dash, electraproto.

### Output Script Analysis

Identify output script types and extract public key hashes:

```go
out := outscript.GuessOut(scriptBytes, pubKeyHint)
fmt.Println(out.Name) // "p2wpkh", "p2pkh", "p2sh", etc.

// Get all possible output formats for a key
outs := outscript.GetOuts(pubKey)
```

## Architecture

The package is built around composable primitives:

- **Format** - A sequence of `Insertable` operations (literal bytes, lookups, hashes, push-data encoding) that define how to derive an output script from a public key.
- **Script** - Holds a public key and generates output scripts by evaluating `Format` definitions. Results are cached.
- **Out** - A generated output script with its format name, hex encoding, and network flags. Can be converted to/from human-readable addresses.
- **Transaction** - Interface implemented by `BtcTx`, `EvmTx`, and `SolanaTx` for binary serialization and hashing.

## License

See [LICENSE](LICENSE) file.
