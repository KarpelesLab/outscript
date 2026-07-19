package outscript

import (
	"encoding/hex"
	"fmt"
)

// EvmAccessTuple is a single entry of an EIP-2930 access list: an address
// together with the storage slots of that address the transaction declares it
// will access. Access lists are shared by EIP-2930, EIP-1559 and EIP-7702
// transactions.
type EvmAccessTuple struct {
	Address     string   // "0x"-prefixed 20-byte address
	StorageKeys []string // "0x"-prefixed 32-byte storage keys
}

// evmAccessTupleJson is used when encoding/decoding an EvmAccessTuple to/from
// JSON, matching the eth JSON-RPC access list representation.
type evmAccessTupleJson struct {
	Address     string   `json:"address"`
	StorageKeys []string `json:"storageKeys"`
}

// rlpTuple returns the two-element RLP representation [address, [storageKeys...]].
func (t *EvmAccessTuple) rlpTuple() []any {
	keys := make([]any, len(t.StorageKeys))
	for i, k := range t.StorageKeys {
		keys[i] = k
	}
	return []any{t.Address, keys}
}

// toJson converts the access tuple into its JSON representation.
func (t *EvmAccessTuple) toJson() *evmAccessTupleJson {
	keys := make([]string, len(t.StorageKeys))
	copy(keys, t.StorageKeys)
	return &evmAccessTupleJson{Address: t.Address, StorageKeys: keys}
}

// toAccessTuple converts the JSON representation into an EvmAccessTuple.
func (j *evmAccessTupleJson) toAccessTuple() *EvmAccessTuple {
	keys := make([]string, len(j.StorageKeys))
	copy(keys, j.StorageKeys)
	return &EvmAccessTuple{Address: j.Address, StorageKeys: keys}
}

// accessListRlp returns the transaction's access list as an RLP list of tuples.
func (tx *EvmTx) accessListRlp() []any {
	out := make([]any, len(tx.AccessList))
	for i, t := range tx.AccessList {
		out[i] = t.rlpTuple()
	}
	return out
}

// parseAccessList decodes the RLP access_list of a transaction into a slice of
// EvmAccessTuple.
func parseAccessList(v any) ([]*EvmAccessTuple, error) {
	items, err := asList(v)
	if err != nil {
		return nil, err
	}
	out := make([]*EvmAccessTuple, 0, len(items))
	for _, item := range items {
		tuple, err := asList(item)
		if err != nil {
			return nil, err
		}
		if len(tuple) != 2 {
			return nil, fmt.Errorf("access list tuple must have 2 fields, got %d", len(tuple))
		}
		addr, err := asBytes(tuple[0])
		if err != nil {
			return nil, err
		}
		keyList, err := asList(tuple[1])
		if err != nil {
			return nil, err
		}
		keys := make([]string, 0, len(keyList))
		for _, k := range keyList {
			kb, err := asBytes(k)
			if err != nil {
				return nil, err
			}
			keys = append(keys, "0x"+hex.EncodeToString(kb))
		}
		out = append(out, &EvmAccessTuple{
			Address:     "0x" + hex.EncodeToString(addr),
			StorageKeys: keys,
		})
	}
	return out, nil
}
