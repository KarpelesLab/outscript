package outscript

import "encoding"

var (
	_ = Transaction(&EvmTx{})
	_ = Transaction(&BtcTx{})
	_ = Transaction(&SolanaTx{})
	_ = Transaction(&CardanoTx{})
)

// Transaction is the common interface for cryptocurrency transactions that can be
// serialized to binary and produce a hash.
type Transaction interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	Hash() ([]byte, error)
}
