package outscript_test

import (
	"testing"

	"github.com/KarpelesLab/outscript"
)

func TestParseMassaAddressInvalidPrefix(t *testing.T) {
	_, err := outscript.ParseMassaAddress("XX12345678901234567890")
	if err == nil {
		t.Error("expected error for invalid prefix")
	}
}

func TestParseMassaAddressInvalidBase58(t *testing.T) {
	_, err := outscript.ParseMassaAddress("AU!!!invalid!!!")
	if err == nil {
		t.Error("expected error for invalid base58")
	}
}

func TestParseMassaAddressShort(t *testing.T) {
	// short base58 payloads used to panic with out-of-bounds slicing; they must
	// now return an error instead.
	for _, addr := range []string{"AU1", "AS1", "AU", "AS", "AU11", "AStt"} {
		_, err := outscript.ParseMassaAddress(addr)
		if err == nil {
			t.Errorf("expected error for short massa address %q", addr)
		}
	}
}
