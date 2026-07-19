package outscript_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/KarpelesLab/outscript"
	"github.com/KarpelesLab/secp256k1"
)

func TestInfo(t *testing.T) {
	// test with this addr: 0208c27162565b6660961b5de8b4a21abcd7bfd197b7e85d6709e8b71055b2c8b2
	pub := must(secp256k1.ParsePubKey(must(hex.DecodeString("0208c27162565b6660961b5de8b4a21abcd7bfd197b7e85d6709e8b71055b2c8b2"))))
	outs := outscript.GetOuts(pub)
	expect := "p2pkh:76a914ab4996a0ed164be1564013917ec5a5a4b10563fe88ac p2pukh:76a914d94642f52c914df99806713058c90eb1905b62cb88ac p2pk:210208c27162565b6660961b5de8b4a21abcd7bfd197b7e85d6709e8b71055b2c8b2ac p2puk:410408c27162565b6660961b5de8b4a21abcd7bfd197b7e85d6709e8b71055b2c8b295261ab7dd1818cb9bc4090b242b7e36f1ef3be5396af56676e9b39caf73b194ac p2wpkh:0014ab4996a0ed164be1564013917ec5a5a4b10563fe p2tr:5120064390579ce6ee97b071f753f55abc145004c8153bff2ad9ceadd03552396324 p2sh:p2pkh:a914301550140d26c46ce4a50114a15c20f87602153787 p2wsh:p2pkh:0020490312e57a26f473003db829fa29cb0bc535ea1c7130d1a7204c27015cc259a5 p2sh:p2pukh:a91494ca87390701782873a0fc810d6da706eea14b8987 p2wsh:p2pukh:00201a742f133a0b7dedff2e1530c9a78a5159dd4287958256ee23cb20ae594b38cf p2sh:p2pk:a914c77651401782e026f89cbaba77f5f8addfdcbc8c87 p2wsh:p2pk:0020ad40d0b48bb6ebcae44bac5190bf735ee569846230fdfae1a2d6565b8fa22764 p2sh:p2puk:a91434c0f2afbde14c67ca56d43eacb4860295cea8e087 p2wsh:p2puk:0020dcda40aa3f2dab19ac1872e48cf2135822872a9bd8ea062ecb4e1b04afd0756f p2sh:p2wpkh:a91459d1d85df2bc403cc8b5c46e3ff6baf01a1fdf8287 p2wsh:p2wpkh:0020e63971d3beaf08a6a7c19d920023aea5206448ec68856a07a68f2498f20fcc7f eth:5fb84129ad9e7818f099966de975ff41213f028d tron:415fb84129ad9e7818f099966de975ff41213f028d"
	found := make(map[string]bool)
	for _, v := range strings.Split(expect, " ") {
		found[v] = false
	}

	for _, out := range outs {
		if _, ok := found[out.String()]; !ok {
			t.Errorf("unexpected output %s", out)
		}
		found[out.String()] = true
	}
	for k, v := range found {
		if !v {
			t.Errorf("failed to find output %s", k)
		}
	}
}
