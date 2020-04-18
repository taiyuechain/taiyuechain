package p256

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/taiyuechain/taiyuechain/crypto/taiCrypto"
	"golang.org/x/crypto/sha3"
	"math/big"
	"testing"
)

func TestP256Signature_ProtoMessage(t *testing.T) {

}

func TestP256Signature_Reset(t *testing.T) {

}

func TestP256Signature_String(t *testing.T) {
	type fields struct {
		R *big.Int
		S *big.Int
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := P256Signature{
				R: tt.fields.R,
				S: tt.fields.S,
			}
			if got := p.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSignP256(t *testing.T) {

	taipriv, _ := taiCrypto.GenerateKey(rand.Reader, elliptic.P256(), nil)
	ecdsaPri := taipriv.EciesPrivate.ExportECDSA()
	h := sha3.NewLegacyKeccak256()
	sign, _ := SignP256(ecdsaPri, h.Sum(nil))
	fmt.Println(VerifyP256(ecdsaPri.PublicKey, h.Sum(nil), sign))
}

func TestVerifyP256(t *testing.T) {

}
