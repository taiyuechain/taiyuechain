package taiCrypto1

import (
	"crypto/rand"
	"fmt"
	tycrpto "github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm2"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm3"
	"golang.org/x/crypto/sha3"
	"reflect"
	"testing"
)

func TestEcdsaPrivateKey_Public(t *testing.T) {
	ecdpri, _ := tycrpto.GenerateKey()
	ecdp := (*EcdsaPrivateKey)(ecdpri)
	pribyte := ecdp.Public()
	fmt.Println(pribyte)

}

func TestEcdsaPrivateKey_Sign(t *testing.T) {
	ecdpri, _ := tycrpto.GenerateKey()
	ecdp := (*EcdsaPrivateKey)(ecdpri)
	d := sha3.NewLegacyKeccak256()
	sign, _ := ecdp.Sign(d.Sum(nil))
	fmt.Println(sign)
}

func TestEcdsaPrivateKey_ToHex(t *testing.T) {
	ecdpri, _ := tycrpto.GenerateKey()
	ecdp := (*EcdsaPrivateKey)(ecdpri)
	stringpri := ecdp.ToHex()
	fmt.Println(stringpri)
}

func TestSm2PrivateKey_Public(t *testing.T) {
	smpri, _, _ := sm2.GenerateKey(rand.Reader)
	smp := (*Sm2PrivateKey)(smpri)
	smprikey := smp.Public()
	fmt.Println(smprikey)
}

func TestSm2PrivateKey_Sign(t *testing.T) {
	smpri, smpub, _ := sm2.GenerateKey(rand.Reader)
	smpri.PublicKey = *smpub
	smp := (*Sm2PrivateKey)(smpri)
	d := sm3.New()
	smsign, _ := smp.Sign(d.Sum(nil))
	fmt.Println(smsign)
}

func TestSm2PrivateKey_ToHex(t *testing.T) {
	smpri, smpub, _ := sm2.GenerateKey(rand.Reader)
	smpri.PublicKey = *smpub
	smp := (*Sm2PrivateKey)(smpri)
	stringpri := smp.ToHex()
	fmt.Println(stringpri)
}

func TestToPrivateKey(t *testing.T) {
	/*	ecdpri, _ := tycrpto.GenerateKey()
		ecdp := (*EcdsaPrivateKey)(ecdpri)
		pribyte := ecdp.Public()
		ecdsapri,_:=ToPrivateKey(pribyte)
		key := ecdsapri.(*ecdsa.PrivateKey)
		fmt.Println(key)*/
	smpri, smpub, _ := sm2.GenerateKey(rand.Reader)
	smpri.PublicKey = *smpub
	smp := (*Sm2PrivateKey)(smpri)
	key := smp.Public()
	smpribyte, _ := ToPrivateKey(key)
	prikey := smpribyte.(*sm2.PrivateKey)
	fmt.Println(prikey)
}

func TestEcdsaPrivateKey_Decrypt(t *testing.T) {
	//ecdpri, _ := tycrpto.GenerateKey()
	//ecdp := (*EcdsaPrivateKey)(ecdpri)
	////ecdp.Decrypt()
	////fmt.Println(sign)
}

func TestSm2PrivateKey_Decrypt(t *testing.T) {
	type args struct {
		ct []byte
	}
	tests := []struct {
		name    string
		Taipri  Sm2PrivateKey
		args    args
		wantM   []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotM, err := tt.Taipri.Decrypt(tt.args.ct)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotM, tt.wantM) {
				t.Errorf("Decrypt() gotM = %v, want %v", gotM, tt.wantM)
			}
		})
	}
}

func TestP256PrivateKey_Decrypt(t *testing.T) {
	type args struct {
		ct []byte
	}
	tests := []struct {
		name    string
		Taipri  P256PrivateKey
		args    args
		wantM   []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotM, err := tt.Taipri.Decrypt(tt.args.ct)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotM, tt.wantM) {
				t.Errorf("Decrypt() gotM = %v, want %v", gotM, tt.wantM)
			}
		})
	}
}
