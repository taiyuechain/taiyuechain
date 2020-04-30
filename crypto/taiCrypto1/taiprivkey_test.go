package taiCrypto1

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	tycrpto "github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/crypto/ecies"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm2"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm3"
	"github.com/taiyuechain/taiyuechain/crypto/p256"
	"github.com/taiyuechain/taiyuechain/crypto/taiCrypto"
	"golang.org/x/crypto/sha3"
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
	prikey := smpribyte.(*Sm2PrivateKey)
	fmt.Println(prikey)
}

func TestEcdsaPrivateKey_Decrypt(t *testing.T) {
	//ecdpri, _ := tycrpto.GenerateKey()
	//ecdp := (*EcdsaPrivateKey)(ecdpri)
	////ecdp.Decrypt()
	////fmt.Println(sign)
}

func TestSm2PrivateKey_Decrypt(t *testing.T) {

}

func TestP256PrivateKey_Decrypt(t *testing.T) {

}

func TestP256PrivateKey_Sign(t *testing.T) {
	pri, _ := ecies.GenerateKey(rand.Reader, elliptic.P256(), nil)
	d := sm3.New()
	p256.SignP256(pri.ExportECDSA(), d.Sum(nil))
}

func TestGenerateKey(t *testing.T) {
	taiCrypto.AsymmetricCryptoType = taiCrypto.ASYMMETRICCRYPTOECDSA
	ecdsa := GenerateKey()
	d := sha3.NewLegacyKeccak256()
	sign, _ := ecdsa.Sign(d.Sum(nil))
	fmt.Println(sign)

}

func TestHexToPrivate(t *testing.T) {
	//taiCrypto.AsymmetricCryptoType=taiCrypto.ASYMMETRICCRYPTOECDSA
	//taiCrypto.AsymmetricCryptoType=taiCrypto.ASYMMETRICCRYPTOSM2
	taiCrypto.AsymmetricCryptoType = taiCrypto.ASYMMETRICCRYPTOECIES
	ecdsa := GenerateKey()
	pristr := ecdsa.ToHex()
	ecdsaprivate, _ := HexToPrivate(pristr)
	fmt.Println(ecdsaprivate)
}
