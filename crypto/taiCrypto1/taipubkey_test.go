package taiCrypto1

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	tycrpto "github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm2"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm3"
	"github.com/taiyuechain/taiyuechain/crypto/taiCrypto"
	"golang.org/x/crypto/sha3"
	"testing"
)

func TestEcdsaTaiPublicKey_ToAddress(t *testing.T) {
	ecdpri, _ := tycrpto.GenerateKey()
	ecdpub := (*EcdsaPublicKey)(&ecdpri.PublicKey)
	pubbytes := ecdpub.ToBytes()
	fmt.Println(pubbytes)
	inpub, _ := ToPublickey(pubbytes)
	ecdsaPub := inpub.(*ecdsa.PublicKey)
	ecdsaTaiPublicKey := (*EcdsaPublicKey)(ecdsaPub)
	address := ecdsaTaiPublicKey.ToAddress()
	fmt.Println(address)

}

func TestEcdsaTaiPublicKey_ToBytes(t *testing.T) {
	ecdpri, _ := tycrpto.GenerateKey()
	ecdpub := (*EcdsaPublicKey)(&ecdpri.PublicKey)
	pubbytes := ecdpub.ToBytes()
	fmt.Println(pubbytes)
}

func TestEcdsaTaiPublicKey_ToHex(t *testing.T) {
	ecdpri, _ := tycrpto.GenerateKey()
	ecdpub := (*EcdsaPublicKey)(&ecdpri.PublicKey)
	hexstring := ecdpub.ToHex()
	fmt.Println(hexstring)
}

func TestEcdsaTaiPublicKey_Verify(t *testing.T) {
	ecdpri, _ := tycrpto.GenerateKey()
	ecdp := (*EcdsaPrivateKey)(ecdpri)
	d := sha3.NewLegacyKeccak256()
	sign, _ := ecdp.Sign(d.Sum(nil))
	fmt.Println(sign)
	ecdpub := (*EcdsaPublicKey)(&ecdpri.PublicKey)
	verity := ecdpub.Verify(d.Sum(nil), sign)
	fmt.Println(verity)

}

func TestSm2TaiPublicKey_ToAddress(t *testing.T) {
	taiCrypto.HashCryptoType = taiCrypto.HASHCRYPTOSM3
	_, smpub, _ := sm2.GenerateKey(rand.Reader)
	sm2pub := (*Sm2PublicKey)(smpub)
	pubbytes := sm2pub.ToBytes()
	fmt.Println(pubbytes)
	inpub, _ := ToPublickey(pubbytes)
	ecdsaPub := inpub.(*sm2.PublicKey)
	ecdsaTaiPublicKey := (*Sm2PublicKey)(ecdsaPub)
	address := ecdsaTaiPublicKey.ToAddress()
	fmt.Println(address)
}

func TestSm2TaiPublicKey_ToBytes(t *testing.T) {
	_, smpub, _ := sm2.GenerateKey(rand.Reader)
	smtaipub := (*Sm2PublicKey)(smpub)
	smbytes := smtaipub.ToBytes()
	fmt.Println(smbytes)

}

func TestSm2TaiPublicKey_ToHex(t *testing.T) {
	_, smpub, _ := sm2.GenerateKey(rand.Reader)
	smtaipub := (*Sm2PublicKey)(smpub)
	hexstring := smtaipub.ToHex()
	fmt.Println(hexstring)
}

func TestSm2TaiPublicKey_Verify(t *testing.T) {
	smpri, smpub, _ := sm2.GenerateKey(rand.Reader)
	smpri.PublicKey = *smpub
	smp := (*Sm2PrivateKey)(smpri)
	d := sm3.New()
	hash := d.Sum(nil)
	fmt.Println(hash)
	smsign, _ := smp.Sign(hash)
	//fmt.Println(smsign)
	smtaipub := (*Sm2PublicKey)(smpub)
	verity := smtaipub.Verify(hash, smsign)
	/*	hash1:=d.Sum(nil)
		fmt.Println(hash1)*/
	fmt.Println(verity)
}

func TestToPublickey(t *testing.T) {

}
