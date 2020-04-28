package taiCrypto1

import (
	"crypto/ecdsa"
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
	fmt.Println(len(smbytes))

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
	pri, _ := ecies.GenerateKey(rand.Reader, elliptic.P256(), nil)
	p256pub := (P256PublicKey)(pri.PublicKey)
	p256bytes := p256pub.ToBytes()
	fmt.Println(p256bytes)
	fmt.Println(len(p256bytes))

}

func TestP256PublicKey_Verify(t *testing.T) {

}

func TestP256PublicKey_ToBytes(t *testing.T) {
	pri, _ := ecies.GenerateKey(rand.Reader, elliptic.P256(), nil)
	fmt.Println(pri)
}

func TestP256PublicKey_ToAddress(t *testing.T) {

}

func TestP256PublicKey_ToHex(t *testing.T) {

}

func TestP256PublicKey_Encrypt(t *testing.T) {
	pri, _ := p256.NewSigningKey()
	src := "caoliang"
	data := []byte(src)
	p256public := (*P256PublicKey)(ecies.ImportECDSAPublic(&pri.PublicKey))
	ct, _ := p256public.Encrypt(data)
	p256pri := (*P256PrivateKey)(ecies.ImportECDSA(pri))
	m, _ := p256pri.Decrypt(ct)
	fmt.Println(string(m))

}

func TestDecompressPublickey(t *testing.T) {
	pri, _ := ecies.GenerateKey(rand.Reader, elliptic.P256(), nil)
	fmt.Println(pri)
	compressbyte := (*P256PublicKey)(&pri.PublicKey).CompressPubkey()
	fmt.Println(compressbyte)
	p256publicket, _ := DecompressPublickey(compressbyte)
	tt := p256publicket.(*ecdsa.PublicKey)
	fmt.Println(tt)
}

func TestP256PublicKey_CompressPubkey(t *testing.T) {
	pri, _ := ecies.GenerateKey(rand.Reader, elliptic.P256(), nil)
	fmt.Println(pri)
	compressbyte := (*P256PublicKey)(&pri.PublicKey).CompressPubkey()
	fmt.Println(compressbyte)
}

func TestSm2PublicKey_CompressPubkey(t *testing.T) {
	smpri, smpub, _ := sm2.GenerateKey(rand.Reader)
	smpri.PublicKey = *smpub
	smtaipub := (*Sm2PublicKey)(smpub)
	pubbyte := smtaipub.CompressPubkey()
	fmt.Println(pubbyte)
	smpublickey, _ := DecompressPublickey(pubbyte)
	tt := smpublickey.(*sm2.PublicKey)
	fmt.Println(tt)

}

func TestEcdsaPublicKey_Encrypt(t *testing.T) {
	ecdpri, _ := tycrpto.GenerateKey()
	ecdpub := (*EcdsaPublicKey)(&ecdpri.PublicKey)
	src := "caoliang"
	data := []byte(src)
	ct, _ := ecdpub.Encrypt(data)
	fmt.Println(ct)
	//ecdpri, _ := tycrpto.GenerateKey()
	ecdprikey := (*EcdsaPrivateKey)(ecdpri)
	m, _ := ecdprikey.Decrypt(ct)
	fmt.Println(string(m))
}

func TestSm2PublicKey_Encrypt(t *testing.T) {
	smpri, smpub, _ := sm2.GenerateKey(rand.Reader)
	smpri.PublicKey = *smpub
	src := "caoliang"
	data := []byte(src)
	smp := (*Sm2PrivateKey)(smpri)
	//fmt.Println(smsign)
	smtaipub := (*Sm2PublicKey)(smpub)
	ct, _ := smtaipub.Encrypt(data)
	fmt.Println(ct)
	m, _ := smp.Decrypt(ct)
	fmt.Println(string(m))

}

func TestP256PublicKey_Encrypt1(t *testing.T) {

}

func TestSigToPub(t *testing.T) {
	/*	ecdpri, _ := tycrpto.GenerateKey()
		ecdp := (*EcdsaPrivateKey)(ecdpri)
		d := sha3.NewLegacyKeccak256()
		sign, _ := ecdp.Sign(d.Sum(nil))
		fmt.Println(sign)
		fmt.Println(ecdpri.PublicKey)
		ecdsapub,_:=SigToPub(d.Sum(nil),sign)
		fmt.Println(ecdsapub.(*ecdsa.PublicKey))
		smpri, smpub, _ := sm2.GenerateKey(rand.Reader)
		smpri.PublicKey = *smpub
		fmt.Println(smpub)
		smp := (*Sm2PrivateKey)(smpri)
		smd := sm3.New()
		smdigst:=smd.Sum(nil)
		smsign, _ := smp.Sign(smdigst)
		fmt.Println(smsign)*/
	//smpubkey,_:=SigToPub(smdigst,smsign)
	//fmt.Println(smpubkey.(sm2.PublicKey))
	//pri, _ := ecies.GenerateKey(rand.Reader, elliptic.P256(), nil)
	pri, _ := p256.NewSigningKey()
	fmt.Println(pri.PublicKey)
	p256d := sha3.NewLegacyKeccak256()
	hash := p256d.Sum(nil)
	p256p := (*P256PrivateKey)(ecies.ImportECDSA(pri))
	p256sign, _ := p256p.Sign(hash)
	p256pubkey1, p256pubkey2, _ := SigToPub(hash, p256sign)
	//fmt.Println(ecies.ImportECDSAPublic(p256pubkey.(*ecdsa.PublicKey)))
	fmt.Println(p256pubkey1.(*ecdsa.PublicKey))
	fmt.Println(p256pubkey2.(*ecdsa.PublicKey))
	p256publickey := (*P256PublicKey)(ecies.ImportECDSAPublic(p256pubkey2.(*ecdsa.PublicKey)))
	bollsign := p256publickey.Verify(hash, p256sign)
	fmt.Println(bollsign)
}
