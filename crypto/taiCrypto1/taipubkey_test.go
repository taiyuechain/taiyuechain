package taiCrypto1

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/ethereum/go-ethereum/common/math"
	tycrpto "github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/crypto/ecies"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm2"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm3"
	"github.com/taiyuechain/taiyuechain/crypto/p256"
	"github.com/taiyuechain/taiyuechain/crypto/taiCrypto"
	"golang.org/x/crypto/sha3"
	"reflect"
	"testing"
)

func TestEcdsaTaiPublicKey_ToAddress(t *testing.T) {
	ecdpri, _ := tycrpto.GenerateKey()
	ecdpub := (*EcdsaPublicKey)(&ecdpri.PublicKey)
	pubbytes := ecdpub.ToBytes()
	fmt.Println(pubbytes)
	inpub, _ := ToPublickey(pubbytes)
	ecdsaPub := inpub.(*EcdsaPublicKey)
	//ecdsaTaiPublicKey := (*EcdsaPublicKey)(ecdsaPub)
	address := ecdsaPub.ToAddress()
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
	ecdsaPub := inpub.(*Sm2PublicKey)
	//ecdsaTaiPublicKey := (*Sm2PublicKey)(ecdsaPub)
	address := ecdsaPub.ToAddress()
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
	fmt.Println(compressbyte, "", len(compressbyte))
	p256publicket, _ := DecompressPublickey(compressbyte)
	tt := p256publicket.(*P256PublicKey)
	fmt.Println(tt)
	pub := &pri.ExportECDSA().PublicKey
	data := elliptic.Marshal(elliptic.P256(), pub.X, pub.Y)
	fmt.Println(pub, "", len(data))
	if !reflect.DeepEqual(pub, tt) {
		t.Fatal("1111111111111111")
	}
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
	tt := smpublickey.(*Sm2PublicKey)
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
	//ecdpri, _ := tycrpto.GenerateKey()
	ecdpri, _ := tycrpto.GenerateKey()
	ecdpublickey := (*EcdsaPublicKey)(&ecdpri.PublicKey)
	e := encodePubkey1(ecdpublickey)
	fmt.Println(e)
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
	pri, _ := ecies.GenerateKey(rand.Reader, elliptic.P256(), nil)
	//pri, _ := p256.NewSigningKey()
	fmt.Println(pri.PublicKey)
	p256d := sha3.NewLegacyKeccak256()
	hash := p256d.Sum(nil)
	p256p := (*P256PrivateKey)(ecies.ImportECDSA(pri.ExportECDSA()))
	p256sign, _ := p256p.Sign(hash)
	p256pubkey1, _ := SigToPub(hash, p256sign)
	//fmt.Println(ecies.ImportECDSAPublic(p256pubkey.(*ecdsa.PublicKey)))
	//fmt.Println(p256pubkey1.(*EcdsaPublicKey))
	p256publickey := (p256pubkey1).(*P256PublicKey)
	bollsign := p256publickey.Verify(hash, p256sign)
	fmt.Println(bollsign)
}

type encPubkey [65]byte

func encodePubkey1(key TaiPubKey) encPubkey {
	var e encPubkey
	switch pub := key.(type) {
	case *EcdsaPublicKey:
		e[0] = 1
		math.ReadBits(pub.X, e[1:len(e)/2+1])
		math.ReadBits(pub.Y, e[len(e)/2+1:])
		return e
	case *Sm2PublicKey:
		e[0] = 2
		math.ReadBits(pub.X, e[1:len(e)/2+1])
		math.ReadBits(pub.Y, e[len(e)/2+1:])
		return e
	case *P256PublicKey:
		{
			e[0] = 3
			math.ReadBits(pub.X, e[1:len(e)/2+1])
			math.ReadBits(pub.Y, e[len(e)/2+1:])
			return e
		}
	}
	return e
	/*	if taiCrypto.AsymmetricCryptoType == taiCrypto.ASYMMETRICCRYPTOECDSA {
			math.ReadBits(key.Publickey.X, e[:len(e)/2])
			math.ReadBits(key.Publickey.Y, e[len(e)/2:])
		}
		if taiCrypto.AsymmetricCryptoType == taiCrypto.ASYMMETRICCRYPTOSM2 {
			math.ReadBits(key.SmPublickey.X, e[:len(e)/2])
			math.ReadBits(key.SmPublickey.Y, e[len(e)/2:])
		}

		return e*/
}
