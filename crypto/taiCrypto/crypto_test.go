package taiCrypto

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/taiyuechain/taiyuechain/core"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm2"
	"reflect"
	"testing"
)

func TestGenPrivKey(t *testing.T) {
	//tests := []struct {
	//	name string
	//	want *TaiPrivateKey
	//}{
	//	// TODO: Add test cases.
	//}
	//for _, tt := range tests {
	//	t.Run(tt.name, func(t *testing.T) {
	//		if got := GenPrivKey(); !reflect.DeepEqual(got, tt.want) {
	//			t.Errorf("GenPrivKey() = %v, want %v", got, tt.want)
	//		}
	//	})
	//}
	//core.AsymmetricCryptoType=core.ASYMMETRICCRYPTOECDSA
	core.AsymmetricCryptoType = core.ASYMMETRICCRYPTOSM2
	tai := GenPrivKey()
	fmt.Println(tai.gmPrivate)
	fmt.Println(tai.private)
}

func TestHexToTaiPrivateKey(t *testing.T) {
	//type args struct {
	//	hexKey string
	//}
	//tests := []struct {
	//	name    string
	//	args    args
	//	want    *TaiPrivateKey
	//	wantErr bool
	//}{
	//	// TODO: Add test cases.
	//}
	//for _, tt := range tests {
	//	t.Run(tt.name, func(t *testing.T) {
	//		got, err := HexToTaiPrivateKey(tt.args.hexKey)
	//		if (err != nil) != tt.wantErr {
	//			t.Errorf("HexToTaiPrivateKey() error = %v, wantErr %v", err, tt.wantErr)
	//			return
	//		}
	//		if !reflect.DeepEqual(got, tt.want) {
	//			t.Errorf("HexToTaiPrivateKey() got = %v, want %v", got, tt.want)
	//		}
	//	})
	//}

	core.AsymmetricCryptoType = core.ASYMMETRICCRYPTOSM2
	tai, _ := HexToTaiPrivateKey("5DD701828C424B84C5D56770ECF7C4FE882E654CAC53C7CC89A66B1709068B9D")

	fmt.Println(tai.hexBytesPrivate)

}

func TestTaiPrivateKey_Public(t *testing.T) {
	var taiP TaiPrivateKey
	//guomi test
	core.AsymmetricCryptoType = core.ASYMMETRICCRYPTOSM2
	taiP.gmPrivate = GenPrivKey().gmPrivate
	fmt.Println(taiP.FromECDSA(taiP))
	// guoji test
	/*	core.AsymmetricCryptoType=core.ASYMMETRICCRYPTOECDSA
		taiP.private=GenPrivKey().private
		fmt.Println(taiP.FromECDSA(taiP))*/
}

func TestTaiPrivateKey_Sign(t *testing.T) {
	src1 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	//src2 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	//src3 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	var taiP TaiPrivateKey
	//guomi sign test
	/*	core.AsymmetricCryptoType=core.ASYMMETRICCRYPTOSM2
		core.HashCryptoType=core.HASHCRYPTOSM3
		taiP.gmPrivate=GenPrivKey().gmPrivate
		var thash THash
		hash:=thash.Keccak256Hash(src1)
		s := make([]byte,64)
		for i := 0; i < TaiHashLength; i++ {
			s[i] = hash[i]
		}
		sign,err:=taiP.Sign(s,taiP)
		if err!=nil{
			fmt.Println(err)
		}
		fmt.Printf("sign:%s\n", hex.EncodeToString(sign))
		//	guo mi VerifySignature
		var tpub TaiPublicKey
		tpub.smPublickey=taiP.gmPrivate.PublicKey
		tpub.VerifySignature(s,sign)*/
	// guoji sign test
	core.AsymmetricCryptoType = core.ASYMMETRICCRYPTOECDSA
	core.HashCryptoType = core.HASHCRYPTOHAS3
	taiP.private = GenPrivKey().private
	var thash THash
	hash := thash.Keccak256Hash(src1)
	s := make([]byte, 32)
	for i := 32; i < TaiHashLength; i++ {
		s[i-32] = hash[i-32]
	}
	sign, err := taiP.Sign(s, taiP)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("sign:%s\n", hex.EncodeToString(sign))
	// guoji VerifySignature test
	var tpub TaiPublicKey
	tpub.publickey = taiP.private.PublicKey

	fmt.Println(tpub.VerifySignature(s, sign[:64]))
}

func TestTaiPublicKey_CompressPubkey(t *testing.T) {
	type fields struct {
		hexBytesPublic []byte
		publickey      ecdsa.PublicKey
		smPublickey    sm2.PublicKey
	}
	type args struct {
		pubkey TaiPublicKey
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			TPK := &TaiPublicKey{
				hexBytesPublic: tt.fields.hexBytesPublic,
				publickey:      tt.fields.publickey,
				smPublickey:    tt.fields.smPublickey,
			}
			if got := TPK.CompressPubkey(tt.args.pubkey); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CompressPubkey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTaiPublicKey_SigToPub(t *testing.T) {
	//guoji sigtopub test
	src1 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	//src2 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	//src3 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	var taiP TaiPrivateKey
	var taipub TaiPublicKey
	/*core.AsymmetricCryptoType=core.ASYMMETRICCRYPTOECDSA
	core.HashCryptoType=core.HASHCRYPTOHAS3
	taiP.private=GenPrivKey().private
	var thash THash
	hash:=thash.Keccak256Hash(src1)
	s := make([]byte,32)
	for i := 32; i < TaiHashLength; i++ {
		s[i-32] = hash[i-32]
	}
	sign,err:=taiP.Sign(s,taiP)
	if err!=nil{
		fmt.Println(err)
	}
	fmt.Printf("sign:%s\n", hex.EncodeToString(sign))
	pub,err:=taipub.SigToPub(s,sign)
	if err!=nil{
		fmt.Println(err)
	}
	fmt.Println(pub.publickey)
	fmt.Println(taiP.private.PublicKey)*/
	//	guomi sigtopub test
	core.AsymmetricCryptoType = core.ASYMMETRICCRYPTOSM2
	core.HashCryptoType = core.HASHCRYPTOSM3
	taiP.gmPrivate = GenPrivKey().gmPrivate
	var thash THash
	hash := thash.Keccak256Hash(src1)
	s := make([]byte, 32)
	for i := 0; i < 32; i++ {
		s[i] = hash[i]
	}
	sign, err := taiP.Sign(s, taiP)

	if err != nil {
		fmt.Println(err)
	}
	//var recid   C.int
	//sign[64]=recid
	pub, err := taipub.SigToPub(s, sign)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(pub.smPublickey)
	fmt.Println(taiP.gmPrivate.PublicKey)
}

func TestTaiPublicKey_VerifySignature(t *testing.T) {

}
