package taiCrypto

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/core"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm2"
	"io/ioutil"
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

func TestTHash_CreateAddress(t *testing.T) {
	//test guomi CreateAddress
	var thash THash
	var nonce uint64
	//src1 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	//src2 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	//src3 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	var address common.Address
	//core.AsymmetricCryptoType=core.ASYMMETRICCRYPTOSM2
	//core.HashCryptoType=core.HASHCRYPTOSM3
	//privateKey:=GenPrivKey()
	//pub:=privateKey.gmPrivate.PublicKey.GetRawBytes()
	//p:=pub[:20]
	//
	//for i:=0;i<20;i++{
	//	address[i]=p[i]
	//}
	//nonce=62332323
	//tt:=thash.CreateAddress(address,nonce)
	//fmt.Println(tt)
	//fmt.Println(len(tt))
	//	guoji CreateAddress test
	core.AsymmetricCryptoType = core.ASYMMETRICCRYPTOECDSA
	core.HashCryptoType = core.HASHCRYPTOHAS3
	privateKey := GenPrivKey()
	pub := privateKey.private.PublicKey
	var tai TaiPublicKey
	tai.publickey = pub
	pp := tai.FromECDSAPub(tai)
	p := pp[:20]
	for i := 0; i < 20; i++ {
		address[i] = p[i]
	}
	nonce = 62332323
	tt := thash.CreateAddress(address, nonce)
	fmt.Println(tt)
	fmt.Println(len(tt))
}

func TestTHash_CreateAddress2(t *testing.T) {
	//test guomi CreateAddress2
	var thash THash
	var salt [32]byte
	//src1 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	//src2 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	//src3 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	var address common.Address
	core.AsymmetricCryptoType = core.ASYMMETRICCRYPTOSM2
	core.HashCryptoType = core.HASHCRYPTOSM3
	privateKey := GenPrivKey()
	pub := privateKey.gmPrivate.PublicKey.GetRawBytes()
	p := pub[:20]
	for i := 0; i < 20; i++ {
		address[i] = p[i]
	}
	for j := 0; j < 20; j++ {
		salt[j] = p[j]
	}

	tt := thash.CreateAddress2(address, salt, p)
	fmt.Println(tt)
	fmt.Println(len(tt))
	//	guoji CreateAddress2 test
	/*	core.AsymmetricCryptoType=core.ASYMMETRICCRYPTOECDSA
			core.HashCryptoType=core.HASHCRYPTOHAS3
			privateKey:=GenPrivKey()
			pub:=privateKey.private.PublicKey
			var tai TaiPublicKey
			tai.publickey=pub
			pp:=tai.FromECDSAPub(tai)
			p:=pp[:20]
			for i:=0;i<20;i++{
				address[i]=p[i]
			}
		    for j:=0;j<20;j++{
				salt[j]=p[j]
			}

			tt:=thash.CreateAddress2(address,salt,pp)
			fmt.Println(tt)
			fmt.Println(len(tt))*/
}

func TestTHash_Keccak256(t *testing.T) {
	// guomi Keccak256 test
	var thash THash
	src1 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	//src2 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	//src3 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	/*core.HashCryptoType=core.HASHCRYPTOSM3
	tt:=thash.Keccak256(src1)
	fmt.Println(tt)
	fmt.Println(len(tt))*/
	//	guoji Keccak256 test
	core.HashCryptoType = core.HASHCRYPTOHAS3
	tt := thash.Keccak256(src1)
	fmt.Println(tt)
	fmt.Println(len(tt))
}

func TestTHash_Keccak256Hash(t *testing.T) {
	var thash THash
	src1 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	//src2 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	//src3 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	core.HashCryptoType = core.HASHCRYPTOSM3
	tt := thash.Keccak256Hash(src1)
	fmt.Println(tt)
	fmt.Println(len(tt))
	//	guoji Keccak256 test
	//	core.HashCryptoType=core.HASHCRYPTOHAS3
	//	tt:=thash.Keccak256Hash(src1)
	//	fmt.Println(tt)
	//	fmt.Println(len(tt))
}

func TestTHash_Keccak512(t *testing.T) {
	var thash THash
	src1 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	//src2 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	//src3 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	//guomi Keccak512 test
	core.HashCryptoType = core.HASHCRYPTOSM3
	tt := thash.Keccak512(src1)
	fmt.Println(tt)
	fmt.Println(len(tt))
}

func TestTaiPrivateKey_FromECDSA(t *testing.T) {

}

func TestTaiPrivateKey_HexToECDSA(t *testing.T) {
	//guomi test

	str := "5DD701828C424B84C5D56770ECF7C4FE882E654CAC53C7CC89A66B1709068B9D" // convert content to a 'string'
	/*fmt.Println(str) // print the content as a 'string'
	var taip TaiPrivateKey
	core.AsymmetricCryptoType=core.ASYMMETRICCRYPTOSM2
	core.HashCryptoType=core.HASHCRYPTOSM3
	/*gmp:= GenPrivKey()
	taip.gmPrivate=gmp.gmPrivate*/
	//fmt.Println(taip.HexToECDSA(str))*/
	//	    guiji test
	var taip TaiPrivateKey
	core.AsymmetricCryptoType = core.ASYMMETRICCRYPTOECDSA
	core.HashCryptoType = core.HASHCRYPTOHAS3
	gmp := GenPrivKey()
	taip.private = gmp.private
	fmt.Println(taip.HexToECDSA(str))
}

func TestTaiPrivateKey_LoadECDSA(t *testing.T) {
	//guomi test
	b, err := ioutil.ReadFile("H:/caoliang/caoliang.txt") // just pass the file name
	if err != nil {
		fmt.Print(err)
	}

	str := string(b) // convert content to a 'string'
	fmt.Println(str) // print the content as a 'string'
	var taip TaiPrivateKey
	core.AsymmetricCryptoType = core.ASYMMETRICCRYPTOSM2
	core.HashCryptoType = core.HASHCRYPTOSM3
	/*gmp:= GenPrivKey()
	taip.gmPrivate=gmp.gmPrivate*/
	fmt.Println(taip.LoadECDSA(str))
	//	    guiji test
	//var taip TaiPrivateKey
	//core.AsymmetricCryptoType=core.ASYMMETRICCRYPTOECDSA
	//core.HashCryptoType=core.HASHCRYPTOHAS3
	//gmp:= GenPrivKey()
	//taip.private=gmp.private
	//fmt.Println(taip.LoadECDSA(str))
}

func TestTaiPrivateKey_SaveECDSA(t *testing.T) {
	//guomi test
	b, err := ioutil.ReadFile("H:/caoliang/caoliang.txt") // just pass the file name
	if err != nil {
		fmt.Print(err)
	}

	str := string(b) // convert content to a 'string'
	fmt.Println(str) // print the content as a 'string'
	/*    var taip TaiPrivateKey
	 core.AsymmetricCryptoType=core.ASYMMETRICCRYPTOSM2
	core.HashCryptoType=core.HASHCRYPTOSM3
	gmp:= GenPrivKey()
	taip.gmPrivate=gmp.gmPrivate
	fmt.Println(taip.SaveECDSA(str,taip))*/
	//	    guiji test
	var taip TaiPrivateKey
	core.AsymmetricCryptoType = core.ASYMMETRICCRYPTOECDSA
	core.HashCryptoType = core.HASHCRYPTOHAS3
	gmp := GenPrivKey()
	taip.private = gmp.private
	fmt.Println(taip.SaveECDSA(str, taip))

}

func TestTaiPrivateKey_ToECDSA(t *testing.T) {
	//guomi _ToECDSA test

	core.AsymmetricCryptoType = core.ASYMMETRICCRYPTOSM2
	var gmp TaiPrivateKey
	tai := GenPrivKey()
	tai.gmPrivate.PublicKey = sm2.PublicKey{}
	pbytes := tai.gmPrivate.GetRawBytes()
	fmt.Println(len(pbytes))
	tpk, err := gmp.ToECDSA(pbytes)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(tpk.gmPrivate)
	fmt.Println(tai.gmPrivate)
	fmt.Println(tai.gmPrivate.PublicKey)
	//guoji ToECDSA test
	//	    core.AsymmetricCryptoType=core.ASYMMETRICCRYPTOECDSA
	//		tai:=GenPrivKey()
	//		var taipri   TaiPrivateKey
	//		taipri.private=tai.private
	//		tpri:=taipri.FromECDSA(taipri)
	//        private,err:= taipri.ToECDSA(tpri)
	//        if err!=nil{
	//        	fmt.Println(err)
	//		}
	//		fmt.Println(private.private)
	//		fmt.Println(tai.private)
	//		fmt.Println(tai.private.PublicKey)

}

func TestTaiPrivateKey_ToECDSAUnsafe(t *testing.T) {

}

func TestTaiPublicKey_CompressPubkey1(t *testing.T) {

}

func TestTaiPublicKey_FromECDSAPub(t *testing.T) {
	//guomi test
	var taipub TaiPublicKey

	core.HashCryptoType = core.HASHCRYPTOSM3
	core.AsymmetricCryptoType = core.ASYMMETRICCRYPTOSM2
	gmpub := GenPrivKey()
	taipub.smPublickey = gmpub.gmPrivate.PublicKey
	tt := taipub.FromECDSAPub(taipub)
	fmt.Println(tt)
	ttt, err := taipub.UnmarshalPubkey(tt)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(ttt.smPublickey)
	fmt.Println(gmpub.gmPrivate.PublicKey)
	// guoji test
	/*	var taipub TaiPublicKey

		core.HashCryptoType=core.HASHCRYPTOHAS3
		core.AsymmetricCryptoType=core.ASYMMETRICCRYPTOECDSA
		gmpub:= GenPrivKey()
		taipub.publickey=gmpub.private.PublicKey
		tt:=taipub.FromECDSAPub(taipub)
		fmt.Println(tt)
		ttt,err:=taipub.UnmarshalPubkey(tt)
		if err!=nil{
			fmt.Println(err)
		}
		fmt.Println(ttt.publickey)
		fmt.Println(gmpub.private.PublicKey)*/
}

func TestTaiPublicKey_PubkeyToAddress(t *testing.T) {
	//test guomi PubkeyToAddress
	/*	var taipub TaiPublicKey
		core.AsymmetricCryptoType= core.ASYMMETRICCRYPTOSM2
		core.HashCryptoType=core.HASHCRYPTOSM3
		pub:=GenPrivKey()
		taipub.smPublickey=pub.gmPrivate.PublicKey
		address:=taipub.PubkeyToAddress(taipub)
		fmt.Println(address)*/
	//	guiji test
	var taipub TaiPublicKey
	core.AsymmetricCryptoType = core.ASYMMETRICCRYPTOECDSA
	core.HashCryptoType = core.HASHCRYPTOHAS3
	pub := GenPrivKey()
	taipub.publickey = pub.private.PublicKey
	address := taipub.PubkeyToAddress(taipub)
	fmt.Println(address)

}

func TestValidateSignatureValues(t *testing.T) {

}
