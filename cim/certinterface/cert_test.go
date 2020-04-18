package certinterface

import (
	"encoding/base64"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm2/cert"
	"github.com/taiyuechain/taiyuechain/crypto/taiCrypto"
	"testing"
)

func TestTaiPrivateKey_CreateIdentity2(t *testing.T) {
	//var taiprivate taiCrypto.TaiPrivateKey
	/*	pri,_:=GenerateKey(rand.Reader,elliptic.P256(),nil)
		CertType=CERTGM*/
	var tai taicrypto
	taiCrypto.AsymmetricCryptoType = taiCrypto.ASYMMETRICCRYPTOSM2
	pri, _ := taiCrypto.GenPrivKey()
	taiCrypto.CertType = taiCrypto.CERTGM
	//taicrypto.CreateIdentity2(pri, pri, "caoliang")
	tai.CreateIdentity2(pri, pri, "caoliang")
}

func TestTaiPrivateKey_ReadPemFileByPath(t *testing.T) {
	var tai taicrypto
	taiCrypto.AsymmetricCryptoType = taiCrypto.ASYMMETRICCRYPTOSM2
	//var taipublic TaiPublicKey
	//CertType=CERTECDSA
	taiCrypto.CertType = taiCrypto.CERTGM
	//fmt.Println(taiprivate.ReadPemFileByPath("caoliangca.pem"))
	filebyte, err := tai.ReadPemFileByPath("caoliangca.pem")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(filebyte))
	certbyte, _ := base64.StdEncoding.DecodeString(string(filebyte))
	//cert1,_:=taiprivate.GetCertFromPem(certbyte)
	//cert1,_:=x509.ParseCertificate(certbyte)
	cert1, _ := cert.ParseCertificateRequest(certbyte)
	//cert1,_:=taiprivate.GetCertFromPem(certbyte)
	fmt.Println(cert1)
	/*public:=cert1.PublicKey*/
	//var publicKeyBytes []byte

	/*	switch pub2 := public.(type) {*/
	/*	case *ecdsa.PublicKey:
		publicKeyBytes = elliptic.Marshal(pub2.Curve, pub2.X, pub2.Y)

	}*/
	//pkcString := string()
	/*	fmt.Println(publicKeyBytes)
		fmt.Println(crypto.FromECDSAPub(pub2))
		if string(publicKeyBytes) == string(crypto.FromECDSAPub(&priv2.PublicKey)) {
			fmt.Println("1111succes")
		}
		taipublic.Publickey=
		taiprivate.VarifyCertByPubkey(&taipublic,certbyte)*/
}

func TestTaiPrivateKey_VarifyCertByPubkey(t *testing.T) {
	taiCrypto.AsymmetricCryptoType = taiCrypto.ASYMMETRICCRYPTOSM2
	//var taiprivate TaiPrivateKey
	taiCrypto.CertType = taiCrypto.CERTECDSA
	bytes, _ := hexutil.Decode("0x04abcc9019d69fa42feca0b273704905b17567719f021a6cd7a78da5f5774d6278e3f07da8a34a997d09dd0d4a591f2e16df773c3548e66b8a3d9121d9df19d5b2")
	fmt.Println(len(bytes))
	public, _ := crypto.DecompressPubkey(bytes)
	fmt.Println(bytes)
	fmt.Println(public)
	a := "0xabcdd"
	b := "0x4"
	c := "abcdsakjjdsjkjsd"
	var data []byte = []byte(a)
	var data1 []byte = []byte(b)
	var data2 []byte = []byte(c)
	fmt.Println(data)
	fmt.Println(data1)
	data2 = append([]byte{0x4}, data2...)
	fmt.Println(data2)

}
