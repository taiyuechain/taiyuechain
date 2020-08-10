/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sm2

import (
	"bytes"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	taicert "github.com/taiyuechain/taiyuechain/cert"
	"github.com/taiyuechain/taiyuechain/cim"
	"github.com/taiyuechain/taiyuechain/crypto"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestSm2(t *testing.T) {
	priv, err := GenerateKey() // 生成密钥对
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v\n", priv.Curve.IsOnCurve(priv.X, priv.Y)) // 验证是否为sm2的曲线
	pub := &priv.PublicKey
	msg := []byte("123456")
	d0, err := pub.Encrypt(msg)
	if err != nil {
		fmt.Printf("Error: failed to encrypt %s: %v\n", msg, err)
		return
	}
	// fmt.Printf("Cipher text = %v\n", d0)
	d1, err := priv.Decrypt(d0)
	if err != nil {
		fmt.Printf("Error: failed to decrypt: %v\n", err)
	}
	fmt.Printf("clear text = %s\n", d1)
	ok, err := WritePrivateKeytoPem("priv.pem", priv, nil) // 生成密钥文件
	if ok != true {
		log.Fatal(err)
	}
	pubKey, _ := priv.Public().(*PublicKey)
	ok, err = WritePublicKeytoPem("pub.pem", pubKey, nil) // 生成公钥文件
	if ok != true {
		log.Fatal(err)
	}
	msg = []byte("test")
	err = ioutil.WriteFile("ifile", msg, os.FileMode(0644)) // 生成测试文件
	if err != nil {
		log.Fatal(err)
	}
	privKey, err := ReadPrivateKeyFromPem("priv.pem", nil) // 读取密钥
	if err != nil {
		log.Fatal(err)
	}
	pubKey, err = ReadPublicKeyFromPem("pub.pem", nil) // 读取公钥
	if err != nil {
		log.Fatal(err)
	}
	msg, _ = ioutil.ReadFile("ifile")                // 从文件读取数据
	sign, err := privKey.Sign(rand.Reader, msg, nil) // 签名
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("ofile", sign, os.FileMode(0644))
	if err != nil {
		log.Fatal(err)
	}
	signdata, _ := ioutil.ReadFile("ofile")
	ok = privKey.Verify(msg, signdata) // 密钥验证
	if ok != true {
		fmt.Printf("Verify error\n")
	} else {
		fmt.Printf("Verify ok\n")
	}
	ok = pubKey.Verify(msg, signdata) // 公钥验证
	if ok != true {
		fmt.Printf("Verify error\n")
	} else {
		fmt.Printf("Verify ok\n")
	}
	templateReq := CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test"},
		},
		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,
	}
	_, err = CreateCertificateRequestToPem("req.pem", &templateReq, privKey)
	if err != nil {
		log.Fatal(err)
	}
	req, err := ReadCertificateRequestFromPem("req.pem")
	if err != nil {
		log.Fatal(err)
	}
	err = req.CheckSignature()
	if err != nil {
		log.Fatalf("Request CheckSignature error:%v", err)
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
	testExtKeyUsage := []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")
	commonName := "test.example.com"
	template := Certificate{
		// SerialNumber is negative to ensure that negative
		// values are parsed. This is due to the prevalence of
		// buggy code that produces certificates with negative
		// serial numbers.
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"TEST"},
			Country:      []string{"China"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Gopher",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "NL",
				},
			},
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),

		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     KeyUsageCertSign,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  true,

		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

		DNSNames:       []string{"test.example.com"},
		EmailAddresses: []string{"gopher@golang.org"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

		PolicyIdentifiers:   []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains: []string{".example.com", "example.com"},

		CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: extraExtensionData,
			},
			// This extension should override the SubjectKeyId, above.
			{
				Id:       oidExtensionSubjectKeyId,
				Critical: false,
				Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
			},
		},
	}
	pubKey, _ = priv.Public().(*PublicKey)
	ok, _ = CreateCertificateToPem("cert.pem", &template, &template, pubKey, privKey)
	if ok != true {
		fmt.Printf("failed to create cert file\n")
	}
	cert, err := ReadCertificateFromPem("cert.pem")
	if err != nil {
		fmt.Printf("failed to read cert file")
	}
	err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		log.Fatal(err)
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
}

func BenchmarkSM2(t *testing.B) {
	t.ReportAllocs()
	msg := []byte("test")
	priv, err := GenerateKey() // 生成密钥对
	if err != nil {
		log.Fatal(err)
	}
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sign, err := priv.Sign(rand.Reader, msg, nil) // 签名
		if err != nil {
			log.Fatal(err)
		}
		priv.Verify(msg, sign) // 密钥验证
		// if ok != true {
		// 	fmt.Printf("Verify error\n")
		// } else {
		// 	fmt.Printf("Verify ok\n")
		// }
	}
}

func TestKEB2(t *testing.T) {
	ida := []byte{'1', '2', '3', '4', '5', '6', '7', '8',
		'1', '2', '3', '4', '5', '6', '7', '8'}
	idb := []byte{'1', '2', '3', '4', '5', '6', '7', '8',
		'1', '2', '3', '4', '5', '6', '7', '8'}
	daBuf := []byte{0x81, 0xEB, 0x26, 0xE9, 0x41, 0xBB, 0x5A, 0xF1,
		0x6D, 0xF1, 0x16, 0x49, 0x5F, 0x90, 0x69, 0x52,
		0x72, 0xAE, 0x2C, 0xD6, 0x3D, 0x6C, 0x4A, 0xE1,
		0x67, 0x84, 0x18, 0xBE, 0x48, 0x23, 0x00, 0x29}
	dbBuf := []byte{0x78, 0x51, 0x29, 0x91, 0x7D, 0x45, 0xA9, 0xEA,
		0x54, 0x37, 0xA5, 0x93, 0x56, 0xB8, 0x23, 0x38,
		0xEA, 0xAD, 0xDA, 0x6C, 0xEB, 0x19, 0x90, 0x88,
		0xF1, 0x4A, 0xE1, 0x0D, 0xEF, 0xA2, 0x29, 0xB5}
	raBuf := []byte{0XD4, 0XDE, 0X15, 0X47, 0X4D, 0XB7, 0X4D, 0X06,
		0X49, 0X1C, 0X44, 0X0D, 0X30, 0X5E, 0X01, 0X24,
		0X00, 0X99, 0X0F, 0X3E, 0X39, 0X0C, 0X7E, 0X87,
		0X15, 0X3C, 0X12, 0XDB, 0X2E, 0XA6, 0X0B, 0XB3}

	rbBuf := []byte{0X7E, 0x07, 0x12, 0x48, 0x14, 0xB3, 0x09, 0x48,
		0x91, 0x25, 0xEA, 0xED, 0x10, 0x11, 0x13, 0x16,
		0x4E, 0xBF, 0x0F, 0x34, 0x58, 0xC5, 0xBD, 0x88,
		0x33, 0x5C, 0x1F, 0x9D, 0x59, 0x62, 0x43, 0xD6}

	expk := []byte{0x6C, 0x89, 0x34, 0x73, 0x54, 0xDE, 0x24, 0x84,
		0xC6, 0x0B, 0x4A, 0xB1, 0xFD, 0xE4, 0xC6, 0xE5}

	curve := P256Sm2()
	curve.ScalarBaseMult(daBuf)
	da := new(PrivateKey)
	da.PublicKey.Curve = curve
	da.D = new(big.Int).SetBytes(daBuf)
	da.PublicKey.X, da.PublicKey.Y = curve.ScalarBaseMult(daBuf)

	db := new(PrivateKey)
	db.PublicKey.Curve = curve
	db.D = new(big.Int).SetBytes(dbBuf)
	db.PublicKey.X, db.PublicKey.Y = curve.ScalarBaseMult(dbBuf)

	ra := new(PrivateKey)
	ra.PublicKey.Curve = curve
	ra.D = new(big.Int).SetBytes(raBuf)
	ra.PublicKey.X, ra.PublicKey.Y = curve.ScalarBaseMult(raBuf)

	rb := new(PrivateKey)
	rb.PublicKey.Curve = curve
	rb.D = new(big.Int).SetBytes(rbBuf)
	rb.PublicKey.X, rb.PublicKey.Y = curve.ScalarBaseMult(rbBuf)

	k1, Sb, S2, err := KeyExchangeB(16, ida, idb, db, &da.PublicKey, rb, &ra.PublicKey)
	if err != nil {
		t.Error(err)
	}
	k2, S1, Sa, err := KeyExchangeA(16, ida, idb, da, &db.PublicKey, ra, &rb.PublicKey)
	if err != nil {
		t.Error(err)
	}
	if bytes.Compare(k1, k2) != 0 {
		t.Error("key exchange differ")
	}
	if bytes.Compare(k1, expk) != 0 {
		t.Errorf("expected %x, found %x", expk, k1)
	}
	if bytes.Compare(S1, Sb) != 0 {
		t.Error("hash verfication failed")
	}
	if bytes.Compare(Sa, S2) != 0 {
		t.Error("hash verfication failed")
	}
}

func TestSm2ToCA(t *testing.T) {
	var (
		p2p1PrivString = "d5939c73167cd3a815530fd8b4b13f1f5492c1c75e4eafb5c07e8fb7f4b09c7c"
		p2p2PrivString = "ea4297749d514cc476fe971a7fe20100cbd29f010864341b3e624e8744d46cec"
		p2p3PrivString = "86937006ac1e6e2c846e160d93f86c0d63b0fcefc39a46e9eaeb65188909fbdc"
		p2p4PrivString = "cbddcbecd252a8586a4fd759babb0cc77f119d55f38bc7f80a708e75964dd801"
	)
	p2pPrivArr := []string{p2p1PrivString, p2p2PrivString, p2p3PrivString, p2p4PrivString}
	for i, priv := range p2pPrivArr {
		j := int64(i + 1)
		privEsda, err := crypto.HexToECDSA(priv)
		priv := ToSm2privatekey(privEsda)
		if err != nil {
			log.Fatal(err)
		}
		if i == 0 {
			fmt.Printf("%v\n", priv.Curve.IsOnCurve(priv.X, priv.Y)) // 验证是否为sm2的曲线
		}

		ok, err := WritePrivateKeytoPem("p2p"+strconv.FormatInt(j, 10)+".key", priv, nil) // 生成密钥文件
		if ok != true {
			log.Fatal(err)
		}
	}
}

func TestSm2RootToCA(t *testing.T) {
	var (
		pbft1PrivString = "7631a11e9d28563cdbcf96d581e4b9a19e53ad433a53c25a9f18c74ddf492f75"
		pbft2PrivString = "bab8dbdcb4d974eba380ff8b2e459efdb6f8240e5362e40378de3f9f5f1e67bb"
		pbft3PrivString = "122d186b77a030e04f5654e13d934b21af2aac03b942c3ecda4632364d81cbab"
		pbft4PrivString = "fe44cbc0e164092a6746bd57957422ab165c009d0299c7639a2f4d290317f20f"
	)
	p2pPrivArr := []string{pbft1PrivString, pbft2PrivString, pbft3PrivString, pbft4PrivString}
	for i, priv := range p2pPrivArr {
		j := int64(i + 1)
		privEsda, err := crypto.HexToECDSA(priv)
		priv := ToSm2privatekey(privEsda)
		if err != nil {
			log.Fatal(err)
		}
		if i == 0 {
			fmt.Printf("%v\n", priv.Curve.IsOnCurve(priv.X, priv.Y)) // 验证是否为sm2的曲线
		}

		ok, err := WritePrivateKeytoPem("bft"+strconv.FormatInt(j, 10)+".key", priv, nil) // 生成密钥文件
		if ok != true {
			log.Fatal(err)
		}
	}
}

var (
	CryptoSM2 = uint8(2)
	pbft1path = "bft1" + ".pem"
	pbft2path = "bft2" + ".pem"
	pbft3path = "bft3" + ".pem"
	pbft4path = "bft4" + ".pem"

	p2p1path = "p2p1" + ".pem"
	p2p2path = "p2p2" + ".pem"
)

func TestVerifyCert(t *testing.T) {
	pbft1Byte, _ := taicert.ReadPemFileByPath(pbft1path)
	pbft2Byte, _ := taicert.ReadPemFileByPath(pbft2path)

	p2p1Byte, _ := taicert.ReadPemFileByPath(p2p1path)
	p2p2Byte, _ := taicert.ReadPemFileByPath(p2p2path)

	//new cimList
	cimList := cim.NewCIMList(CryptoSM2)
	cimList.AddCim(cim.CreateCim(pbft1Byte))
	cimList.AddCim(cim.CreateCim(pbft2Byte))

	err := cimList.VerifyCert(p2p1Byte)
	if err != nil {
		t.Fatalf("verify cert 1 error")
	}

	err = cimList.VerifyCert(p2p2Byte)
	if err != nil {
		t.Fatalf("verify cert 2 error")
	}

	_, err = taicert.GetPubByteFromCert(p2p1Byte)
	if err != nil {
		panic(err)
	}
}

func TestPrintPem(t *testing.T) {
	pbft1Byte, _ := taicert.ReadPemFileByPath(pbft1path)
	pbft2Byte, _ := taicert.ReadPemFileByPath(pbft2path)
	pbft3Byte, _ := taicert.ReadPemFileByPath(pbft3path)
	pbft4Byte, _ := taicert.ReadPemFileByPath(pbft4path)
	fmt.Println(hex.EncodeToString(pbft1Byte))
	fmt.Println(hex.EncodeToString(pbft2Byte))
	fmt.Println(hex.EncodeToString(pbft3Byte))
	fmt.Println(hex.EncodeToString(pbft4Byte))

}