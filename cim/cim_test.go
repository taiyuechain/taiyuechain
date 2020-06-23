package cim

import (
	"fmt"

	"testing"

	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"log"
	"math/big"
	"time"

	"github.com/taiyuechain/taiyuechain/common/hexutil"
	"github.com/taiyuechain/taiyuechain/crypto"
	taicert "github.com/taiyuechain/taiyuechain/cert"
	"github.com/taiyuechain/taiyuechain/params"

	//"github.com/taiyuechain/taiyuechain/params"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/pem"
	"os"

	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm2"
	//sm2_cert "github.com/taiyuechain/taiyuechain/crypto/gm/sm2/cert"
)

var (
	CryptoType = uint8(1)
	CryptoSM2  = uint8(2)

	pbft1PrivString = "7631a11e9d28563cdbcf96d581e4b9a19e53ad433a53c25a9f18c74ddf492f75"
	pbft2PrivString = "bab8dbdcb4d974eba380ff8b2e459efdb6f8240e5362e40378de3f9f5f1e67bb"
	pbft3PrivString = "122d186b77a030e04f5654e13d934b21af2aac03b942c3ecda4632364d81cbab"
	pbft4PrivString = "fe44cbc0e164092a6746bd57957422ab165c009d0299c7639a2f4d290317f20f"

	pbft1PubString = "04bdf9699d20b4ebabe76e76260480e5492c87aaeda51b138bd22c6d66b69549313dc3eb8c96dc9a1cbbf3b347322c51c05afdd609622277444e0f07e6bd35d8bd"
	pbft2PubString = "045e1711b6cd8550a5e5466f7f0868b5507929cb69c2f0fca84f8f94816eb40a808ea8a77c3d83c9d16341acb037fbea2f7d9d4af46326defa39b408f40f28fb98"
	pbft3PubString = "041b931d350257e881f27bce2563d98c99b13ca4f525a0662f5e7d53f085edff0dca8ceaae550c9f4ceecf217f72806a48a48fb024916392ae41d7c45168e89b94"
	pbft4PubString = "049923777d866fd80485be57a126d638cc7dda78a5d6958aff784ca7ed9d9c7be494125bf75fd0328490ae51020274427b9fbb07f59e4c9b5104ac6924721a4438"

	p2p1PrivString = "d5939c73167cd3a815530fd8b4b13f1f5492c1c75e4eafb5c07e8fb7f4b09c7c"
	p2p2PrivString = "ea4297749d514cc476fe971a7fe20100cbd29f010864341b3e624e8744d46cec"
	p2p3PrivString = "86937006ac1e6e2c846e160d93f86c0d63b0fcefc39a46e9eaeb65188909fbdc"
	p2p4PrivString = "cbddcbecd252a8586a4fd759babb0cc77f119d55f38bc7f80a708e75964dd801"

	pbft1Name = "pbft1priv"
	pbft2Name = "pbft2priv"
	pbft3Name = "pbft3priv"
	pbft4Name = "pbft4priv"

	p2p1Name = "p2p1cert"
	p2p2Name = "p2p2cert"
	p2p3Name = "p2p3cert"
	p2p4Name = "p2p4cert"

	pbft1path = "./testdata/testcert/" + pbft1Name + ".pem"
	pbft2path = "./testdata/testcert/" + pbft2Name + ".pem"
	pbft3path = "./testdata/testcert/" + pbft3Name + ".pem"
	pbft4path = "./testdata/testcert/" + pbft4Name + ".pem"

	p2p1path        = "./testdata/testcert/" + p2p1Name + ".pem"
	p2p2path        = "./testdata/testcert/" + p2p2Name + ".pem"
	p2p3path        = "./testdata/testcert/" + p2p3Name + ".pem"
	p2p4path        = "./testdata/testcert/" + p2p4Name + ".pem"
	pbft5PrivString = "77b4e6383502fd145cae5c2f8db28a9b750394bd70c0c138b915bb1327225489"
	pbft5Name       = "pbft5priv"
	pbft5path       = "./testdata/testcert/" + pbft5Name + ".pem"
	p2p5PrivString  = "5a25f1ad94e51092c041a38bd1f7a6dab203d90c0b673294cb7eb2c3e6a8576a"
	p2p5Name        = "p2p5cert"
	p2p5path        = "./testdata/testcert/" + p2p5Name + ".pem"
)

func TestCertCIMAndVerfiyCert(t *testing.T) {
	cimList := NewCIMList(CryptoType)

	var root, _ = crypto.HexToECDSA("696b0620068602ecdda42ada206f74952d8c305a811599d463b89cfa3ba3bb98")

	//create root
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	ca := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            []string{"China"},
			Organization:       []string{"Yjwt"},
			OrganizationalUnit: []string{"YjwtU"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca, &root.PublicKey, root)
	if err != nil {
		log.Println("create ca failed", err)
		//return false
		t.Fatalf("3")
	}

	//encodeca := base64.StdEncoding.EncodeToString(ca_b)
	//encodeca :=pem.Encode()
	rootCert, err := x509.ParseCertificate(ca_b)
	if err != nil {
		t.Fatalf("cert error")
	}

	err = rootCert.CheckSignature(rootCert.SignatureAlgorithm, rootCert.RawTBSCertificate, rootCert.Signature)
	if err != nil {
		log.Fatal(err)
	} else {
		fmt.Printf("CheckSignature ok\n")
	}

	cimCa, err := NewCIM()
	if err != nil {
		t.Fatalf("error for new cim")
	}

	err = cimCa.SetUpFromCA(ca_b)
	if err != nil {
		//fmt.Println(err)
		t.Fatalf("set cimCa error")
	}

	cimList.AddCim(cimCa)

	// son
	//bytes, _ := base64.StdEncoding.DecodeString(encodeca)

	/*rootCert, err := x509.ParseCertificate(bytes)
	if err != nil{
		t.Fatalf("cert error")
	}*/
	var son, _ = crypto.HexToECDSA("c1094d6cc368fa78f0175974968e9bf3d82216e87a6dfd59328220ac74181f47")
	serialNumberLimit2 := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber2, err := rand.Int(rand.Reader, serialNumberLimit2)
	ca2 := &x509.Certificate{
		SerialNumber: serialNumber2,
		Subject: pkix.Name{
			Country:            []string{"China"},
			Organization:       []string{"Yjwt"},
			OrganizationalUnit: []string{"YjwtU"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	ca_b2, err := x509.CreateCertificate(rand.Reader, ca2, rootCert, &son.PublicKey, root)
	if err != nil {
		log.Println("create ca failed", err)
		//return false
		t.Fatalf("2")
	}

	/*encodeca2 := base64.StdEncoding.EncodeToString(ca_b2)

	if len(encodeca2) == 0 {
		t.Fatalf("len is zero")
	}*/
	err = cimList.VerifyCert(ca_b2)
	if err != nil {
		t.Fatalf("verfiy error")
	}

}

func TestCertCIMAndVerfiyCert_SM2(t *testing.T) {
	cimList := NewCIMList(CryptoSM2)

	//HexToECDSAP
	//var root, _ = crypto.HexToECDSAP256("696b0620068602ecdda42ada206f74952d8c305a811599d463b89cfa3ba3bb98")
	//(prikey)
	//pribytebyte, err := hex.DecodeString("696b0620068602ecdda42ada206f74952d8c305a811599d463b89cfa3ba3bb98")
	//var rootpri, _ = sm2.RawBytesToPrivateKey(pribytebyte)
	//var rootPuk = sm2.PrivteToPublickey(*rootpri)
	rootpri, rootPuk, err := sm2.GenerateKey(rand.Reader)
	ca_b := taicert.CreateCertBySMPrivte(rootpri, rootPuk)

	rootCert, err := taicert.ParseCertificate(ca_b)
	if err != nil {
		t.Fatalf("cert error")
	}

	fmt.Println(rootCert)

	cimCa, err := NewCIM()
	if err != nil {
		t.Fatalf("error for new cim")
	}

	err = cimCa.SetUpFromCA(ca_b)
	if err != nil {
		//fmt.Println(err)
		t.Fatalf("set cimCa error")
	}

	cimList.AddCim(cimCa)

	// son
	//bytes, _ := base64.StdEncoding.DecodeString(encodeca)

	/*rootCert, err := x509.ParseCertificate(bytes)
	if err != nil{
		t.Fatalf("cert error")
	}*/
	//var son, _ = crypto.HexToECDSAP256("c1094d6cc368fa78f0175974968e9bf3d82216e87a6dfd59328220ac74181f47")
	//pribytebyte_son, err := hex.DecodeString("c1094d6cc368fa78f0175974968e9bf3d82216e87a6dfd59328220ac74181f47")
	//var son, _ = sm2.RawBytesToPrivateKey(pribytebyte_son)
	//var sonPuk = sm2.PrivteToPublickey(*son)
	_, sonPuk, err := sm2.GenerateKey(rand.Reader)

	rootcert, err := taicert.ParseCertificate(ca_b)
	if err != nil {
		t.Fatalf("ParseCertificate error")
	}

	son_byte, err := taicert.IssueCert(rootcert, rootpri, sonPuk)
	if err != nil {
		t.Fatalf("IssueCert error")
	}
	err = cimList.VerifyCert(son_byte)
	if err != nil {
		t.Fatalf("verfiy error")
	}

}

func TestCreateCertByPrivate(t *testing.T) {

	var prv, _ = crypto.HexToECDSA("696b0620068602ecdda42ada206f74952d8c305a811599d463b89cfa3ba3bb98")
	var prv2, _ = crypto.HexToECDSA("c1094d6cc368fa78f0175974968e9bf3d82216e87a6dfd59328220ac74181f47")
	var prv3, _ = crypto.HexToECDSA("96531838617b060305f04e5c9b760e8644454cadd375c1dd1fcd6140034a67a5")
	var prv4, _ = crypto.HexToECDSA("0477ce2c8b15abc55832b9218e624282ad351adcd1c23edc4459f087d4be7edf")
	//var prvB :=

	fmt.Println(crypto.FromECDSA(prv))
	fmt.Println(crypto.FromECDSA(prv2))
	fmt.Println(crypto.FromECDSA(prv3))
	fmt.Println(crypto.FromECDSA(prv4))
	//varpriKey, _     = crypto.HexToECDSA("0260c952edc49037129d8cabbe4603d15185d83aa718291279937fb6db0fa7a2")
	CreateIdentity2(prv, prv2, "696b")
	CreateIdentity2(prv2, prv2, "c109")
	CreateIdentity2(prv3, prv2, "9653")
	CreateIdentity2(prv4, prv2, "0477")
	//CreateIdentity2(prv4,prv2,"0477")
}

func TestVerifyCertByPrivate(t *testing.T) {
	/*var prv ,_ = crypto.HexToECDSAP256("696b0620068602ecdda42ada206f74952d8c305a811599d463b89cfa3ba3bb98")
	fmt.Println(crypto.FromECDSA(prv))
	path := "./testdata/testcert/696bca.pem"
	cert ,err :=ReadPemFileByPath(path)
	if err !=nil{
		t.Fatalf("ReadPemFileByPath err")
		return
	}
	tt := string(cert)
	log.Info("cert","is",tt)
	fmt.Println(tt)
	if VarifyCertByPrivateKey(prv,cert) != nil{
		t.Fatalf("VarifyCertByPrivateKey err")
		return
	}*/
}

func TestCreatePubk(t *testing.T) {
	var prv, _ = crypto.HexToECDSA("696b0620068602ecdda42ada206f74952d8c305a811599d463b89cfa3ba3bb98")
	var prv2, _ = crypto.HexToECDSA("c1094d6cc368fa78f0175974968e9bf3d82216e87a6dfd59328220ac74181f47")
	var prv3, _ = crypto.HexToECDSA("96531838617b060305f04e5c9b760e8644454cadd375c1dd1fcd6140034a67a5")
	var prv4, _ = crypto.HexToECDSA("0477ce2c8b15abc55832b9218e624282ad351adcd1c23edc4459f087d4be7edf")

	//pk :=
	pkbyte1 := crypto.FromECDSAPub(&prv.PublicKey)
	pkstring1 := hexutil.Encode(pkbyte1)
	fmt.Println(pkstring1)

	pkbyte2 := crypto.FromECDSAPub(&prv2.PublicKey)
	pkstring2 := hexutil.Encode(pkbyte2)
	fmt.Println(pkstring2)

	pkbyte3 := crypto.FromECDSAPub(&prv3.PublicKey)
	pkstring3 := hexutil.Encode(pkbyte3)
	fmt.Println(pkstring3)

	pkbyte4 := crypto.FromECDSAPub(&prv4.PublicKey)
	pkstring4 := hexutil.Encode(pkbyte4)
	fmt.Println(pkstring4)

	b, err := hexutil.Decode(pkstring1)

	_, err = crypto.UnmarshalPubkey(b)
	if err != nil {
		fmt.Println("errr", "is", err)
	}

}

func TestCreateAndVerifyRoot(t *testing.T) {
	var root, _ = crypto.HexToECDSA("696b0620068602ecdda42ada206f74952d8c305a811599d463b89cfa3ba3bb98")
	var son, _ = crypto.HexToECDSA("c1094d6cc368fa78f0175974968e9bf3d82216e87a6dfd59328220ac74181f47")
	var last, _ = crypto.HexToECDSA("96531838617b060305f04e5c9b760e8644454cadd375c1dd1fcd6140034a67a5")

	//create root
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	ca := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            []string{"China"},
			Organization:       []string{"Yjwt"},
			OrganizationalUnit: []string{"YjwtU"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca, &root.PublicKey, root)
	if err != nil {
		log.Println("create ca failed", err)
		//return false
		t.Fatalf("3")
	}

	encodeca := base64.StdEncoding.EncodeToString(ca_b)
	//fmt.Println(encodeca)
	bytes, _ := base64.StdEncoding.DecodeString(encodeca)
	/*var data []byte
	if strings.Contains(string(bytes), "-BEGIN CERTIFICATE-") {
		block, _ := pem.Decode(ca_b)
		if block == nil {
			fmt.Println("that ca not right")
		}
		data = block.Bytes
	}*/

	//theCert, err := x509.ParseCertificate(data)

	//t  :="696b0620068602ecdda42ada206f74952d8c305a811599d463b89cfa3ba3bb98"

	rootCert, err := x509.ParseCertificate(bytes)
	if err != nil {
		t.Fatalf("root error")
	}
	//create son

	serialNumberLimit2 := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber2, err := rand.Int(rand.Reader, serialNumberLimit2)
	ca2 := &x509.Certificate{
		SerialNumber: serialNumber2,
		Subject: pkix.Name{
			Country:            []string{"China"},
			Organization:       []string{"Yjwt"},
			OrganizationalUnit: []string{"YjwtU"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	ca_b2, err := x509.CreateCertificate(rand.Reader, ca2, rootCert, &son.PublicKey, root)
	if err != nil {
		log.Println("create ca failed", err)
		//return false
		t.Fatalf("2")
	}

	encodeca2 := base64.StdEncoding.EncodeToString(ca_b2)
	//fmt.Println(encodeca)
	bytes2, _ := base64.StdEncoding.DecodeString(encodeca2)
	/*var data []byte
	if strings.Contains(string(bytes), "-BEGIN CERTIFICATE-") {
		block, _ := pem.Decode(ca_b)
		if block == nil {
			fmt.Println("that ca not right")
		}
		data = block.Bytes
	}*/

	//theCert, err := x509.ParseCertificate(data)

	//t  :="696b0620068602ecdda42ada206f74952d8c305a811599d463b89cfa3ba3bb98"

	sonCert, err := x509.ParseCertificate(bytes2)

	//create******************************************************************//

	serialNumberLimit3 := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber3, err := rand.Int(rand.Reader, serialNumberLimit3)
	ca3 := &x509.Certificate{
		SerialNumber: serialNumber3,
		Subject: pkix.Name{
			Country:            []string{"China"},
			Organization:       []string{"Yjwt"},
			OrganizationalUnit: []string{"YjwtU"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	ca_b3, err := x509.CreateCertificate(rand.Reader, ca3, sonCert, &last.PublicKey, son)
	if err != nil {
		log.Println("create ca failed", err)
		//return false
		t.Fatalf("1")
	}

	encodeca3 := base64.StdEncoding.EncodeToString(ca_b3)
	//fmt.Println(encodeca)
	bytes3, _ := base64.StdEncoding.DecodeString(encodeca3)
	/*var data []byte
	if strings.Contains(string(bytes), "-BEGIN CERTIFICATE-") {
		block, _ := pem.Decode(ca_b)
		if block == nil {
			fmt.Println("that ca not right")
		}
		data = block.Bytes
	}*/

	//theCert, err := x509.ParseCertificate(data)

	//t  :="696b0620068602ecdda42ada206f74952d8c305a811599d463b89cfa3ba3bb98"

	lastCert, err := x509.ParseCertificate(bytes3)

	///verify cert
	err1 := lastCert.CheckSignatureFrom(rootCert)

	if err1 != nil {
		t.Fatalf("check CheckSignatureFrom")
	}

}

//func (c *Certificate) Verify(opts VerifyOptions) (chains [][]*Certificate, err error)

func TestCreateAndVerifyRoot22(t *testing.T) {
	//cert2 := []byte("MIIBrzCCAVSgAwIBAgIQGw+ZL1AAtkflUiPEAfDRSjAKBggqhkjOPQQDAjAvMQ4wDAYDVQQGEwVDaGluYTENMAsGA1UEChMEWWp3dDEOMAwGA1UECxMFWWp3dFUwHhcNMjAwNDA2MDMyNDMzWhcNMzAwNDA2MDMyNDMzWjAvMQ4wDAYDVQQGEwVDaGluYTENMAsGA1UEChMEWWp3dDEOMAwGA1UECxMFWWp3dFUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ/WgjVUvDJCIGMX+My7DluIgqkS/4pOl0W4LSljuS47FdFd5aP950rp9j0cuE+mNg/e1gXnJJcKMaIMd1yqurCo1IwUDAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0OBAcEBQECAwQFMAoGCCqGSM49BAMCA0kAMEYCIQDjw3r4fmSh1rOr4ziEZtPzK0VeJARifcdctKAkiPInMwIhAM7y15GEROMcmqazQazhUUVz8pxt89szqSq/oibmgKKw")
	//var certList= [][]byte{cert1, cert2, cert3, cert4}
	var root, _ = crypto.HexToECDSA("696b0620068602ecdda42ada206f74952d8c305a811599d463b89cfa3ba3bb98")

	//create root
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	ca := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            []string{"China"},
			Organization:       []string{"Yjwt"},
			OrganizationalUnit: []string{"YjwtU"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca, &root.PublicKey, root)
	if err != nil {
		log.Println("create ca failed", err)
		//return false
		t.Fatalf("3")
	}

	cert1, err := x509.ParseCertificate(ca_b)
	if err != nil {
		t.Fatalf("1")
	}

	cert2, err := x509.ParseCertificate(ca_b)
	if err != nil {
		t.Fatalf("1")
	}

	if !cert1.Equal(cert2) {
		t.Fatalf("not equl")
	}
}

func TestReadPemFile(t *testing.T) {
	path := "./testdata/testcert/peer-expired.pem"
	byte, _ := cert.ReadPemFileByPath(path)
	encodeca2 := base64.StdEncoding.EncodeToString(byte)
	fmt.Println(encodeca2)
}

func TestCreatePrivateKeyAndPublick(t *testing.T) {
	pbft1Priv, _ := crypto.GenerateKey()
	pbft2Priv, _ := crypto.GenerateKey()
	pbft3Priv, _ := crypto.GenerateKey()
	pbft4Priv, _ := crypto.GenerateKey()

	p2p1Priv, _ := crypto.GenerateKey()
	p2p2Priv, _ := crypto.GenerateKey()
	p2p3Priv, _ := crypto.GenerateKey()
	p2p4Priv, _ := crypto.GenerateKey()

	fmt.Println("pbft1Priv:")
	fmt.Println(hex.EncodeToString(crypto.FromECDSA(pbft1Priv)))
	fmt.Println("pbft2Priv:")
	fmt.Println(hex.EncodeToString(crypto.FromECDSA(pbft2Priv)))
	fmt.Println("pbft3Priv:")
	fmt.Println(hex.EncodeToString(crypto.FromECDSA(pbft3Priv)))
	fmt.Println("pbft4Priv:")
	fmt.Println(hex.EncodeToString(crypto.FromECDSA(pbft4Priv)))

	fmt.Println("p2p1Priv:")
	fmt.Println(hex.EncodeToString(crypto.FromECDSA(p2p1Priv)))
	fmt.Println("p2p2Priv:")
	fmt.Println(hex.EncodeToString(crypto.FromECDSA(p2p2Priv)))
	fmt.Println("p2p3Priv:")
	fmt.Println(hex.EncodeToString(crypto.FromECDSA(p2p3Priv)))
	fmt.Println("p2p4Priv:")
	fmt.Println(hex.EncodeToString(crypto.FromECDSA(p2p4Priv)))
}

func TestCreatePublick(t *testing.T) {
	pbft1priv, _ := crypto.HexToECDSA(pbft1PrivString)
	pbft2priv, _ := crypto.HexToECDSA(pbft2PrivString)
	pbft3priv, _ := crypto.HexToECDSA(pbft3PrivString)
	pbft4priv, _ := crypto.HexToECDSA(pbft4PrivString)

	fmt.Println("pbft1Priv:")
	fmt.Println(crypto.FromECDSAPub(&pbft1priv.PublicKey))
	fmt.Println(hex.EncodeToString(crypto.FromECDSAPub(&pbft1priv.PublicKey)))
	fmt.Println("pbft2Priv:")
	fmt.Println(hex.EncodeToString(crypto.FromECDSAPub(&pbft2priv.PublicKey)))
	fmt.Println("pbft3Priv:")
	fmt.Println(hex.EncodeToString(crypto.FromECDSAPub(&pbft3priv.PublicKey)))
	fmt.Println("pbft4Priv:")
	fmt.Println(hex.EncodeToString(crypto.FromECDSAPub(&pbft4priv.PublicKey)))

}

func TestCreateRootCert(t *testing.T) {
	pbft1priv, _ := crypto.HexToECDSA(pbft1PrivString)
	pbft2priv, _ := crypto.HexToECDSA(pbft2PrivString)
	pbft3priv, _ := crypto.HexToECDSA(pbft3PrivString)
	pbft4priv, _ := crypto.HexToECDSA(pbft4PrivString)

	createRootCert(pbft1priv, pbft1Name)
	createRootCert(pbft2priv, pbft2Name)
	createRootCert(pbft3priv, pbft3Name)
	createRootCert(pbft4priv, pbft4Name)

	pbft5priv, _ := crypto.HexToECDSA(pbft5PrivString)
	createRootCert(pbft5priv, pbft5Name)

}

func TestIsuseP2PCert(t *testing.T) {

	pbft1priv, _ := crypto.HexToECDSA(pbft1PrivString)
	pbft2priv, _ := crypto.HexToECDSA(pbft2PrivString)
	pbft3priv, _ := crypto.HexToECDSA(pbft3PrivString)
	pbft4priv, _ := crypto.HexToECDSA(pbft4PrivString)

	p2p1priv, _ := crypto.HexToECDSA(p2p1PrivString)
	p2p2priv, _ := crypto.HexToECDSA(p2p2PrivString)
	p2p3priv, _ := crypto.HexToECDSA(p2p3PrivString)
	p2p4priv, _ := crypto.HexToECDSA(p2p4PrivString)
	pbft5priv, _ := crypto.HexToECDSA(pbft5PrivString)
	p2p5priv, _ := crypto.HexToECDSA(p2p5PrivString)

	//pbft1RootCert
	pbft1Byte, _ := taicert.ReadPemFileByPath(pbft1path)
	pbft1Cert, _ := taicert.ParseCertificate(pbft1Byte)
	IssueCert(pbft1Cert, pbft1priv, &p2p1priv.PublicKey, p2p1Name)

	//pbft2RootCert
	pbft2Byte, _ := taicert.ReadPemFileByPath(pbft2path)
	pbft2Cert, _ := taicert.ParseCertificate(pbft2Byte)
	IssueCert(pbft2Cert, pbft2priv, &p2p2priv.PublicKey, p2p2Name)

	//pbft3RootCert
	pbft3Byte, _ := taicert.ReadPemFileByPath(pbft3path)
	pbft3Cert, _ := taicert.ParseCertificate(pbft3Byte)
	IssueCert(pbft3Cert, pbft3priv, &p2p3priv.PublicKey, p2p3Name)

	//pbft4RootCert
	pbft4Byte, _ := taicert.ReadPemFileByPath(pbft4path)
	pbft4Cert, _ := taicert.ParseCertificate(pbft4Byte)
	IssueCert(pbft4Cert, pbft4priv, &p2p4priv.PublicKey, p2p4Name)

	pbft5Byte, _ := taicert.ReadPemFileByPath(pbft5path)
	pbft5Cert, _ := taicert.ParseCertificate(pbft5Byte)
	IssueCert(pbft5Cert, pbft5priv, &p2p5priv.PublicKey, p2p5Name)
}

func TestGetPBFTCertBytes(t *testing.T) {

	pbft1Byte, _ := taicert.ReadPemFileByPath(pbft1path)
	pbft2Byte, _ := taicert.ReadPemFileByPath(pbft2path)
	pbft3Byte, _ := taicert.ReadPemFileByPath(pbft3path)
	pbft4Byte, _ := taicert.ReadPemFileByPath(pbft4path)

	fmt.Println("byt1")
	for i := 0; i < len(pbft1Byte); i++ {

		fmt.Print(pbft1Byte[i])
		fmt.Print(",")
	}
	fmt.Println("byt1")
	fmt.Println(pbft1Byte)
	fmt.Println("byt2")
	for i := 0; i < len(pbft2Byte); i++ {

		fmt.Print(pbft2Byte[i])
		fmt.Print(",")
	}
	fmt.Println(pbft2Byte)
	fmt.Println("byt3")
	for i := 0; i < len(pbft3Byte); i++ {

		fmt.Print(pbft3Byte[i])
		fmt.Print(",")
	}
	fmt.Println("byt3")
	fmt.Println(pbft3Byte)
	fmt.Println("byt4")
	for i := 0; i < len(pbft4Byte); i++ {

		fmt.Print(pbft4Byte[i])
		fmt.Print(",")
	}
	fmt.Println("byt4")
	fmt.Println(pbft4Byte)

}

func TestVerifyCert(t *testing.T) {

	pbft1Byte, _ := taicert.ReadPemFileByPath(pbft1path)
	pbft2Byte, _ := taicert.ReadPemFileByPath(pbft2path)
	pbft3Byte, _ := taicert.ReadPemFileByPath(pbft3path)
	pbft4Byte, _ := taicert.ReadPemFileByPath(pbft4path)

	p2p1Byte, _ := taicert.ReadPemFileByPath(p2p1path)
	p2p2Byte, _ := taicert.ReadPemFileByPath(p2p2path)
	p2p3Byte, _ := taicert.ReadPemFileByPath(p2p3path)
	p2p4Byte, _ := taicert.ReadPemFileByPath(p2p4path)

	//new cimList
	cimList := NewCIMList(CryptoSM2)
	cimList.AddCim(CreateCim(pbft1Byte))
	cimList.AddCim(CreateCim(pbft2Byte))
	cimList.AddCim(CreateCim(pbft3Byte))
	cimList.AddCim(CreateCim(pbft4Byte))


	err := cimList.VerifyCert(p2p1Byte)
	if err != nil {
		t.Fatalf("verify cert 1 error")
	}

	err = cimList.VerifyCert(p2p2Byte)
	if err != nil {
		t.Fatalf("verify cert 2 error")
	}

	err = cimList.VerifyCert(p2p3Byte)
	if err != nil {
		t.Fatalf("verify cert 3 error")
	}

	err = cimList.VerifyCert(p2p4Byte)
	if err != nil {
		t.Fatalf("verify cert 4 error")
	}

	_, err = taicert.GetPubByteFromCert(p2p1Byte)
	if err != nil {
		panic(err)
	}
}

func TestVerfyDempFile(t *testing.T) {
	cert1 := []byte{48, 130, 2, 142, 48, 130, 2, 58, 160, 3, 2, 1, 2, 2, 1, 255, 48, 10, 6, 8, 42, 129, 28, 207, 85, 1, 131, 117, 48, 48, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12, 10, 206, 163, 32, 65, 99, 109, 101, 32, 67, 111, 49, 25, 48, 23, 6, 3, 85, 4, 3, 19, 16, 116, 101, 115, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 30, 23, 13, 50, 48, 48, 53, 49, 50, 49, 49, 49, 57, 49, 54, 90, 23, 13, 50, 51, 48, 55, 49, 51, 50, 49, 48, 53, 53, 54, 90, 48, 48, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12, 10, 206, 163, 32, 65, 99, 109, 101, 32, 67, 111, 49, 25, 48, 23, 6, 3, 85, 4, 3, 19, 16, 116, 101, 115, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 129, 28, 207, 85, 1, 130, 45, 3, 66, 0, 4, 189, 249, 105, 157, 32, 180, 235, 171, 231, 110, 118, 38, 4, 128, 229, 73, 44, 135, 170, 237, 165, 27, 19, 139, 210, 44, 109, 102, 182, 149, 73, 49, 61, 195, 235, 140, 150, 220, 154, 28, 187, 243, 179, 71, 50, 44, 81, 192, 90, 253, 214, 9, 98, 34, 119, 68, 78, 15, 7, 230, 189, 53, 216, 189, 163, 130, 1, 67, 48, 130, 1, 63, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 4, 48, 38, 6, 3, 85, 29, 37, 4, 31, 48, 29, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 2, 42, 3, 6, 3, 129, 11, 1, 48, 15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3, 1, 1, 255, 48, 13, 6, 3, 85, 29, 14, 4, 6, 4, 4, 1, 2, 3, 4, 48, 95, 6, 8, 43, 6, 1, 5, 5, 7, 1, 1, 4, 83, 48, 81, 48, 35, 6, 8, 43, 6, 1, 5, 5, 7, 48, 1, 134, 23, 104, 116, 116, 112, 58, 47, 47, 111, 99, 115, 112, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 42, 6, 8, 43, 6, 1, 5, 5, 7, 48, 2, 134, 30, 104, 116, 116, 112, 58, 47, 47, 99, 114, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 116, 48, 26, 6, 3, 85, 29, 17, 4, 19, 48, 17, 130, 15, 102, 111, 111, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 15, 6, 3, 85, 29, 32, 4, 8, 48, 6, 48, 4, 6, 2, 42, 3, 48, 87, 6, 3, 85, 29, 31, 4, 80, 48, 78, 48, 37, 160, 35, 160, 33, 134, 31, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 49, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 108, 48, 37, 160, 35, 160, 33, 134, 31, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 50, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 108, 48, 10, 6, 8, 42, 129, 28, 207, 85, 1, 131, 117, 3, 66, 0, 131, 46, 82, 7, 238, 174, 229, 35, 21, 9, 185, 1, 207, 0, 140, 155, 37, 5, 51, 144, 102, 3, 144, 159, 133, 0, 25, 187, 107, 235, 88, 78, 120, 10, 180, 88, 86, 170, 145, 143, 188, 203, 241, 77, 36, 181, 65, 77, 101, 184, 110, 46, 241, 7, 57, 140, 91, 148, 142, 69, 22, 227, 8, 201, 104}
	cert2 := []byte{48, 130, 2, 142, 48, 130, 2, 58, 160, 3, 2, 1, 2, 2, 1, 255, 48, 10, 6, 8, 42, 129, 28, 207, 85, 1, 131, 117, 48, 48, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12, 10, 206, 163, 32, 65, 99, 109, 101, 32, 67, 111, 49, 25, 48, 23, 6, 3, 85, 4, 3, 19, 16, 116, 101, 115, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 30, 23, 13, 50, 48, 48, 53, 49, 50, 49, 49, 49, 57, 49, 54, 90, 23, 13, 50, 51, 48, 55, 49, 51, 50, 49, 48, 53, 53, 54, 90, 48, 48, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12, 10, 206, 163, 32, 65, 99, 109, 101, 32, 67, 111, 49, 25, 48, 23, 6, 3, 85, 4, 3, 19, 16, 116, 101, 115, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 129, 28, 207, 85, 1, 130, 45, 3, 66, 0, 4, 94, 23, 17, 182, 205, 133, 80, 165, 229, 70, 111, 127, 8, 104, 181, 80, 121, 41, 203, 105, 194, 240, 252, 168, 79, 143, 148, 129, 110, 180, 10, 128, 142, 168, 167, 124, 61, 131, 201, 209, 99, 65, 172, 176, 55, 251, 234, 47, 125, 157, 74, 244, 99, 38, 222, 250, 57, 180, 8, 244, 15, 40, 251, 152, 163, 130, 1, 67, 48, 130, 1, 63, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 4, 48, 38, 6, 3, 85, 29, 37, 4, 31, 48, 29, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 2, 42, 3, 6, 3, 129, 11, 1, 48, 15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3, 1, 1, 255, 48, 13, 6, 3, 85, 29, 14, 4, 6, 4, 4, 1, 2, 3, 4, 48, 95, 6, 8, 43, 6, 1, 5, 5, 7, 1, 1, 4, 83, 48, 81, 48, 35, 6, 8, 43, 6, 1, 5, 5, 7, 48, 1, 134, 23, 104, 116, 116, 112, 58, 47, 47, 111, 99, 115, 112, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 42, 6, 8, 43, 6, 1, 5, 5, 7, 48, 2, 134, 30, 104, 116, 116, 112, 58, 47, 47, 99, 114, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 116, 48, 26, 6, 3, 85, 29, 17, 4, 19, 48, 17, 130, 15, 102, 111, 111, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 15, 6, 3, 85, 29, 32, 4, 8, 48, 6, 48, 4, 6, 2, 42, 3, 48, 87, 6, 3, 85, 29, 31, 4, 80, 48, 78, 48, 37, 160, 35, 160, 33, 134, 31, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 49, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 108, 48, 37, 160, 35, 160, 33, 134, 31, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 50, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 108, 48, 10, 6, 8, 42, 129, 28, 207, 85, 1, 131, 117, 3, 66, 0, 54, 1, 43, 195, 143, 59, 59, 1, 217, 61, 117, 20, 211, 235, 240, 170, 36, 249, 228, 206, 10, 160, 246, 47, 38, 23, 140, 33, 150, 164, 210, 130, 163, 224, 124, 78, 241, 143, 7, 36, 39, 218, 139, 125, 36, 68, 65, 212, 170, 159, 86, 100, 223, 212, 24, 109, 113, 24, 210, 220, 210, 190, 190, 240, 27}
	cert3 := []byte{48, 130, 2, 142, 48, 130, 2, 58, 160, 3, 2, 1, 2, 2, 1, 255, 48, 10, 6, 8, 42, 129, 28, 207, 85, 1, 131, 117, 48, 48, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12, 10, 206, 163, 32, 65, 99, 109, 101, 32, 67, 111, 49, 25, 48, 23, 6, 3, 85, 4, 3, 19, 16, 116, 101, 115, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 30, 23, 13, 50, 48, 48, 53, 49, 50, 49, 49, 49, 57, 49, 54, 90, 23, 13, 50, 51, 48, 55, 49, 51, 50, 49, 48, 53, 53, 54, 90, 48, 48, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12, 10, 206, 163, 32, 65, 99, 109, 101, 32, 67, 111, 49, 25, 48, 23, 6, 3, 85, 4, 3, 19, 16, 116, 101, 115, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 129, 28, 207, 85, 1, 130, 45, 3, 66, 0, 4, 27, 147, 29, 53, 2, 87, 232, 129, 242, 123, 206, 37, 99, 217, 140, 153, 177, 60, 164, 245, 37, 160, 102, 47, 94, 125, 83, 240, 133, 237, 255, 13, 202, 140, 234, 174, 85, 12, 159, 76, 238, 207, 33, 127, 114, 128, 106, 72, 164, 143, 176, 36, 145, 99, 146, 174, 65, 215, 196, 81, 104, 232, 155, 148, 163, 130, 1, 67, 48, 130, 1, 63, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 4, 48, 38, 6, 3, 85, 29, 37, 4, 31, 48, 29, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 2, 42, 3, 6, 3, 129, 11, 1, 48, 15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3, 1, 1, 255, 48, 13, 6, 3, 85, 29, 14, 4, 6, 4, 4, 1, 2, 3, 4, 48, 95, 6, 8, 43, 6, 1, 5, 5, 7, 1, 1, 4, 83, 48, 81, 48, 35, 6, 8, 43, 6, 1, 5, 5, 7, 48, 1, 134, 23, 104, 116, 116, 112, 58, 47, 47, 111, 99, 115, 112, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 42, 6, 8, 43, 6, 1, 5, 5, 7, 48, 2, 134, 30, 104, 116, 116, 112, 58, 47, 47, 99, 114, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 116, 48, 26, 6, 3, 85, 29, 17, 4, 19, 48, 17, 130, 15, 102, 111, 111, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 15, 6, 3, 85, 29, 32, 4, 8, 48, 6, 48, 4, 6, 2, 42, 3, 48, 87, 6, 3, 85, 29, 31, 4, 80, 48, 78, 48, 37, 160, 35, 160, 33, 134, 31, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 49, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 108, 48, 37, 160, 35, 160, 33, 134, 31, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 50, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 108, 48, 10, 6, 8, 42, 129, 28, 207, 85, 1, 131, 117, 3, 66, 0, 23, 99, 174, 106, 168, 143, 97, 153, 142, 22, 9, 195, 162, 11, 204, 116, 48, 40, 149, 188, 129, 27, 73, 87, 44, 255, 22, 78, 131, 126, 150, 132, 56, 217, 250, 135, 153, 217, 27, 154, 225, 182, 2, 128, 193, 77, 27, 112, 199, 26, 195, 78, 146, 192, 47, 101, 168, 118, 251, 254, 110, 238, 154, 61, 252}
	cert4 := []byte{48, 130, 2, 142, 48, 130, 2, 58, 160, 3, 2, 1, 2, 2, 1, 255, 48, 10, 6, 8, 42, 129, 28, 207, 85, 1, 131, 117, 48, 48, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12, 10, 206, 163, 32, 65, 99, 109, 101, 32, 67, 111, 49, 25, 48, 23, 6, 3, 85, 4, 3, 19, 16, 116, 101, 115, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 30, 23, 13, 50, 48, 48, 53, 49, 50, 49, 49, 49, 57, 49, 54, 90, 23, 13, 50, 51, 48, 55, 49, 51, 50, 49, 48, 53, 53, 54, 90, 48, 48, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12, 10, 206, 163, 32, 65, 99, 109, 101, 32, 67, 111, 49, 25, 48, 23, 6, 3, 85, 4, 3, 19, 16, 116, 101, 115, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 129, 28, 207, 85, 1, 130, 45, 3, 66, 0, 4, 153, 35, 119, 125, 134, 111, 216, 4, 133, 190, 87, 161, 38, 214, 56, 204, 125, 218, 120, 165, 214, 149, 138, 255, 120, 76, 167, 237, 157, 156, 123, 228, 148, 18, 91, 247, 95, 208, 50, 132, 144, 174, 81, 2, 2, 116, 66, 123, 159, 187, 7, 245, 158, 76, 155, 81, 4, 172, 105, 36, 114, 26, 68, 56, 163, 130, 1, 67, 48, 130, 1, 63, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 4, 48, 38, 6, 3, 85, 29, 37, 4, 31, 48, 29, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 2, 42, 3, 6, 3, 129, 11, 1, 48, 15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3, 1, 1, 255, 48, 13, 6, 3, 85, 29, 14, 4, 6, 4, 4, 1, 2, 3, 4, 48, 95, 6, 8, 43, 6, 1, 5, 5, 7, 1, 1, 4, 83, 48, 81, 48, 35, 6, 8, 43, 6, 1, 5, 5, 7, 48, 1, 134, 23, 104, 116, 116, 112, 58, 47, 47, 111, 99, 115, 112, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 42, 6, 8, 43, 6, 1, 5, 5, 7, 48, 2, 134, 30, 104, 116, 116, 112, 58, 47, 47, 99, 114, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 116, 48, 26, 6, 3, 85, 29, 17, 4, 19, 48, 17, 130, 15, 102, 111, 111, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 15, 6, 3, 85, 29, 32, 4, 8, 48, 6, 48, 4, 6, 2, 42, 3, 48, 87, 6, 3, 85, 29, 31, 4, 80, 48, 78, 48, 37, 160, 35, 160, 33, 134, 31, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 49, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 108, 48, 37, 160, 35, 160, 33, 134, 31, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 50, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 108, 48, 10, 6, 8, 42, 129, 28, 207, 85, 1, 131, 117, 3, 66, 0, 73, 105, 46, 107, 12, 203, 248, 158, 67, 242, 104, 99, 83, 203, 126, 29, 111, 44, 140, 197, 57, 122, 49, 73, 25, 32, 96, 22, 151, 95, 174, 87, 52, 219, 117, 204, 227, 227, 32, 6, 11, 152, 89, 254, 173, 69, 140, 8, 156, 233, 7, 38, 117, 88, 223, 205, 150, 34, 231, 133, 66, 105, 110, 244, 46}
	cert, err := taicert.ParseCertificate(cert1)
	if err != nil {
		t.Fatalf("1111")
	}

	cert, err = taicert.ParseCertificate(cert2)
	if err != nil {
		t.Fatalf("1111")
	}

	cert, err = taicert.ParseCertificate(cert3)
	if err != nil {
		t.Fatalf("1111")
	}

	cert, err = taicert.ParseCertificate(cert4)
	if err != nil {
		t.Fatalf("1111")
	}
	fmt.Println(cert.PublicKey)

}

func createRootCert(priKey *ecdsa.PrivateKey, name string) (cert []byte, err error) {

	filepath := "./testdata/testcert/" + name + ".pem"
	if crypto.CryptoType == crypto.CRYPTO_P256_SH3_AES {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
		ca := &x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				Country:            []string{"China"},
				Organization:       []string{"Yjwt"},
				OrganizationalUnit: []string{"YjwtU"},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(10, 0, 0),
			SubjectKeyId:          []byte{1, 2, 3, 4, 5},
			BasicConstraintsValid: true,
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		}

		ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca, &priKey.PublicKey, priKey)


		withPemFile(filepath, ca_b)

		return ca_b, err
	}

	if crypto.CryptoType == crypto.CRYPTO_SM2_SM3_SM4 {
		ca_b, err := taicert.CreateRootCert(sm2.ToSm2privatekey(priKey))

		File, err := os.Create(filepath)
		defer File.Close()
		if err != nil {
			return nil, err
		}
		b := &pem.Block{Bytes: ca_b, Type: "CERTIFICATE"}
		pem.Encode(File, b)

		return ca_b, err
	}
	return nil, nil
}

func IssueCert(rootCert *x509.Certificate, rootPri *ecdsa.PrivateKey, sonPuk *ecdsa.PublicKey, name string) (cert []byte, err error) {
	filepath := "./testdata/testcert/" + name + ".pem"
	if crypto.CryptoType == crypto.CRYPTO_P256_SH3_AES {
		serialNumberLimit2 := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber2, err := rand.Int(rand.Reader, serialNumberLimit2)
		ca2 := &x509.Certificate{
			SerialNumber: serialNumber2,
			Subject: pkix.Name{
				Country:            []string{"China"},
				Organization:       []string{"Yjwt"},
				OrganizationalUnit: []string{"YjwtU"},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(10, 0, 0),
			SubjectKeyId:          []byte{1, 2, 3, 4, 5},
			BasicConstraintsValid: true,
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		}

		ca_b2, err := x509.CreateCertificate(rand.Reader, ca2, rootCert, sonPuk, rootPri)
		if err != nil {
			return nil, err
		}
		withPemFile(filepath, ca_b2)
		return ca_b2, nil
	}

	if crypto.CryptoType == crypto.CRYPTO_SM2_SM3_SM4 {
		ca_b, err := taicert.IssueCert(rootCert, sm2.ToSm2privatekey(rootPri), sm2.ToSm2Publickey(sonPuk))
		if err != nil {
			return nil, err
		}
		withPemFile(filepath, ca_b)

		return ca_b, nil

	}
	return nil, nil
}

func withPemFile(path string, cert []byte) error {
	File, err := os.Create(path)
	defer File.Close()
	if err != nil {
		return err
	}
	b := &pem.Block{Bytes: cert, Type: "CERTIFICATE"}
	pem.Encode(File, b)

	return nil
}

func TestO1(t *testing.T) {
	SendP256Transtion()
	fmt.Println("finish")
}
func SendP256Transtion() {
	crypto.SetCrtptoType(crypto.CRYPTO_P256_SH3_AES)
	//ok fc888b21ac3f492376c2e1cece9ed3b1c54ddb0ceafbed12ec2ad7f50312471f
	//bad 4a41d5c5fa542bb313f7457b3404f134f5d33ecee68d6cef07f0bbc9e12320ed
	fromPrivateStr := "fc888b21ac3f492376c2e1cece9ed3b1c54ddb0ceafbed12ec2ad7f50312471f"
	toPrivateStr := "696b0620068602ecdda42ada206f74952d8c305a811599d463b89cfa3ba3bb98"

	//sendRawTransaction(client *rpc.Client, from string, to string, value string) (string, error)
	var fromPrive, _ = crypto.HexToECDSA(fromPrivateStr)
	var toPrive, _ = crypto.HexToECDSA(toPrivateStr)

	from := crypto.PubkeyToAddress(fromPrive.PublicKey)
	amount := new(big.Int).SetInt64(1000000000000000000)
	fmt.Println("amount", amount)
	nonce := uint64(2)
	//nonce := client.GetNonceAtBlockNumber(context.Background(),from,)

	//to
	//tocertbyte := crypto.CreateCertP256(toPrive)

	//toCert, err := x509.ParseCertificate(tocertbyte)
	//if err != nil {
	//	return
	//}
	//fmt.Println(tocert.Version)
	//var topubk ecdsa.PublicKey
	//switch pub := toCert.PublicKey.(type) {
	//case *ecdsa.PublicKey:
	//	topubk.Curve = pub.Curve
	//	topubk.X = pub.X
	//	topubk.Y = pub.Y
	//}

	// from
	path := "./testdata/testcert/testOkp2p.pem"
	fromcert, err := taicert.ReadPemFileByPath(path)
	if err != nil {
		fmt.Println(err)
		return
	}

	chainID := big.NewInt(100)

	to := crypto.PubkeyToAddress(toPrive.PublicKey)
	fmt.Println("--from address", hexutil.Encode(from.Bytes()), "--to address", hexutil.Encode(to.Bytes()))

	//send true transfer
	tx := types.NewP256Transaction(nonce, &to, nil, amount,
		new(big.Int).SetInt64(0), params.TxGas, new(big.Int).SetInt64(0), nil, fromcert, chainID, nil)

	signer := types.NewSigner(chainID)
	signTx, _ := types.SignTx(tx, signer, fromPrive)

	if addr, err := types.Sender(signer, signTx); err != nil {
		fmt.Println("err:", err)
	} else {
		fmt.Println("addr:", addr)
	}
	fmt.Println("--end send ")
	fmt.Println("tx Hash", "is", hexutil.Encode(signTx.Hash().Bytes()))
}
func TestO12(t *testing.T) {
	//var s [][]byte
	//var t1 [][]byte
	s := make([][]byte,2)
	s[0] = []byte{'1','2'}
	s[1] = []byte{'3','4'}

	t1 := make([][]byte,2)
	for i:=0;i<len(s);i++{
		t1[i] = append(t1[i],s[i][:]...)
	}

	fmt.Println("t","t",t1[1][1])


	s[1] = []byte{'3','9'}

	fmt.Println("t","t",t1[1][1])



	ss := []byte{'1','2'}
	fmt.Println("t","t",ss[1])
	ss =ss[0:0]
	fmt.Println("t","t",len(ss))



}

func TestGMSSL(t *testing.T){

	rootPath := "./testdata/testcert/" + "root.pem"
	rootByte, _ := taicert.ReadPemFileByPath(rootPath)


	certPath :="./testdata/testcert/" + "ca.pem"
	certByte, _ := taicert.ReadPemFileByPath(certPath)


	//new cimList
	cimList := NewCIMList(CryptoSM2)
	cimList.AddCim(CreateCim(rootByte))


	err := cimList.VerifyCert(certByte)
	if err != nil{
		t.Fatalf("verfiy error")
	}
}