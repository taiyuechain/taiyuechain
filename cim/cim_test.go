package cim

import (
	"fmt"

	"testing"

	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"github.com/taiyuechain/taiyuechain/common/hexutil"
	"github.com/taiyuechain/taiyuechain/crypto"
	"log"
	"math/big"
	"time"
	//"github.com/taiyuechain/taiyuechain/params"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm2"
	sm2_cert "github.com/taiyuechain/taiyuechain/crypto/gm/sm2/cert"
	"crypto/ecdsa"
	"encoding/hex"
	"os"
	"encoding/pem"
)

var (
	CryptoType = uint8(1)
	CryptoSM2  = uint8(2)

	pbft1PrivString ="7631a11e9d28563cdbcf96d581e4b9a19e53ad433a53c25a9f18c74ddf492f75"
	pbft2PrivString ="bab8dbdcb4d974eba380ff8b2e459efdb6f8240e5362e40378de3f9f5f1e67bb"
	pbft3PrivString ="122d186b77a030e04f5654e13d934b21af2aac03b942c3ecda4632364d81cbab"
	pbft4PrivString ="fe44cbc0e164092a6746bd57957422ab165c009d0299c7639a2f4d290317f20f"

	p2p1PrivString ="d5939c73167cd3a815530fd8b4b13f1f5492c1c75e4eafb5c07e8fb7f4b09c7c"
	p2p2PrivString ="ea4297749d514cc476fe971a7fe20100cbd29f010864341b3e624e8744d46cec"
	p2p3PrivString ="86937006ac1e6e2c846e160d93f86c0d63b0fcefc39a46e9eaeb65188909fbdc"
	p2p4PrivString ="cbddcbecd252a8586a4fd759babb0cc77f119d55f38bc7f80a708e75964dd801"

	pbft1Name = "pbft1priv"
	pbft2Name = "pbft2priv"
	pbft3Name = "pbft3priv"
	pbft4Name = "pbft4priv"

	p2p1Name = "p2p1cert"
	p2p2Name = "p2p2cert"
	p2p3Name = "p2p3cert"
	p2p4Name = "p2p4cert"

	pbft1path ="./testdata/testcert/"+pbft1Name+".pem"
	pbft2path ="./testdata/testcert/"+pbft2Name+".pem"
	pbft3path ="./testdata/testcert/"+pbft3Name+".pem"
	pbft4path ="./testdata/testcert/"+pbft4Name+".pem"

	p2p1path ="./testdata/testcert/"+p2p1Name+".pem"
	p2p2path ="./testdata/testcert/"+p2p2Name+".pem"
	p2p3path ="./testdata/testcert/"+p2p3Name+".pem"
	p2p4path ="./testdata/testcert/"+p2p4Name+".pem"
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
	ca_b := sm2_cert.CreateCertBySMPrivte(rootpri, rootPuk)

	rootCert, err := sm2_cert.ParseCertificate(ca_b)
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

	rootcert, err := sm2_cert.ParseCertificate(ca_b)
	if err != nil {
		t.Fatalf("ParseCertificate error")
	}

	son_byte, err := sm2_cert.IssueCert(rootcert, rootpri, sonPuk)
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
	byte, _ := crypto.ReadPemFileByPath(path)
	encodeca2 := base64.StdEncoding.EncodeToString(byte)
	fmt.Println(encodeca2)
}

func TestCreatePrivateKeyAndPublick(t *testing.T)  {
	pbft1Priv,_ := crypto.GenerateKey()
	pbft2Priv,_ := crypto.GenerateKey()
	pbft3Priv,_ := crypto.GenerateKey()
	pbft4Priv,_ := crypto.GenerateKey()

	p2p1Priv,_ := crypto.GenerateKey()
	p2p2Priv,_ := crypto.GenerateKey()
	p2p3Priv,_ := crypto.GenerateKey()
	p2p4Priv,_ := crypto.GenerateKey()

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

func TestCreateRootCert(t *testing.T)  {
	pbft1priv,_:=crypto.HexToECDSA(pbft1PrivString)
	pbft2priv,_:=crypto.HexToECDSA(pbft2PrivString)
	pbft3priv,_:=crypto.HexToECDSA(pbft3PrivString)
	pbft4priv,_:=crypto.HexToECDSA(pbft4PrivString)

	createRootCert(pbft1priv,pbft1Name)
	createRootCert(pbft2priv,pbft2Name)
	createRootCert(pbft3priv,pbft3Name)
	createRootCert(pbft4priv,pbft4Name)

}

func TestIsuseP2PCert(t *testing.T)  {



	pbft1priv,_:=crypto.HexToECDSA(pbft1PrivString)
	pbft2priv,_:=crypto.HexToECDSA(pbft2PrivString)
	pbft3priv,_:=crypto.HexToECDSA(pbft3PrivString)
	pbft4priv,_:=crypto.HexToECDSA(pbft4PrivString)

	p2p1priv,_:=crypto.HexToECDSA(p2p1PrivString)
	p2p2priv,_:=crypto.HexToECDSA(p2p2PrivString)
	p2p3priv,_:=crypto.HexToECDSA(p2p3PrivString)
	p2p4priv,_:=crypto.HexToECDSA(p2p4PrivString)

	//pbft1RootCert
	pbft1Byte,_:=crypto.ReadPemFileByPath(pbft1path)
	pbft1Cert ,_:=crypto.ParseCertificate(pbft1Byte)
	IssueCert(pbft1Cert,pbft1priv,&p2p1priv.PublicKey,p2p1Name)


	//pbft2RootCert
	pbft2Byte,_:=crypto.ReadPemFileByPath(pbft2path)
	pbft2Cert ,_:=crypto.ParseCertificate(pbft2Byte)
	IssueCert(pbft2Cert,pbft2priv,&p2p2priv.PublicKey,p2p2Name)

	//pbft3RootCert
	pbft3Byte,_:=crypto.ReadPemFileByPath(pbft3path)
	pbft3Cert ,_:=crypto.ParseCertificate(pbft3Byte)
	IssueCert(pbft3Cert,pbft3priv,&p2p3priv.PublicKey,p2p3Name)


	//pbft4RootCert
	pbft4Byte,_:=crypto.ReadPemFileByPath(pbft4path)
	pbft4Cert ,_:=crypto.ParseCertificate(pbft4Byte)
	IssueCert(pbft4Cert,pbft4priv,&p2p4priv.PublicKey,p2p4Name)

}

func TestVerifyCert(t *testing.T)  {

	pbft1Byte,_:=crypto.ReadPemFileByPath(pbft1path)
	pbft2Byte,_:=crypto.ReadPemFileByPath(pbft2path)
	pbft3Byte,_:=crypto.ReadPemFileByPath(pbft3path)
	pbft4Byte,_:=crypto.ReadPemFileByPath(pbft4path)

	p2p1Byte,_:=crypto.ReadPemFileByPath(p2p1path)
	p2p2Byte,_:=crypto.ReadPemFileByPath(p2p2path)
	p2p3Byte,_:=crypto.ReadPemFileByPath(p2p3path)
	p2p4Byte,_:=crypto.ReadPemFileByPath(p2p4path)

	//new cimList
	cimList := NewCIMList(CryptoSM2)
	cimList.AddCim(createCim(pbft1Byte))
	cimList.AddCim(createCim(pbft2Byte))
	cimList.AddCim(createCim(pbft3Byte))
	cimList.AddCim(createCim(pbft4Byte))

	err :=cimList.VerifyCert(p2p1Byte)
	if err !=nil{
		t.Fatalf("verify cert 1 error")
	}

	err =cimList.VerifyCert(p2p2Byte)
	if err !=nil{
		t.Fatalf("verify cert 2 error")
	}

	err =cimList.VerifyCert(p2p3Byte)
	if err !=nil{
		t.Fatalf("verify cert 3 error")
	}

	err =cimList.VerifyCert(p2p4Byte)
	if err !=nil{
		t.Fatalf("verify cert 4 error")
	}






}

func createRootCert(priKey *ecdsa.PrivateKey,name string )(cert []byte, err error)  {

	filepath :="./testdata/testcert/"+name+".pem"
	if crypto.CryptoType == crypto.CRYPTO_P256_SH3_AES{
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

		withPemFile(filepath,ca_b)


		return ca_b,err
	}

	if crypto.CryptoType == crypto.CRYPTO_SM2_SM3_SM4{
		ca_b ,err :=sm2_cert.CreateRootCert(sm2.ToSm2privatekey(priKey))

		File, err := os.Create(filepath)
		defer File.Close()
		if err != nil {
			return nil,err
		}
		b := &pem.Block{Bytes: ca_b, Type: "CERTIFICATE"}
		pem.Encode(File, b)

		return ca_b,err
	}
	return nil,nil
}

func IssueCert(rootCert *x509.Certificate, rootPri *ecdsa.PrivateKey,sonPuk *ecdsa.PublicKey,name string) (cert []byte, err error) {
	filepath :="./testdata/testcert/"+name+".pem"
	if crypto.CryptoType == crypto.CRYPTO_P256_SH3_AES{
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
		if err != nil{
			return nil,err
		}
		withPemFile(filepath,ca_b2)
		return ca_b2,nil
	}

	if crypto.CryptoType == crypto.CRYPTO_SM2_SM3_SM4{
		ca_b,err := sm2_cert.IssueCert(rootCert,sm2.ToSm2privatekey(rootPri),sm2.ToSm2Publickey(sonPuk))
		if err != nil{
			return nil,err
		}
		withPemFile(filepath,ca_b)

		return ca_b,nil

	}
	return nil,nil
}

func withPemFile(path string,cert []byte) error  {
	File, err := os.Create(path)
	defer File.Close()
	if err != nil {
		return err
	}
	b := &pem.Block{Bytes: cert, Type: "CERTIFICATE"}
	pem.Encode(File, b)

	return nil
}

func createCim(certbyte []byte) CIM  {
	cimCa, err := NewCIM()
	if err != nil {
		return nil
	}

	err = cimCa.SetUpFromCA(certbyte)
	if err != nil {
		//fmt.Println(err)
		return nil
	}

	return cimCa

}