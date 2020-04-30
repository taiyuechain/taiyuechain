package cim

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/taiyuechain/taiyuechain/cim/config"
	"path/filepath"
	"testing"

	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"github.com/taiyuechain/taiyuechain/common/hexutil"
	"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/crypto/taiCrypto"
	"log"
	"math/big"
	"time"
)

/*func TestMain(m *testing.M) {
	cimConfigDir, _ := config.GetDevCIMDir()
	cimID := "simpleCIM"
	err := InitCrypto(cimConfigDir, cimID)
	if err != nil {
		fmt.Printf("Setup for CMI should have succeeded, got err %s instead", err)
		os.Exit(-1)
	}
	retVal := m.Run()
	os.Exit(retVal)
}*/

func TestNewIdentity(t *testing.T) {
	cimConfigDir, _ := config.GetDevCIMDir()
	singcertPath := cimConfigDir + "testcert"
	id, err := GetLocalIdentityDataFromConfig(singcertPath)
	assert.Error(t, err)
	assert.NotNil(t, id)
}

func TestChectIdentity(t *testing.T) {
	cimConfigDir, _ := config.GetDevConfigDir()
	cimDir, _ := config.GetDevCIMDir()
	singcertPath := filepath.Join(cimConfigDir, "/testcert")
	id, err := GetLocalIdentityDataFromConfig(singcertPath)
	assert.NotNil(t, id)
	err = GetLocalCIM().Validate(id)
	assert.Error(t, err)
	singcertValidPath := filepath.Join(cimDir, "/signcerts")
	certValidId, err := GetLocalIdentityDataFromConfig(singcertValidPath)
	assert.NotNil(t, id)
	err = GetLocalCIM().Validate(certValidId)
	assert.Error(t, err)
}

func TestSignAndVerify(t *testing.T) {
	cim := GetLocalCIM()
	id := cim.GetSigningIdentity()

	msg := []byte("foo")
	sig, err := id.Sign(msg)
	if err != nil {
		t.Fatalf("Sign should have succeeded")
		return
	}

	err = id.Verify(msg, sig)
	if err != nil {
		t.Fatalf("The signature should be valid")
		return
	}

	err = id.Verify(msg[1:], sig)
	assert.Error(t, err)
	err = id.Verify(msg, sig[1:])
	assert.Error(t, err)
}

func TestCertCIMAndVerfiyCert(t *testing.T) {
	cimList := NewCIMList()

	var root, _ = crypto.HexToECDSAP256("696b0620068602ecdda42ada206f74952d8c305a811599d463b89cfa3ba3bb98")

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
	//ecdsa, err := taiCrypto.HexToTaiPrivateKey(priv)
	//var thash taiCrypto.THash
	//caecda, err := private.ToECDSACA(ecdsa.HexBytesPrivate)
	//caecda, err := private.ToECDSACA([]byte(priv))
	//pub := crypto.FromECDSAPub(&priv.PublicKey)
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
	var son, _ = crypto.HexToECDSAP256("c1094d6cc368fa78f0175974968e9bf3d82216e87a6dfd59328220ac74181f47")
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
	//ecdsa, err := taiCrypto.HexToTaiPrivateKey(priv)
	//var thash taiCrypto.THash
	//caecda, err := private.ToECDSACA(ecdsa.HexBytesPrivate)
	//caecda, err := private.ToECDSACA([]byte(priv))
	//pub := crypto.FromECDSAPub(&priv.PublicKey)
	ca_b2, err := x509.CreateCertificate(rand.Reader, ca2, rootCert, &son.PublicKey, root)
	if err != nil {
		log.Println("create ca failed", err)
		//return false
		t.Fatalf("2")
	}

	encodeca2 := base64.StdEncoding.EncodeToString(ca_b2)

	if len(encodeca2) == 0 {
		t.Fatalf("len is zero")
	}
	err = cimList.VerifyCert(ca_b2)
	if err != nil {
		t.Fatalf("verfiy error")
	}

}

func TestCreateCertByPrivate(t *testing.T) {

	var prv, _ = crypto.HexToECDSAP256("696b0620068602ecdda42ada206f74952d8c305a811599d463b89cfa3ba3bb98")
	var prv2, _ = crypto.HexToECDSAP256("c1094d6cc368fa78f0175974968e9bf3d82216e87a6dfd59328220ac74181f47")
	var prv3, _ = crypto.HexToECDSAP256("96531838617b060305f04e5c9b760e8644454cadd375c1dd1fcd6140034a67a5")
	var prv4, _ = crypto.HexToECDSAP256("0477ce2c8b15abc55832b9218e624282ad351adcd1c23edc4459f087d4be7edf")
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
	var prv, _ = crypto.HexToECDSAP256("696b0620068602ecdda42ada206f74952d8c305a811599d463b89cfa3ba3bb98")
	var prv2, _ = crypto.HexToECDSAP256("c1094d6cc368fa78f0175974968e9bf3d82216e87a6dfd59328220ac74181f47")
	var prv3, _ = crypto.HexToECDSAP256("96531838617b060305f04e5c9b760e8644454cadd375c1dd1fcd6140034a67a5")
	var prv4, _ = crypto.HexToECDSAP256("0477ce2c8b15abc55832b9218e624282ad351adcd1c23edc4459f087d4be7edf")

	//pk :=
	pkbyte1 := crypto.FromECDSAPubCA(&prv.PublicKey)
	pkstring1 := hexutil.Encode(pkbyte1)
	fmt.Println(pkstring1)

	pkbyte2 := crypto.FromECDSAPubCA(&prv2.PublicKey)
	pkstring2 := hexutil.Encode(pkbyte2)
	fmt.Println(pkstring2)

	pkbyte3 := crypto.FromECDSAPubCA(&prv3.PublicKey)
	pkstring3 := hexutil.Encode(pkbyte3)
	fmt.Println(pkstring3)

	pkbyte4 := crypto.FromECDSAPubCA(&prv4.PublicKey)
	pkstring4 := hexutil.Encode(pkbyte4)
	fmt.Println(pkstring4)

	var taipublic taiCrypto.TaiPublicKey

	b, err := hexutil.Decode(pkstring1)
	taiCrypto.AsymmetricCryptoType = taiCrypto.ASYMMETRICCRYPTOECDSA
	_, err = taipublic.UnmarshalPubkey(b)
	if err != nil {
		fmt.Println("errr", "is", err)
	}

}

func TestCreateAndVerifyRoot(t *testing.T) {
	var root, _ = crypto.HexToECDSAP256("696b0620068602ecdda42ada206f74952d8c305a811599d463b89cfa3ba3bb98")
	var son, _ = crypto.HexToECDSAP256("c1094d6cc368fa78f0175974968e9bf3d82216e87a6dfd59328220ac74181f47")
	var last, _ = crypto.HexToECDSAP256("96531838617b060305f04e5c9b760e8644454cadd375c1dd1fcd6140034a67a5")

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
	//ecdsa, err := taiCrypto.HexToTaiPrivateKey(priv)
	//var thash taiCrypto.THash
	//caecda, err := private.ToECDSACA(ecdsa.HexBytesPrivate)
	//caecda, err := private.ToECDSACA([]byte(priv))
	//pub := crypto.FromECDSAPub(&priv.PublicKey)
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
	//ecdsa, err := taiCrypto.HexToTaiPrivateKey(priv)
	//var thash taiCrypto.THash
	//caecda, err := private.ToECDSACA(ecdsa.HexBytesPrivate)
	//caecda, err := private.ToECDSACA([]byte(priv))
	//pub := crypto.FromECDSAPub(&priv.PublicKey)
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
	//ecdsa, err := taiCrypto.HexToTaiPrivateKey(priv)
	//var thash taiCrypto.THash
	//caecda, err := private.ToECDSACA(ecdsa.HexBytesPrivate)
	//caecda, err := private.ToECDSACA([]byte(priv))
	//pub := crypto.FromECDSAPub(&priv.PublicKey)
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
	cert2 := []byte("MIIBrzCCAVSgAwIBAgIQGw+ZL1AAtkflUiPEAfDRSjAKBggqhkjOPQQDAjAvMQ4wDAYDVQQGEwVDaGluYTENMAsGA1UEChMEWWp3dDEOMAwGA1UECxMFWWp3dFUwHhcNMjAwNDA2MDMyNDMzWhcNMzAwNDA2MDMyNDMzWjAvMQ4wDAYDVQQGEwVDaGluYTENMAsGA1UEChMEWWp3dDEOMAwGA1UECxMFWWp3dFUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ/WgjVUvDJCIGMX+My7DluIgqkS/4pOl0W4LSljuS47FdFd5aP950rp9j0cuE+mNg/e1gXnJJcKMaIMd1yqurCo1IwUDAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0OBAcEBQECAwQFMAoGCCqGSM49BAMCA0kAMEYCIQDjw3r4fmSh1rOr4ziEZtPzK0VeJARifcdctKAkiPInMwIhAM7y15GEROMcmqazQazhUUVz8pxt89szqSq/oibmgKKw")
	//var certList= [][]byte{cert1, cert2, cert3, cert4}

	//startTime := time.Now().UnixNano()
	//var certificate *x509.Certificate
	_, err := x509.ParseCertificate(cert2)
	if err != nil {
		t.Fatalf("1")
	}
	//fmt.Println(certificate == nil)
}
