package cim

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/pkg/errors"
	"github.com/taiyuechain/taiyuechain/crypto"
	"os"
	"crypto/elliptic"
	"io/ioutil"
	"math/big"
	"crypto/x509/pkix"
	"time"
	"log"
	"crypto/rand"

)



/*func GetCertFromPem(idBytes []byte,cryptoType uint8) (*x509.Certificate, error) {
	if idBytes == nil {
		return nil, errors.New("getCertFromPem error: nil idBytes")
	}

	// Decode the pem bytes

	//pemCert ,_:= base64.StdEncoding.DecodeString(string(idBytes))

	var cert *x509.Certificate
	var err error
	if cryptoType == 1{
		cert, err = x509.ParseCertificate(idBytes)
	}
	if cryptoType == 2{
		cert, err = sm2_cert.ParseCertificate(idBytes)
	}

	if err != nil {
		return nil, errors.Wrap(err, "getCertFromPem error: failed to parse x509 cert")
	}

	return cert, nil
}*/

/*func CreateIdentity(priv string) bool {
	//var private taiCrypto.TaiPrivateKey
	//var public taiCrypto.TaiPublicKey
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
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
	caecda, err := crypto.ToECDSA([]byte(priv))
	if err != nil {
		log.Println("create ca failed", err)
		return false
	}
	ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca, &caecda.PublicKey, &caecda)
	if err != nil {
		log.Println("create ca failed", err)
		return false
	}

	encodeString := base64.StdEncoding.EncodeToString(ca_b)

	fileName := priv[:4] + "ca.pem"
	dstFile, err := os.Create(fileName)
	if err != nil {
		return false
	}
	defer dstFile.Close()
	priv_b, _ := x509.MarshalECPrivateKey(caecda)
	encodeString1 := base64.StdEncoding.EncodeToString(priv_b)
	if err != nil {
		fmt.Println(err)
	}
	fileName1 := priv[:4] + "ca.key"
	dstFile1, err := os.Create(fileName1)
	if err != nil {
		return false
	}
	defer dstFile1.Close()
	dstFile1.WriteString(encodeString1 + "\n")
	fmt.Println(encodeString)
	return true
}*/

func CreateCertP256(priv *ecdsa.PrivateKey)( cert []byte)  {
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

	ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca, &priv.PublicKey, priv)
	if err != nil {
		log.Println("create ca failed", err)
		return nil
	}
	cert = ca_b
	return cert;
}

func CreateIdentity2(priv, priv2 *ecdsa.PrivateKey, name string) bool {


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

	ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca, &priv.PublicKey, priv)
	if err != nil {
		log.Println("create ca failed", err)
		return false
	}

	encodeca := base64.StdEncoding.EncodeToString(ca_b)
	fmt.Println(encodeca)
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

	theCert, err := x509.ParseCertificate(bytes)
	pubk1 := theCert.PublicKey
	var publicKeyBytes []byte

	switch pub2 := pubk1.(type) {
	case *ecdsa.PublicKey:
		publicKeyBytes = elliptic.Marshal(pub2.Curve, pub2.X, pub2.Y)

	}

	//pkcString := string()
	fmt.Println(publicKeyBytes)
	fmt.Println(crypto.FromECDSAPub(&priv.PublicKey))
	fmt.Println(crypto.FromECDSAPub(&priv2.PublicKey))
	if string(publicKeyBytes) == string(crypto.FromECDSAPub(&priv2.PublicKey)) {
		fmt.Println("1111succes")
	} else {
		if string(publicKeyBytes) == string(crypto.FromECDSAPub(&priv.PublicKey)) {
			fmt.Println("222success")
		}
	}
	//fmt.Println(pkcString)
	/*if(string(crypto.FromECDSA(pkcert)) == (string(crypto.FromECDSA(priv)))){
		fmt.Println("=====")
	}else{
		fmt.Println("not =====")
	}*/

	encodeString := base64.StdEncoding.EncodeToString(ca_b)
	fileName := "../../accounts/keystore/testdata/" + name + "ca.pem"
	dstFile, err := os.Create(fileName)
	if err != nil {
		return false
	}
	//dstFile.WriteString(encodeString + "\n")
	dstFile.WriteString(encodeString )
	defer dstFile.Close()
	/*
		priv_b, _ := x509.MarshalECPrivateKey(priv)
		encodeString1 := base64.StdEncoding.EncodeToString(priv_b)
		if err != nil {
			fmt.Println(err)
		}
		fileName1 := "test1" + "ca.key"
		dstFile1, err := os.Create(fileName1)
		if err != nil {
			return false
		}
		defer dstFile1.Close()
		dstFile1.WriteString(encodeString1 + "\n")
		fmt.Println(encodeString)*/
	return true
}

func VarifyCertByPubKey(pubkey *ecdsa.PublicKey, cert []byte) error {
	if cert == nil {
		return errors.New("cert is nil")
	}
	if pubkey == nil {
		return errors.New("pubkey is nil")
	}

	bytes, _ := base64.StdEncoding.DecodeString(string(cert))
	theCert, err := x509.ParseCertificate(bytes)
	if err != nil {
		return err
	}
	pubk := theCert.PublicKey
	var publicKeyBytes []byte

	switch pub2 := pubk.(type) {
	case *ecdsa.PublicKey:
		publicKeyBytes = elliptic.Marshal(pub2.Curve, pub2.X, pub2.Y)
	}

	if string(publicKeyBytes) == string(crypto.FromECDSAPub(pubkey)) {
		return nil
	} else {
		return errors.New("cert pubk not same with cert")
	}

}

type Configuration struct {
	Enabled   bool
	EcdsaPath string
	GmPath    string
}



func ReadPemFileUsePath(path string) ([]byte, error) {


	return ioutil.ReadFile(path)
}
