package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"

	"crypto/x509"
	"github.com/pkg/errors"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm2"
	sm2_cert "github.com/taiyuechain/taiyuechain/crypto/gm/sm2/cert"
	"io/ioutil"
	"encoding/pem"
	"strings"
	"fmt"
)

func IsCorrectSY(syCrypto interface{}) bool {

	switch pub := syCrypto.(type) {
	case *sm2.PublicKey:
		if CryptoType == CRYPTO_SM2_SM3_SM4 {
			return true
		}
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			if CryptoType == CRYPTO_P256_SH3_AES {
				return true
			}
		}
	}
	return false
}

func GetCertFromByte(idBytes []byte) (*x509.Certificate, error) {
	if idBytes == nil {
		return nil, errors.New("getCertFromPem error: nil idBytes")
	}

	cert, err := ParseCertificate(idBytes)

	if err != nil {
		return nil, errors.Wrap(err, "getCertFromPem error: failed to parse x509 cert")
	}

	return cert, nil
}

func ParseCertificate(asn1Data []byte) (*x509.Certificate, error) {
	if asn1Data == nil {
		return nil, errors.New("getCertFromPem error: nil idBytes")
	}
	if CryptoType == CRYPTO_P256_SH3_AES {
		return x509.ParseCertificate(asn1Data)
	} else if CryptoType == CRYPTO_SM2_SM3_SM4 {
		return sm2_cert.ParseCertificate(asn1Data)
	}
	return nil, nil

}

func CheckSignatureFrom(son *x509.Certificate, parent *x509.Certificate) error {
	if CryptoType == CRYPTO_P256_SH3_AES {
		return son.CheckSignatureFrom(parent)
	}
	if CryptoType == CRYPTO_SM2_SM3_SM4 {
		return sm2_cert.CheckSignatureFrom(son, parent)
	}
	return nil
}

func CheckSignatrue(cert *x509.Certificate) error {
	if CryptoType == CRYPTO_P256_SH3_AES {
		return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	}
	if CryptoType == CRYPTO_SM2_SM3_SM4 { //sm2
		return sm2_cert.CheckSignature(cert)
	}
	return nil
}

func IsEqulCert(cert *x509.Certificate, idBytes []byte) error {

	needVerfyCert, err := GetCertFromByte(idBytes)
	if err != nil {
		return err
	}
	if err != nil {
		return err
	}

	if !cert.Equal(needVerfyCert) {
		return errors.New("not equl ")
	}
	return nil
}


func ReadPemFileByPath(path string) ([]byte, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf(
			"Unable to read test certificate from %q - %q "+
				"Does a unit test have an incorrect test file name?\n",
			path, err))
	}

	if strings.Contains(string(data), "-BEGIN CERTIFICATE-") {
		block, _ := pem.Decode(data)
		if block == nil {
			panic(fmt.Sprintf(
				"Failed to PEM decode test certificate from %q - "+
					"Does a unit test have a buggy test cert file?\n",
				path))
		}
		data = block.Bytes
	}
	return data,nil
}

func PemDecode(data []byte) []byte {
	block, _ := pem.Decode(data)
	if block == nil {
		panic(fmt.Sprintf(
			"Failed to PEM decode test certificate from %q - "+
				"Does a unit test have a buggy test cert file?\n"))
	}
	return block.Bytes

}