package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"

	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
	"github.com/taiyuechain/taiyuechain/cert/crypto/sm2"
	"github.com/taiyuechain/taiyuechain/crypto"
	"io/ioutil"
	"strings"
)

func IsCorrectSY(syCrypto interface{}) bool {

	switch pub := syCrypto.(type) {
	case *sm2.PublicKey:
		if crypto.CryptoType == crypto.CRYPTO_SM2_SM3_SM4 {
			return true
		}
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			if crypto.CryptoType == crypto.CRYPTO_P256_SH3_AES {
				return true
			}
		}
	case *rsa.PublicKey:
		return true
	}
	return false
}

func GetCertFromByte(idBytes []byte) (*x509.Certificate, error) {
	if idBytes == nil {
		return nil, errors.New("GetCertFromByte error: nil idBytes")
	}

	cert, err := ParseCertificate(idBytes)

	if err != nil {
		return nil, errors.Wrap(err, "GetCertFromByte error: failed to parse x509 cert")
	}

	return cert, nil
}

func ParseCertificate(asn1Data []byte) (*x509.Certificate, error) {
	if asn1Data == nil {
		return nil, errors.New("ParseCertificate error: nil idBytes")
	}

	cert, err := x509.ParseCertificate(asn1Data)
	if err != nil {
		return ParseCertificateSM2(asn1Data)

	}

	return cert, err

}

func CheckSignatureFrom(son *x509.Certificate, parent *x509.Certificate) error {

	switch son.PublicKey.(type) {
	case *sm2.PublicKey:
		return CheckSignatureFromSM2(son, parent)
	case *ecdsa.PublicKey:
	case *rsa.PublicKey:
		return son.CheckSignatureFrom(parent)
	}

	return nil
}

func CheckSignature(cert *x509.Certificate) error {

	switch cert.PublicKey.(type) {
	case *sm2.PublicKey:
		return CheckSignatureSM2(cert)
	case *ecdsa.PublicKey:
	case *rsa.PublicKey:
		return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
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
	return data, nil
}

func GetPubByteFromCert(asn1Data []byte) ([]byte, error) {
	cert, err := ParseCertificate(asn1Data)
	if err != nil {
		return nil, err
	}

	pubk := cert.PublicKey

	switch pub2 := pubk.(type) {
	case *ecdsa.PublicKey:

		return elliptic.Marshal(pub2.Curve, pub2.X, pub2.Y), nil
	case *sm2.PublicKey:
		return elliptic.Marshal(pub2.Curve, pub2.X, pub2.Y), nil
	}

	return nil, errors.New("err public curve")
}

func FromCertBytesToPubKey(asn1Data []byte) (*ecdsa.PublicKey, error) {
	//data, err := GetPubByteFromCert(asn1Data)

	cert, err := ParseCertificate(asn1Data)
	if err != nil {
		return nil, err
	}

	pubk := cert.PublicKey
	switch pub2 := pubk.(type) {
	case *ecdsa.PublicKey:

		return &ecdsa.PublicKey{Curve: pub2.Curve, X: pub2.X, Y: pub2.Y}, nil
	case *sm2.PublicKey:
		return &ecdsa.PublicKey{Curve: pub2.Curve, X: pub2.X, Y: pub2.Y}, nil
	}

	return nil, nil
}

func FromCertBytesToPubKey1(asn1Data []byte) (*ecdsa.PublicKey, error) {
	cert, err := ParseCertificate(asn1Data)
	if err != nil {
		return nil, err
	}
	pubk := cert.PublicKey
	switch pub2 := pubk.(type) {
	case *ecdsa.PublicKey:
		return pub2, nil
	case *sm2.PublicKey:
		return sm2.ToECDSAPublickey(pub2), nil
	}

	return nil, errors.New("err public curve")
}
