package cim

import (
	"crypto/ecdsa"
	"crypto/elliptic"


	 "github.com/taiyuechain/taiyuechain/crypto/gm/sm2"
	sm2_cert "github.com/taiyuechain/taiyuechain/crypto/gm/sm2/cert"
	"crypto/x509"
	"github.com/pkg/errors"
)

func IsCorrectSY(cryptoType uint8,syCrypto interface{}) bool {

	switch pub := syCrypto.(type)  {
	case *sm2.PublicKey:
		if cryptoType == 2 {
			return true
		}
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case  elliptic.P256():
			if cryptoType == 1 {
				return true
			}
		}
	}
	return false
}

func GetCertFromByte(idBytes []byte,cryptoType uint8) (*x509.Certificate, error) {
	if idBytes == nil {
		return nil, errors.New("getCertFromPem error: nil idBytes")
	}

	cert,err:=ParseCertificate(idBytes,cryptoType)

	if err != nil {
		return nil, errors.Wrap(err, "getCertFromPem error: failed to parse x509 cert")
	}

	return cert, nil
}

func ParseCertificate(asn1Data []byte,cryptoType uint8) (*x509.Certificate, error)  {
	if asn1Data == nil {
		return nil, errors.New("getCertFromPem error: nil idBytes")
	}
	if cryptoType == 1{
		return x509.ParseCertificate(asn1Data)
	}else if cryptoType == 2{
		return sm2_cert.ParseCertificate(asn1Data)
	}
	return nil, nil

}

func CheckSignatureFrom(son *x509.Certificate,parent *x509.Certificate,cryptoType uint8) error   {
	if cryptoType ==1 {
		return son.CheckSignatureFrom(parent)
	}
	if cryptoType == 2 {
		return sm2_cert.CheckSignatureFrom(son,parent)
	}
	return nil
}

func CheckSignatrue(cert *x509.Certificate,cryptoType uint8) error  {
	if cryptoType ==1 {
		return cert.CheckSignature(cert.SignatureAlgorithm,cert.RawTBSCertificate,cert.Signature)
	}
	if cryptoType == 2{ //sm2
		return sm2_cert.CheckSignature(cert)
	}
	return nil
}

func isEqulCert(cert *x509.Certificate,idBytes []byte,cryptoType uint8) error {

	needVerfyCert,err :=GetCertFromByte(idBytes,cryptoType)
	if err != nil{
		return err
	}
	if(err != nil){
		return err
	}

	if !cert.Equal(needVerfyCert){
		return errors.New("not equl ")
	}
	return nil
}

