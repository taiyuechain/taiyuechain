package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"


	 "github.com/taiyuechain/taiyuechain/crypto/gm/sm2"
	sm2_cert "github.com/taiyuechain/taiyuechain/crypto/gm/sm2/cert"
	"crypto/x509"
	"github.com/pkg/errors"
)

func IsCorrectSY(syCrypto interface{}) bool {

	switch pub := syCrypto.(type)  {
	case *sm2.PublicKey:
		if cryptotype == CRYPTO_SM2_SM3 {
			return true
		}
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case  elliptic.P256():
			if cryptotype == CRYPTO_P256_SH3 {
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

	cert,err:=ParseCertificate(idBytes)

	if err != nil {
		return nil, errors.Wrap(err, "getCertFromPem error: failed to parse x509 cert")
	}

	return cert, nil
}

func ParseCertificate(asn1Data []byte) (*x509.Certificate, error)  {
	if asn1Data == nil {
		return nil, errors.New("getCertFromPem error: nil idBytes")
	}
	if cryptotype == CRYPTO_P256_SH3{
		return x509.ParseCertificate(asn1Data)
	}else if cryptotype == CRYPTO_SM2_SM3{
		return sm2_cert.ParseCertificate(asn1Data)
	}
	return nil, nil

}

func CheckSignatureFrom(son *x509.Certificate,parent *x509.Certificate) error   {
	if cryptotype ==CRYPTO_P256_SH3 {
		return son.CheckSignatureFrom(parent)
	}
	if cryptotype == CRYPTO_SM2_SM3 {
		return sm2_cert.CheckSignatureFrom(son,parent)
	}
	return nil
}

func CheckSignatrue(cert *x509.Certificate) error  {
	if cryptotype ==CRYPTO_P256_SH3 {
		return cert.CheckSignature(cert.SignatureAlgorithm,cert.RawTBSCertificate,cert.Signature)
	}
	if cryptotype == CRYPTO_SM2_SM3{ //sm2
		return sm2_cert.CheckSignature(cert)
	}
	return nil
}

func IsEqulCert(cert *x509.Certificate,idBytes []byte) error {

	needVerfyCert,err :=GetCertFromByte(idBytes)
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

