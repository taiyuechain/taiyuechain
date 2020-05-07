package cim

import (
	"crypto/x509"
	"github.com/pkg/errors"
	"time"

	//"github.com/taiyuechain/taiyuechain/etai"
)

type ReIdentity struct {
	Identity *x509.Certificate `json:"identity"       gencodec:"required"`
	//Pk       Key               `json:"pk"        gencodec:"required"`
}
type identity struct {

	cert *x509.Certificate
	//pk   Key
}

func (id *identity) ExpiresAt() time.Time {
	return id.cert.NotAfter
}


func (id *identity) VerifyByte(cert []byte,cryptoType uint8) error {

	needVerfyCert,err :=GetCertFromByte(cert,cryptoType)
	if err != nil{
		return err
	}


	//verfiy cert time
	now := time.Now()
	if now.Before(needVerfyCert.NotBefore) || now.After(needVerfyCert.NotAfter) {
		return errors.New("x509: certificate has expired or is not yet valid")
	}

	if !IsCorrectSY(cryptoType,needVerfyCert.PublicKey){
		return errors.New("x509: publick key crypto Algorithm not right")
	}
	//check from

	err =needVerfyCert.CheckSignatureFrom(id.cert)
	if err != nil{
		return err
	}
	return nil
}

func (id *identity) isEqulIdentity(cert []byte,cryptoType uint8) error{

	needVerfyCert,err :=GetCertFromByte(cert,cryptoType)
	if err != nil{
		return err
	}
	if(err != nil){
		return err
	}

	if !id.cert.Equal(needVerfyCert){
		return errors.New("not equl ")
	}
	return nil
}


/*func IsCorrectSY(cryptoType uint8,syCrypto interface{}) bool {

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
}*/


func NewIdentity(cert *x509.Certificate) (Identity, error) {
	return &identity{cert: cert}, nil
}
