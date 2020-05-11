package cim

import (
	"crypto/x509"
	"github.com/pkg/errors"
	"time"

	//"github.com/taiyuechain/taiyuechain/tai"
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
	//check cert signatrue only root need
	/*err = CheckSignatrue(needVerfyCert,cryptoType)
	if err != nil{
		return err
	}*/




	err =CheckSignatureFrom(needVerfyCert,id.cert,cryptoType)
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

	CheckSignatrue(needVerfyCert,cryptoType)
	if err != nil{
		return err
	}

	err = isEqulCert(id.cert,cert,cryptoType)
	if err != nil{
		return err
	}
	return nil
}




func NewIdentity(cert *x509.Certificate) (Identity, error) {
	return &identity{cert: cert}, nil
}

func GetIdentityFromByte(idBytes []byte,cryptoType uint8) (Identity, error) {
	cert, err := GetCertFromByte(idBytes,cryptoType)
	if err != nil {
		return nil, err
	}

	CheckSignatrue(cert,cryptoType)
	if err != nil{
		return nil,err
	}

	identity, err := NewIdentity(cert)
	if err != nil {
		return nil, err
	}
	return identity, nil
}
