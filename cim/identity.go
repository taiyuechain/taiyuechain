package cim

import (
	"crypto/x509"
	"github.com/pkg/errors"
	"time"

	"github.com/taiyuechain/taiyuechain/crypto"
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

func (id *identity) VerifyByte(cert []byte) error {

	needVerfyCert, err := crypto.GetCertFromByte(cert)
	if err != nil {
		return err
	}

	//verfiy cert time
	now := time.Now()
	if now.Before(needVerfyCert.NotBefore) || now.After(needVerfyCert.NotAfter) {
		return errors.New("x509: certificate has expired or is not yet valid")
	}

	if !crypto.IsCorrectSY(needVerfyCert.PublicKey) {
		return errors.New("x509: publick key crypto Algorithm not right")
	}

	err = crypto.CheckSignatureFrom(needVerfyCert, id.cert)
	if err != nil {
		return err
	}

	return nil
}

func (id *identity) isEqulIdentity(cert []byte) error {

	needVerfyCert, err := crypto.GetCertFromByte(cert)
	if err != nil {
		return err
	}

	err = crypto.CheckSignatrue(needVerfyCert)
	if err != nil {
		return err
	}

	err = crypto.IsEqulCert(id.cert, cert)
	if err != nil {
		return err
	}
	return nil
}

func NewIdentity(cert *x509.Certificate) (Identity, error) {
	return &identity{cert: cert}, nil
}

func GetIdentityFromByte(idBytes []byte) (Identity, error) {
	cert, err := crypto.GetCertFromByte(idBytes)
	if err != nil {
		return nil, err
	}

	err = crypto.CheckSignatrue(cert)
	if err != nil {
		return nil, err
	}

	identity, err := NewIdentity(cert)
	if err != nil {
		return nil, err
	}
	return identity, nil
}
