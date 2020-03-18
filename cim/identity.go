package cim

import (
	"crypto/x509"
	"fmt"
	"github.com/taiyuechain/taiyuechain/crypto"
	"time"
)

type identity struct {
	cert *x509.Certificate
	pk   Key
}

func (id *identity) ExpiresAt() time.Time {
	return id.cert.NotAfter
}

func (id *identity) Verify(msg []byte, sig []byte) error {
	raw, err := x509.MarshalPKIXPublicKey(id.cert.PublicKey)
	if err != nil {
		return fmt.Errorf("Failed marshalling key [%s]", err)
	}
	isVerify := crypto.VerifySignature(raw, msg, sig)
	if !isVerify {
		return fmt.Errorf("verify failure")
	}
	return nil
}

func NewIdentity(cert *x509.Certificate, pk Key) (Identity, error) {
	return &identity{cert: cert, pk: pk}, nil
}
