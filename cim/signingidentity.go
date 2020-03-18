package cim

import (
	"crypto"
	"crypto/x509"
	tcry "github.com/taiyuechain/taiyuechain/crypto"
)

type signingidentity struct {
	// we embed everything from a base identity
	identity
	// signer corresponds to the object that can produce signatures from this identity
	signer crypto.Signer
}

func (sig *signingidentity) Sign(msg []byte) ([]byte, error) {
	return tcry.Sign(msg, nil)
}

func (sig *signingidentity) GetPublicVersion() Identity {
	return &sig.identity
}

func newSigningIdentity(cert *x509.Certificate, key Key, signer crypto.Signer) (SigningIdentity, error) {
	id, err := NewIdentity(cert, key)
	if err != nil {
		return nil, err
	}
	return &signingidentity{identity: *id.(*identity), signer: signer}, nil
}
