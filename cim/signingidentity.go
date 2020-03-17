package cim

import (
	"crypto/ecdsa"
	"crypto/x509"
	tcry "github.com/taiyuechain/taiyuechain/crypto"
)

type signingidentity struct {
	// we embed everything from a base identity
	identity
	// signer corresponds to the object that can produce signatures from this identity
	prv *ecdsa.PrivateKey
}

func (sig *signingidentity) Sign(msg []byte) ([]byte, error) {
	return tcry.Sign(msg, sig.prv)
}

func (sig *signingidentity) GetPublicVersion() Identity {
	return &sig.identity
}

func newSigningIdentity(cert *x509.Certificate, prvKey *ecdsa.PrivateKey) (SigningIdentity, error) {
	id, err := NewIdentity(cert)
	if err != nil {
		return nil, err
	}
	return &signingidentity{identity: *id.(*identity), prv: prvKey}, nil
}
