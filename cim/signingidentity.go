package cim

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
)

type signingidentity struct {
	// we embed everything from a base identity
	identity
	// signer corresponds to the object that can produce signatures from this identity
	signer crypto.Signer
}

func (sig *signingidentity) Sign(msg []byte) ([]byte, error) {
	return sig.signer.Sign(rand.Reader, msg, crypto.SHA3_256)
}

func (sig *signingidentity) GetPublicVersion() Identity {
	return &sig.identity
}

func newSigningIdentity(cert *x509.Certificate, pk []byte, signer crypto.Signer) (SigningIdentity, error) {
	//mspIdentityLogger.Infof("Creating signing identity instance for ID %s", id)
	mspId, err := newIdentity(cert, pk)
	if err != nil {
		return nil, err
	}
	return &signingidentity{identity: *mspId.(*identity), signer: signer}, nil
}
