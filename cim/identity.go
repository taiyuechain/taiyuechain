package cim

import (
	"crypto/x509"
	"github.com/pkg/errors"
	"time"
)

type ReIdentity struct {
	Identity *x509.Certificate `json:"identity"       gencodec:"required"`
	Pk       Key               `json:"pk"        gencodec:"required"`
}
type identity struct {
	cert *x509.Certificate
	pk   Key
}

func (id *identity) ExpiresAt() time.Time {
	return id.cert.NotAfter
}

func (id *identity) Verify(msg []byte, sig []byte) error {
	// Validate arguments
	if id.pk == nil {
		return errors.New("Invalid Key. It must not be nil.")
	}
	if len(sig) == 0 {
		return errors.New("Invalid signature. Cannot be empty.")
	}
	if len(msg) == 0 {
		return errors.New("Invalid digest. Cannot be empty.")
	}

	switch id.pk.(type) {
	case *ecdsaPublicKey:
		keyVerifier := &ecdsaPublicKeyKeyVerifier{}
		_, err := keyVerifier.Verify(id.pk, sig, msg)
		return err
	case *ecdsaPrivateKey:
		keyVerifier := &ecdsaPrivateKeyVerifier{}
		_, err := keyVerifier.Verify(id.pk, sig, msg)
		return err
	case *rsaPublicKey:
		keyVerifier := &rsaPublicKeyKeyVerifier{}
		_, err := keyVerifier.Verify(id.pk, sig, msg)
		return err
	case *rsaPrivateKey:
		keyVerifier := &rsaPrivateKeyVerifier{}
		_, err := keyVerifier.Verify(id.pk, sig, msg)
		return err
	default:
		return errors.New("Certificate's public key type not recognized. Supported keys: [ECDSA, RSA]")
	}
}

func NewIdentity(cert *x509.Certificate, pk Key) (Identity, error) {
	return &identity{cert: cert, pk: pk}, nil
}
