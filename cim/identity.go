package cim

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"github.com/pkg/errors"
	"time"
)

type identity struct {
	cert *x509.Certificate
	//private key
	pk []byte
}

func DERToPublicKey(raw []byte) (pub interface{}, err error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid DER. It must be different from nil.")
	}

	key, err := x509.ParsePKIXPublicKey(raw)

	return key, err
}

func (id *identity) ExpiresAt() time.Time {
	return id.cert.NotAfter
}

func (id *identity) Verify(msg []byte, sig []byte) error {
	r, s, err := UnmarshalECDSASignature(sig)
	if err != nil {
		return fmt.Errorf("Failed unmashalling signature [%s]", err)
	}

	lowS, err := IsLowS(id.cert.PublicKey.(*ecdsa.PublicKey), s)
	if err != nil {
		return err
	}

	if !lowS {
		return fmt.Errorf("Invalid S. Must be smaller than half the order [%s][%s].", s, GetCurveHalfOrdersAt(id.cert.PublicKey.(*ecdsa.PublicKey).Curve))
	}
	bVerify := ecdsa.Verify(id.cert.PublicKey.(*ecdsa.PublicKey), msg, r, s)
	if !bVerify {
		return fmt.Errorf("verify Failure", err)
	}
	return nil
}

func newIdentity(cert *x509.Certificate, pk []byte) (Identity, error) {
	return &identity{cert: cert, pk: pk}, nil
}
