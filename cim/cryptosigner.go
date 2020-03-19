package cim

import (
	"crypto"
	"github.com/pkg/errors"
	"github.com/taiyuechain/taiyuechain/cim/utils"
	"io"
)

type cryptoSigner struct {
	key Key
	pk  interface{}
}

func (s *cryptoSigner) Public() crypto.PublicKey {
	return s.pk
}

func (s *cryptoSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	// Validate arguments
	if s.key == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}
	if len(digest) == 0 {
		return nil, errors.New("Invalid digest. Cannot be empty.")
	}

	switch s.key.(type) {
	case *ecdsaPrivateKey:
		keySigner := &ecdsaSigner{}
		return keySigner.Sign(s.key, digest)
	case *rsaPrivateKey:
		keySigner := &rsaSigner{}
		return keySigner.Sign(s.key, digest)

	default:
		return nil, errors.New("Certificate's public key type not recognized. Supported keys: [ECDSA, RSA]")
	}
}

func NewCryptoSigner(key Key) (crypto.Signer, error) {
	pub, err := key.PublicKey()
	if err != nil {
		return nil, errors.Wrap(err, "failed getting public key")
	}
	raw, err := pub.Bytes()
	if err != nil {
		return nil, errors.Wrap(err, "failed marshalling public key")
	}
	pk, err := utils.DERToPublicKey(raw)
	if err != nil {
		return nil, errors.Wrap(err, "failed marshalling der to public key")
	}

	return &cryptoSigner{key, pk}, nil
}
