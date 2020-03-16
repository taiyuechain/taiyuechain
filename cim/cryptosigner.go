package cim

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"github.com/pkg/errors"
	"io"
)

type cryptoSigner struct {
	cert       *x509.Certificate
	pk         interface{}
	privateKey interface{}
}

func (s *cryptoSigner) Public() crypto.PublicKey {
	return s.pk
}

func (s *cryptoSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	keyByts, err := hex.DecodeString(s.pk.(string))
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(keyByts)
	if err != nil {
		fmt.Println("ParsePKCS8PrivateKey err", err)
		return nil, err
	}
	h := sha1.New()
	h.Write(digest)
	hash := h.Sum(nil)
	sigTag, err := rsa.SignPKCS1v15(rand, privateKey.(*rsa.PrivateKey), opts.HashFunc(), hash[:])
	if err != nil {
		fmt.Printf("Error from signing: %s\n", err)
		return nil, err
	}
	return sigTag, nil
}

func NewCryptoSigner(cert *x509.Certificate, key ecdsa.PrivateKey) (crypto.Signer, error) {
	if cert == nil {
		return nil, errors.New("key must be different from nil.")
	}
	pub := cert.PublicKey

	raw := pub.([]byte)
	pk, err := DERToPublicKey(raw)
	if err != nil {
		return nil, errors.Wrap(err, "failed marshalling der to public key")
	}

	return &cryptoSigner{cert, pk, key}, nil
}
