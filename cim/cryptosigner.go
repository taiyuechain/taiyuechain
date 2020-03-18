package cim

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"fmt"
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
