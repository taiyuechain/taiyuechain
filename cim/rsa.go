package cim

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

type rsaSigner struct{}

func (s *rsaSigner) Sign(k Key, digest []byte) (signature []byte, err error) {
	return k.(*rsaPrivateKey).privKey.Sign(rand.Reader, digest, crypto.SHA3_256)
}

type rsaPrivateKeyVerifier struct{}

func (v *rsaPrivateKeyVerifier) Verify(k Key, signature, digest []byte) (valid bool, err error) {
	opts := &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA3_256}

	errVerify := rsa.VerifyPSS(&(k.(*rsaPrivateKey).privKey.PublicKey),
		opts.Hash,
		digest, signature, opts)

	return errVerify == nil, errVerify
}

type rsaPublicKeyKeyVerifier struct{}

func (v *rsaPublicKeyKeyVerifier) Verify(k Key, signature, digest []byte) (valid bool, err error) {
	opts := &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA3_256}
	errVerify := rsa.VerifyPSS(k.(*rsaPublicKey).pubKey,
		opts.Hash,
		digest, signature, opts)
	return errVerify == nil, errVerify
}
