/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
