// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// +build !nacl,!js,cgo

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/taiyuechain/taiyuechain/common/math"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm2"
	"github.com/taiyuechain/taiyuechain/crypto/p256"
	"github.com/taiyuechain/taiyuechain/crypto/secp256k1"
	"github.com/taiyuechain/taiyuechain/log"
	"math/big"
)

// Ecrecover returns the uncompressed public key that created the given signature.
/*func Ecrecover(hash, sig []byte) ([]byte, error) {
	return secp256k1.RecoverPubkey(hash, sig)
}*/
func Ecrecover(hash, sig []byte) ([]byte, error) {
	if len(sig) != SignatureLength {
		log.Info("sig length", "is", len(sig))
		return nil, errors.New("sig length is err")
	}
	if CryptoType == CRYPTO_P256_SH3_AES {
		//p256pub,err:=p256.ECRecovery(hash, sig)nil
		p256pub, err := DecompressPubkey(sig[65:])
		if err != nil {
			return nil, err
		}
		return FromECDSAPub(p256pub), nil
	}
	//guomi
	if CryptoType == CRYPTO_SM2_SM3_SM4 {
		ee := new(big.Int).SetBytes(sig[65:])
		smpub, err := sm2.SigToPub(hash, sig[:65], nil, ee)
		if err != nil {
			return nil, err
		}
		return FromECDSAPub(smpub), nil
	}
	//guoji S256
	if CryptoType == CRYPTO_S256_SH3_AES {
		return secp256k1.RecoverPubkey(hash, sig[:65])
	}
	return nil, nil
}

// SigToPub returns the public key that created the given signature.
func SigToPub(hash, sig []byte) (*ecdsa.PublicKey, error) {
	if len(sig) != SignatureLength || len(hash) != 32 {
		return nil, errors.New("SigToPub sign length is wrong ")
	}
	if CryptoType == CRYPTO_P256_SH3_AES {
		//p256pub,err:=p256.ECRecovery(hash, sig)nil
		p256pub, err := DecompressPubkey(sig[65:])
		if err != nil {
			return nil, err
		}
		return p256pub, nil
	}
	//guomi
	if CryptoType == CRYPTO_SM2_SM3_SM4 {
		// smpub, err := DecompressPubkey(sig[65:])
		ee := new(big.Int).SetBytes(sig[65:])
		smpub, err := sm2.SigToPub(hash, sig[:65], nil, ee)
		if err != nil {
			return nil, err
		}
		return smpub, nil
	}
	//guoji S256
	if CryptoType == CRYPTO_S256_SH3_AES {
		s, err := Ecrecover(hash, sig)
		if err != nil {
			return nil, err
		}

		x, y := elliptic.Unmarshal(S256(), s)
		return &ecdsa.PublicKey{Curve: S256(), X: x, Y: y}, nil
	}
	return nil, nil
}

// Sign calculates an ECDSA signature.
//
// This function is susceptible to chosen plaintext attacks that can leak
// information about the private key that is used for signing. Callers must
// be aware that the given digest cannot be chosen by an adversery. Common
// solution is to hash any input before calculating the signature.
//
// The produced signature is in the [R || S || V] format where V is 0 or 1.
func Sign(digestHash []byte, prv *ecdsa.PrivateKey) (sig []byte, err error) {
	if len(digestHash) != 32 {
		return nil, errors.New("sign digestHash is wrong")
	}
	if prv == nil {
		return nil, errors.New("invalid private key")
	}
	if CryptoType == CRYPTO_P256_SH3_AES {
		p256sign, err := p256.Sign(prv, digestHash)
		if err != nil {
			return nil, err
		}
		if len(p256sign) != 65 {
			return nil, errors.New("sig length is wrong !!!" + string(len(p256sign)))
		}
		pubtype := CompressPubkey(&prv.PublicKey)
		p256sign = append(p256sign, pubtype...)
		return p256sign, nil
	}
	//guomi
	if CryptoType == CRYPTO_SM2_SM3_SM4 {

		smsign, e, err := sm2.Sign(sm2.ToSm2privatekey(prv), nil, digestHash)
		if err != nil {
			return nil, err
		}
		if len(smsign) != 65 {
			log.Warn("Sign", "digestHash", hex.EncodeToString(digestHash), "priv", hex.EncodeToString(FromECDSA(prv)), " smsign", len(smsign))
			return nil, errors.New("sig length is wrong !!!  " + string(len(smsign)))
		}
		var pad [32]byte
		buf := e.Bytes()
		copy(pad[32-len(buf):], buf)
		smsign = append(smsign, pad[:]...)
		return smsign, nil
	}
	//guoji S256
	if CryptoType == CRYPTO_S256_SH3_AES {
		if len(digestHash) != DigestLength {
			return nil, fmt.Errorf("hash is required to be exactly %d bytes (%d)", DigestLength, len(digestHash))
		}
		seckey := math.PaddedBigBytes(prv.D, prv.Params().BitSize/8)
		defer zeroBytes(seckey)
		smsign, err := secp256k1.Sign(digestHash, seckey)
		if err != nil {
			return nil, err
		}

		var pad [32]byte
		smsign = append(smsign, pad[:]...)
		return smsign, nil
	}
	return nil, nil
}

// VerifySignature checks that the given public key created signature over digest.
// The public key should be in compressed (33 bytes) or uncompressed (65 bytes) format.
// The signature should have the 64 byte [R || S] format.
func VerifySignature(pubkey, digestHash, signature []byte) bool {
	if len(signature) != SignatureLength || len(digestHash) != 32 {
		return false
	}
	if CryptoType == CRYPTO_P256_SH3_AES {
		if len(pubkey) == 33 {
			p256pub, err := DecompressPubkey(pubkey)
			if err != nil {
				return false
			}
			return p256.Verify(p256pub, digestHash, signature)
		}

		p256pub, err := UnmarshalPubkey(pubkey)
		if err != nil {
			return false
		}
		return p256.Verify(p256pub, digestHash, signature)
	}
	//guomi
	if CryptoType == CRYPTO_SM2_SM3_SM4 {
		if len(pubkey) == 33 {
			smpub, err := DecompressPubkey(pubkey)
			if err != nil {
				return false
			}
			return sm2.Verify(sm2.ToSm2Publickey(smpub), nil, digestHash, signature)
		}
		smpub, err := UnmarshalPubkey(pubkey)
		if err != nil {
			return false
		}

		return sm2.Verify(sm2.ToSm2Publickey(smpub), nil, digestHash, signature)
	}
	//guoji S256
	if CryptoType == CRYPTO_S256_SH3_AES {
		return secp256k1.VerifySignature(pubkey, digestHash, signature[:64])
	}
	return false
}

func getPubFromBytes(pk []byte) (*ecdsa.PublicKey, error) {
	if len(pk) == 33 {
		smpub, err := DecompressPubkey(pk)
		if err != nil {
			return nil, err
		}
		return smpub, nil
	}
	if len(pk) != 65 {
		return nil, errors.New("len not equal 65")
	}
	p256pub, err := UnmarshalPubkey(pk)
	if err != nil {
		return nil, err
	}
	return p256pub, nil
}

// DecompressPubkey parses a public key in the 33-byte compressed format.
func DecompressPubkey(pubkey []byte) (*ecdsa.PublicKey, error) {
	if len(pubkey) != 33 {
		return nil, errors.New("DecompressPubkey length is wrong !" + string(len(pubkey)))
	}
	if CryptoType == CRYPTO_P256_SH3_AES {
		p256pub, err := p256.DecompressPubkey(pubkey)
		if err != nil {
			return nil, err
		}
		return p256pub, nil
	}
	//guomi
	if CryptoType == CRYPTO_SM2_SM3_SM4 {
		return sm2.ToECDSAPublickey(sm2.Decompress(pubkey)), nil

	}
	//guoji S256
	if CryptoType == CRYPTO_S256_SH3_AES {
		x, y := secp256k1.DecompressPubkey(pubkey)
		if x == nil {
			return nil, fmt.Errorf("invalid public key")
		}
		return &ecdsa.PublicKey{X: x, Y: y, Curve: S256()}, nil
	}
	return nil, nil

}

// CompressPubkey encodes a public key to the 33-byte compressed format.
func CompressPubkey(pubkey *ecdsa.PublicKey) []byte {
	if pubkey == nil {
		return nil
	}
	if CryptoType == CRYPTO_P256_SH3_AES {
		return p256.CompressPubkey(pubkey)
	}
	//guomi
	if CryptoType == CRYPTO_SM2_SM3_SM4 {
		return sm2.Compress(sm2.ToSm2Publickey(pubkey))

	}
	//guoji S256
	if CryptoType == CRYPTO_S256_SH3_AES {
		return secp256k1.CompressPubkey(pubkey.X, pubkey.Y)
	}
	return nil
}

// S256 returns an instance of the secp256k1 curve.
func S256() elliptic.Curve {
	return secp256k1.S256()
}
