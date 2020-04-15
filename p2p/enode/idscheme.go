// Copyright 2018 The go-ethereum Authors
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

package enode

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm2"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm3"
	"github.com/taiyuechain/taiyuechain/crypto/p256"
	"math/big"
	//"crypto/ecdsa"
	//"crypto/ecdsa"
	"fmt"
	"github.com/taiyuechain/taiyuechain/crypto/taiCrypto"
	"io"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/taiyuechain/taiyuechain/p2p/enr"
	"golang.org/x/crypto/sha3"

)

// List of known secure identity schemes.
var ValidSchemes = enr.SchemeMap{
	"v4": V4ID{},
}

var ValidSchemesForTesting = enr.SchemeMap{
	"v4":   V4ID{},
	"null": NullID{},
}

// v4ID is the "v4" identity scheme.
type V4ID struct{}
type EcdsaSecp256k1 ecdsa.PublicKey

func (e EcdsaSecp256k1) ENRKey() string {
	return "ecdsasecp256k1"
}
func (e EcdsaSecp256k1) EncodeRLP(w io.Writer) error {
	//return rlp.Encode(w, crypto.CompressPubkey((*ecdsa.PublicKey)(&v)))
	var taipublic taiCrypto.TaiPublicKey
	taipublic.Publickey = ecdsa.PublicKey(e)
	return rlp.Encode(w, taipublic.CompressPubkey(taipublic))
}

// DecodeRLP implements rlp.Decoder.
func (e *EcdsaSecp256k1) DecodeRLP(s *rlp.Stream) error {
	var taipublic taiCrypto.TaiPublicKey
	buf, err := s.Bytes()
	if err != nil {
		return err
	}
	//pk, err := crypto.DecompressPubkey(buf)
	pk, err := taipublic.DecompressPubkey(buf)
	if err != nil {
		return err
	}
	*e = (EcdsaSecp256k1)(pk.Publickey)
	return nil
}

type Sm2Secp256k1 sm2.PublicKey

func (s Sm2Secp256k1) ENRKey() string {
	return "secp256k1"
}
func (s Sm2Secp256k1) EncodeRLP(w io.Writer) error {
	//return rlp.Encode(w, crypto.CompressPubkey((*ecdsa.PublicKey)(&v)))
	var taipublic taiCrypto.TaiPublicKey
	taipublic.SmPublickey = sm2.PublicKey(s)
	return rlp.Encode(w, taipublic.CompressPubkey(taipublic))
}

// DecodeRLP implements rlp.Decoder.
func (s Sm2Secp256k1) DecodeRLP(r *rlp.Stream) error {
	var taipublic taiCrypto.TaiPublicKey
	buf, err := r.Bytes()
	if err != nil {
		return err
	}
	//pk, err := crypto.DecompressPubkey(buf)
	pk, err := taipublic.DecompressPubkey(buf)
	if err != nil {
		return err
	}
	s = (Sm2Secp256k1)(pk.SmPublickey)
	return nil
}

// SignV4 signs a record using the v4 scheme.
//func SignV4(r *enr.Record, privkey *ecdsa.PrivateKey) error {
func SignV4(r *enr.Record, privkey *taiCrypto.TaiPrivateKey) error {
	// Copy r to avoid modifying it if signing fails.
	var taiprivate taiCrypto.TaiPrivateKey

	if taiCrypto.AsymmetricCryptoType == taiCrypto.ASYMMETRICCRYPTOECDSA {
		cpy := *r
		cpy.Set(enr.ID("v4"))
		cpy.Set(EcdsaSecp256k1(privkey.Private.PublicKey))
		h := sha3.NewLegacyKeccak256()
		rlp.Encode(h, cpy.AppendElements(nil))
		hash := h.Sum(nil)

		/*	r1,s1,_:=ecdsa.Sign(rand.Reader,&privkey.Private,hash)
				err1:=ecdsa.Verify(&privkey.Private.PublicKey,hash,r1,s1)
		         fmt.Println(err1)*/
		sig, err := p256.SignP256(rand.Reader, &privkey.Private, hash)
		//err1 := p256.VerifyP256(privkey.Private.PublicKey, hash, sign1)

		//sig, err := crypto.Sign(h.Sum(nil), privkey.Private)
		//sig, err := taiprivate.Sign(h.Sum(nil), *privkey)
		/*	taipublic.Publickey = privkey.Private.PublicKey
			taipublic.HexBytesPublic = taipublic.CompressPubkey(taipublic)*/
		/*	sig = sig[:len(sig)-1]
			t := taipublic.VerifySignature(h.Sum(nil), sig)
			fmt.Println(t)*/
		/*	if err != nil {
			return err
		}*/
		//sig = sig[:len(sig)-1] // remove v
		if err = cpy.SetSig(V4ID{}, sig); err == nil {
			*r = cpy
		}
		return err
	}
	if taiCrypto.AsymmetricCryptoType == taiCrypto.ASYMMETRICCRYPTOSM2 {
		cpy := *r
		cpy.Set(enr.ID("v4"))
		//cpy.Set(Secp256k1(privkey.TaiPubKey))
		cpy.Set(Sm2Secp256k1(privkey.GmPrivate.PublicKey))

		h := sm3.New()
		rlp.Encode(h, cpy.AppendElements(nil))
		sig, err := taiprivate.Sign(h.Sum(nil), *privkey)
		if err != nil {
			return err
		}
		sig = sig[:len(sig)-1] // remove v
		if err = cpy.SetSig(V4ID{}, sig); err == nil {
			*r = cpy
		}
		return err
	}
	return nil
}

func (V4ID) Verify(r *enr.Record, sig []byte) error {
	var taipublic taiCrypto.TaiPublicKey
	var entry s256raw
	if err := r.Load(&entry); err != nil {
		return err
	} else if len(entry) != 65 {
		return fmt.Errorf("invalid public key")
	}

	h := sha3.NewLegacyKeccak256()
	rlp.Encode(h, r.AppendElements(nil))
	//if !crypto.VerifySignature(entry, h.Sum(nil), sig) {
	//if !taiprivate.VerifySignature(entry, h.Sum(nil), sig) {}
	//taipublic.HexBytesPublic = entry
	//if !taipublic.VerifySignature(h.Sum(nil), sig[:len(sig)-1]) {
	//	return enr.ErrInvalidSig
	//}
	publickey, err := taipublic.DecompressPubkey(entry)
	//publickey.Publickey.Y = y2(publickey.Publickey.Params(), publickey.Publickey.X)
	//publickey.Publickey.Y=elliptic.S256Y(publickey.Publickey.Params(), publickey.Publickey.X)
	if err != nil {
		return err
	}
	if !p256.VerifyP256(publickey.Publickey, h.Sum(nil), sig) {
		return enr.ErrInvalidSig
	}
	return nil
}
func y2(curve *elliptic.CurveParams, x *big.Int) *big.Int {

	/*	y2 := new(big.Int).Mul(y, y)
		y2.Mod(y2, curve.P)*/

	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	threeX := new(big.Int).Lsh(x, 1)
	threeX.Add(threeX, x)
	x3.Sub(x3, threeX)
	x3.Add(x3, curve.B)
	/*	y.Div(x3,curve.P)
		x3.Mod(x3,curve.P)
		y.Mul(y,curve.P)
		y.Add(y,x3)*/
	x3.Sqrt(x3)
	return x3
}
func sqrt(s string) *big.Int {
	var n, a, b, m, m2 big.Int

	n.SetString(s, 10)

	a.SetInt64(int64(1))
	b.Set(&n)

	for {
		m.Add(&a, &b).Div(&m, big.NewInt(2))

		if m.Cmp(&a) == 0 || m.Cmp(&b) == 0 {
			break
		}

		m2.Mul(&m, &m)
		if m2.Cmp(&n) > 0 {
			b.Set(&m)
		} else {
			a.Set(&m)
		}
	}

	return &m
}

func (V4ID) NodeAddr(r *enr.Record) []byte {
	var pubkey EcdsaSecp256k1
	var thash taiCrypto.THash
	if taiCrypto.AsymmetricCryptoType == taiCrypto.ASYMMETRICCRYPTOECDSA {
		err := r.Load(&pubkey)
		if err != nil {
			return nil
		}
		buf := make([]byte, 64)
		math.ReadBits(pubkey.X, buf[:32])
		math.ReadBits(pubkey.Y, buf[32:])
		return thash.Keccak256(buf)
	}
	if taiCrypto.AsymmetricCryptoType == taiCrypto.ASYMMETRICCRYPTOSM2 {
		err := r.Load(&pubkey)
		if err != nil {
			return nil
		}
		buf := make([]byte, 64)
		math.ReadBits(pubkey.X, buf[:32])
		math.ReadBits(pubkey.Y, buf[32:])
		return thash.Keccak256(buf)
	}
	return nil
}

// Secp256k1 is the "secp256k1" key, which holds a public key.
//type Secp256k1 ecdsa.PublicKey
type Secp256k1 taiCrypto.TaiPublicKey

func (v Secp256k1) ENRKey() string { return "secp256k1" }

// EncodeRLP implements rlp.Encoder.
func (v Secp256k1) EncodeRLP(w io.Writer) error {
	//return rlp.Encode(w, crypto.CompressPubkey((*ecdsa.PublicKey)(&v)))
	var taipublic taiCrypto.TaiPublicKey
	return rlp.Encode(w, taipublic.CompressPubkey(taiCrypto.TaiPublicKey((v))))
}

// DecodeRLP implements rlp.Decoder.
func (v *Secp256k1) DecodeRLP(s *rlp.Stream) error {
	var taipublic taiCrypto.TaiPublicKey
	buf, err := s.Bytes()
	if err != nil {
		return err
	}
	//pk, err := crypto.DecompressPubkey(buf)
	pk, err := taipublic.DecompressPubkey(buf)
	if err != nil {
		return err
	}
	*v = (Secp256k1)(*pk)
	return nil
}

// s256raw is an unparsed secp256k1 public key entry.
type s256raw []byte

func (s256raw) ENRKey() string { return "ecdsasecp256k1" }

// v4CompatID is a weaker and insecure version of the "v4" scheme which only checks for the
// presence of a secp256k1 public key, but doesn't verify the signature.
type v4CompatID struct {
	V4ID
}

func (v4CompatID) Verify(r *enr.Record, sig []byte) error {
	var pubkey EcdsaSecp256k1
	return r.Load(&pubkey)
}

//func signV4Compat(r *enr.Record, pubkey *ecdsa.PublicKey) {
func signV4Compat(r *enr.Record, pubkey *taiCrypto.TaiPublicKey) {

	r.Set((*EcdsaSecp256k1)(&pubkey.Publickey))
	if err := r.SetSig(v4CompatID{}, []byte{}); err != nil {
		panic(err)
	}
}

// NullID is the "null" ENR identity scheme. This scheme stores the node
// ID in the record without any signature.
type NullID struct{}

func (NullID) Verify(r *enr.Record, sig []byte) error {
	return nil
}

func (NullID) NodeAddr(r *enr.Record) []byte {
	var id ID
	r.Load(enr.WithEntry("nulladdr", &id))
	return id[:]
}

func SignNull(r *enr.Record, id ID) *Node {
	r.Set(enr.ID("null"))
	r.Set(enr.WithEntry("nulladdr", id))
	if err := r.SetSig(NullID{}, []byte{}); err != nil {
		panic(err)
	}
	return &Node{r: *r, id: id}
}
