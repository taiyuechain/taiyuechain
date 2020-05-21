package p256

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/taiyuechain/taiyuechain/common"
	"math/big"
)

type Signature struct {
	R, S *big.Int
	//X, Y *big.Int
}

func (p Signature) Reset() {
	panic("implement me")
}

func (p Signature) String() string {
	panic("implement me")
}

func (p Signature) ProtoMessage() {
	panic("implement me")
}

func Sign(priv *ecdsa.PrivateKey, hash []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash)
	if err != nil {
		return nil, err
	}
	sign := make([]byte, 65)
	sign = append(sign, r.Bytes()...)
	sign = append(sign, s.Bytes()...)
	sign = append(sign, 1)
	return sign[65:], nil
}

func Verify(public *ecdsa.PublicKey, hash []byte, sign []byte) bool {
	return ecdsa.Verify(public, hash, new(big.Int).SetBytes(sign[:32]), new(big.Int).SetBytes(sign[32:64]))
}

// NewSigningKey generates a random P-256 ECDSA private key.
func NewSigningKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return key, err
}

// DecompressPubkey parses a public key in the 33-byte compressed format.
func DecompressPubkey(pubkey []byte) (*ecdsa.PublicKey, error) {
	x, y := new(big.Int), new(big.Int)
	if len(pubkey) != 33 {
		return nil, fmt.Errorf("invalid public key")
	}
	if (pubkey[0] != 0x02) && (pubkey[0] != 0x03) {
		return nil, fmt.Errorf("invalid public key")
	}
	if x == nil {
		return nil, fmt.Errorf("invalid public key")
	}
	x.SetBytes(pubkey[1:])

	xxx := new(big.Int).Mul(x, x)
	xxx.Mul(xxx, x)

	ax := new(big.Int).Mul(big.NewInt(3), x)

	yy := new(big.Int).Sub(xxx, ax)
	yy.Add(yy, elliptic.P256().Params().B)

	y1 := new(big.Int).ModSqrt(yy, elliptic.P256().Params().P)
	if y1 == nil {
		return nil, fmt.Errorf("can not revcovery public key")
	}

	y2 := new(big.Int).Neg(y1)
	y2.Mod(y2, elliptic.P256().Params().P)

	if pubkey[0] == 0x02 {
		if y1.Bit(0) == 0 {
			y = y1
		} else {
			y = y2
		}
	} else {
		if y1.Bit(0) == 1 {
			y = y1
		} else {
			y = y2
		}
	}
	//fmt.Println("dx:",x)
	//fmt.Println("dy:",y)
	return &ecdsa.PublicKey{X: x, Y: y, Curve: elliptic.P256()}, nil
}

// CompressPubkey encodes a public key to the 33-byte compressed format.
func CompressPubkey(pubkey *ecdsa.PublicKey) []byte {
	//fmt.Println("cx:",pubkey.X)
	//fmt.Println("cy:",pubkey.Y)
	// big.Int.Bytes() will need padding in the case of leading zero bytes
	params := pubkey.Curve.Params()
	curveOrderByteSize := params.P.BitLen() / 8
	xBytes := pubkey.X.Bytes()
	signature := make([]byte, curveOrderByteSize+1)
	if pubkey.Y.Bit(0) == 1 {
		signature[0] = 0x03
	} else {
		signature[0] = 0x02
	}
	copy(signature[1+curveOrderByteSize-len(xBytes):], xBytes)
	return signature
}

//func ECRecovery(data []byte, rawSign []byte) (*ecdsa.PublicKey, *ecdsa.PublicKey, error) {
func ECRecovery(data []byte, rawSign []byte) (*ecdsa.PublicKey, error) {
	r := big.Int{}
	s := big.Int{}
	sigLen := len(rawSign)
	r.SetBytes(rawSign[:(sigLen / 2)])
	s.SetBytes(rawSign[(sigLen / 2):])

	expy := new(big.Int).Sub(elliptic.P256().Params().N, big.NewInt(2))
	rinv := new(big.Int).Exp(&r, expy, elliptic.P256().Params().N)
	z := new(big.Int).SetBytes(data)

	xxx := new(big.Int).Mul(&r, &r)
	xxx.Mul(xxx, &r)

	ax := new(big.Int).Mul(big.NewInt(3), &r)

	yy := new(big.Int).Sub(xxx, ax)
	yy.Add(yy, elliptic.P256().Params().B)

	//y_squard := new(big.Int).Mod(tmp4,elliptic.P256().Params().P)

	y1 := new(big.Int).ModSqrt(yy, elliptic.P256().Params().P)
	if y1 == nil {
		return nil, fmt.Errorf("can not revcovery public key")
	}

	y2 := new(big.Int).Neg(y1)
	y2.Mod(y2, elliptic.P256().Params().P)
	//p1, p2 := elliptic.P256().ScalarMult(&r, y1, s.Bytes())
	//p3, p4 := elliptic.P256().ScalarBaseMult(z.Bytes())

	//p5 := new(big.Int).Neg(p4)
	//p5.Mod(p5, elliptic.P256().Params().P)

	//q1, q2 := elliptic.P256().Add(p1, p2, p3, p5)
	//q3, q4 := elliptic.P256().ScalarMult(q1, q2, rinv.Bytes())

	n1, n2 := elliptic.P256().ScalarMult(&r, y2, s.Bytes())
	n3, n4 := elliptic.P256().ScalarBaseMult(z.Bytes())

	n5 := new(big.Int).Neg(n4)
	n5.Mod(n5, elliptic.P256().Params().P)

	q5, q6 := elliptic.P256().Add(n1, n2, n3, n5)
	q7, q8 := elliptic.P256().ScalarMult(q5, q6, rinv.Bytes())

	//key1 := ecdsa.PublicKey{Curve: elliptic.P256(), X: q3, Y: q4}
	key2 := ecdsa.PublicKey{Curve: elliptic.P256(), X: q7, Y: q8}
	return &key2, nil

}

func comparePublicKey(key1, key2 *ecdsa.PublicKey) bool {
	x := key1.X.Cmp(key2.X)
	y := key2.Y.Cmp(key2.Y)
	if x == 0 && y == 0 {
		return true
	} else {
		return false
	}
}
func ValidateSignatureValues(v byte, r, s *big.Int, homestead bool) bool {

	if r.Cmp(common.Big1) < 0 || s.Cmp(common.Big1) < 0 {
		return false
	}
	// reject upper range of s values (ECDSA malleability)
	// see discussion in secp256k1/libsecp256k1/include/secp256k1.h
	if homestead && s.Cmp(elliptic.P256().Params().N) > 0 {
		return false
	}
	// Frontier: allow s to be in full N range
	return r.Cmp(elliptic.P256().Params().N) < 0 && s.Cmp(elliptic.P256().Params().N) < 0 && (v == 0 || v == 1)
}
