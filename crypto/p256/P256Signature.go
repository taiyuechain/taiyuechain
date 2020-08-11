package p256

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/taiyuechain/taiyuechain/common"
	"math/big"
)

// p256 Sign with privatekey
func Sign(priv *ecdsa.PrivateKey, hash []byte) ([]byte, error) {
	signrmark := 1
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash)
	if err != nil {
		return nil, err
	}
	sign := make([]byte, 65)
	sign = BytesCombine(r.Bytes())
	sign = BytesCombine(sign, s.Bytes())
	if len(r.Bytes()) < 32 {
		for i := 0; i < 32-len(r.Bytes()); i++ {
			sign = append(sign, (byte)(len(r.Bytes())))
			signrmark = signrmark * 3
		}
		if len(s.Bytes()) < 32 {
			signsmark := 1
			for i := 0; i < 32-len(r.Bytes()); i++ {
				sign = append(sign, (byte)(len(s.Bytes())))
				signsmark = signsmark * 7
				signrmark = signrmark + signsmark
			}
			goto SIGN
		}

	}
	if len(s.Bytes()) < 32 {
		for i := 0; i < 32-len(s.Bytes()); i++ {
			sign = append(sign, (byte)(len(s.Bytes())))
			signrmark = signrmark * 7
		}
	}
SIGN:
	if signrmark == 1 {
		sign = append(sign, 1)
	}
	if signrmark != 1 {
		sign = append(sign, (byte)(signrmark))

	}
	return sign, nil
}
func BytesCombine(pBytes ...[]byte) []byte {
	return bytes.Join(pBytes, []byte(""))
}

// p256 Verify with publickey
func Verify(public *ecdsa.PublicKey, hash []byte, sign []byte) bool {
	if sign[64] != 1 {
		if (int)(sign[64])%3 == 0 {
			return ecdsa.Verify(public, hash, new(big.Int).SetBytes(sign[:32-(int)(sign[64])/3]), new(big.Int).SetBytes(sign[32-(int)(sign[64])/3:64-(int)(sign[64])/3]))
		}
		if (int)(sign[64])%7 == 0 {
			return ecdsa.Verify(public, hash, new(big.Int).SetBytes(sign[:32]), new(big.Int).SetBytes(sign[32:64-(int)(sign[64])/7]))
		}
		rlen := ((int)(sign[64]) - (32-(int)(sign[63]))*7) / 3

		return ecdsa.Verify(public, hash, new(big.Int).SetBytes(sign[:rlen]), new(big.Int).SetBytes(sign[rlen:(rlen+(int)(sign[63]))]))
	}
	return ecdsa.Verify(public, hash, new(big.Int).SetBytes(sign[:32]), new(big.Int).SetBytes(sign[32:64]))
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

// According hash and sign to rccovery publickey
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

// Validate v,r and s is true
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
