package p256

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"math/big"
)

type P256Signature struct {
	R, S *big.Int
	//X, Y *big.Int
}

func (p P256Signature) Reset() {
	panic("implement me")
}

func (p P256Signature) String() string {
	panic("implement me")
}

func (p P256Signature) ProtoMessage() {
	panic("implement me")
}

func SignP256(priv *ecdsa.PrivateKey, hash []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(P256Signature{r, s})
}

func VerifyP256(public *ecdsa.PublicKey, hash []byte, sign []byte) bool {
	p256sign := new(P256Signature)
	tt, err := asn1.Unmarshal(sign, p256sign)
	fmt.Println(len(tt))
	if err != nil {
		return false
	}
	return ecdsa.Verify(public, hash, p256sign.R, p256sign.S)
}

// NewSigningKey generates a random P-256 ECDSA private key.
func NewSigningKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return key, err
}

// Sign signs arbitrary data using ECDSA.
func Sign(data []byte, privkey *ecdsa.PrivateKey) ([]byte, error) {
	// hash message
	//digest := sha256.Sum256(data)

	// sign the hash
	r, s, err := ecdsa.Sign(rand.Reader, privkey, data[:])
	if err != nil {
		return nil, err
	}

	// encode the signature {R, S}
	// big.Int.Bytes() will need padding in the case of leading zero bytes
	params := privkey.Curve.Params()
	curveOrderByteSize := params.P.BitLen() / 8
	rBytes, sBytes := r.Bytes(), s.Bytes()
	signature := make([]byte, curveOrderByteSize*2)
	copy(signature[curveOrderByteSize-len(rBytes):], rBytes)
	copy(signature[curveOrderByteSize*2-len(sBytes):], sBytes)

	//privkey.PublicKey.Y

	return signature, nil
}

// Verify checks a raw ECDSA signature.
// Returns true if it's valid and false if not.
func Verify(data, signature []byte, pubkey *ecdsa.PublicKey) bool {
	// hash message
	//digest := sha256.Sum256(data)

	curveOrderByteSize := pubkey.Curve.Params().P.BitLen() / 8

	r, s := new(big.Int), new(big.Int)
	r.SetBytes(signature[:curveOrderByteSize])
	s.SetBytes(signature[curveOrderByteSize:])

	return ecdsa.Verify(pubkey, data[:], r, s)
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

/*func testCompressPublicKey() {
	fmt.Println("--------------")
	key, err := NewSigningKey()
	if err != nil {
		log.Fatal(err)
	}
	compressed := CompressPubkey(&key.PublicKey)
	uncompressed, err := DecompressPubkey(compressed)
	if err != nil {
		log.Fatal(err)
	}
	result := comparePublicKey(&key.PublicKey, uncompressed)
	if result != true {
		log.Fatal("result does not match!")
	}

}*/

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

/*func testEcRecovery() {
	fmt.Println("--------------")
	key, err := NewSigningKey()
	if err != nil {
		log.Fatal(err)
	}

	data := []byte("hello world.")
	sign, err := Sign(data, key)
	if err != nil {
		log.Fatal(err)
	}

	result := Verify(data, sign, &key.PublicKey)
	if result == false {
		log.Fatal("verify failed.")
	}

	hash := sha256.Sum256(data)

	key1, key2, _ := ecRecovery(hash[:], sign)
	if comparePublicKey(&key.PublicKey, key1) || comparePublicKey(&key.PublicKey, key2) {
		fmt.Println("match found.")
	} else {
		log.Fatal("match not found!!!")
	}
	result = Verify(data, sign, key1)
	if result == false {
		log.Fatal("key 1 verify failed.")
	}
	result = Verify(data, sign, key2)
	if result == false {
		log.Fatal("key 2 verify failed.")
	}
	fmt.Println("verify ok.")
}*/
