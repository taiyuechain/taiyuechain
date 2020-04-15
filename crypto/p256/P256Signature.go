package p256

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"io"
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

func SignP256(reader io.Reader, priv *ecdsa.PrivateKey, hash []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash)
	/*	sign:=make([]byte,65)
		fmt.Println(r.Bytes())
		fmt.Println(s.Bytes())*/
	if err != nil {
		return nil, err
	}
	//fmt.Println(asn1.Marshal(P256Signature{r, s}))
	/*	copy(sign[:31],r.Bytes())
		copy(sign[32:63],s.Bytes())
		x := int32(4)
		bytesBuffer := bytes.NewBuffer([]byte{})
		binary.Write(bytesBuffer, binary.BigEndian, x)
		copy(sign[64:],bytesBuffer.Bytes())*/
	return asn1.Marshal(P256Signature{r, s})
}

func VerifyP256(public ecdsa.PublicKey, hash []byte, sign []byte) bool {
	p256sign := new(P256Signature)
	tt, err := asn1.Unmarshal(sign, p256sign)
	fmt.Println(len(tt))
	if err != nil {
		return false
	}
	return ecdsa.Verify(&public, hash, p256sign.R, p256sign.S)
}
