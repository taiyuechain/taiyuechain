package taiCrypto1

import (
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/common"
	"github.com/taiyuechain/taiyuechain/crypto/ecies"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm2"
)

type TaiPrivKey interface {
	Public() []byte
	Sign(digestHash []byte) ([]byte, error)
	ToHex() string
	Decrypt(m []byte) (ct []byte, err error)
}
type TaiPubKey interface {
	Verify(hash, sig []byte) bool
	ToBytes() []byte
	ToAddress() common.Address
	ToHex() string
	Encrypt(m []byte) (ct []byte, err error)
}
type EcdsaPrivateKey ecdsa.PrivateKey
type EcdsaPublicKey ecdsa.PublicKey
type Sm2PrivateKey sm2.PrivateKey
type Sm2PublicKey sm2.PublicKey
type P256PrivateKey ecies.PrivateKey
type P256PublicKey ecies.PublicKey
