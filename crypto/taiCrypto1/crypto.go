package taiCrypto1

import (
	"crypto/ecdsa"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/crypto/ecies"

	"github.com/taiyuechain/taiyuechain/crypto/gm/sm2"
)

type TaiPrivKey interface {
	Public() []byte
	ToPubkeyByte() []byte
	Sign(digestHash []byte) ([]byte, error)
	ToHex() string
	Decrypt(m []byte) (ct []byte, err error)
	SavePrivate(file string) error
}
type TaiPubKey interface {
	Verify(hash, sig []byte) bool
	ToBytes() []byte
	ToAddress() common.Address
	ToHex() string
	Encrypt(m []byte) (ct []byte, err error)
	CompressPubkey() []byte
	PubkeyToAddress() common.Address
}
type TaiHash interface {
	Keccak256Hash(data ...[]byte)
	Keccak256(data ...[]byte)
	//Keccak512(data ...[]byte)
	CreateAddress(b common.Address, nonce uint64)
	CreateAddress2(b common.Address, salt [32]byte, inithash []byte)
}
type EcdsaPrivateKey ecdsa.PrivateKey
type EcdsaPublicKey ecdsa.PublicKey
type Sm2PrivateKey sm2.PrivateKey
type Sm2PublicKey sm2.PublicKey
type P256PrivateKey ecies.PrivateKey
type P256PublicKey ecies.PublicKey
type Sm3Hash struct {
	Ha      []byte
	H       common.Hash
	Address common.Address
}
type EcdsaHash struct {
	Ha      []byte
	H       common.Hash
	Address common.Address
}
