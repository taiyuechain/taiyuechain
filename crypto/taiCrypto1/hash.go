package taiCrypto1

import (
	"github.com/taiyuechain/taiyuechain/common"
	tycrpto "github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm3"
)

/*sm3 hash*/
func (smh *Sm3Hash) Keccak256Hash(data ...[]byte) {
	smh.H = sm3.Keccak256Hash(data...)
}
func (smh *Sm3Hash) Keccak256(data ...[]byte) {
	smh.Ha = sm3.Keccak256(data...)
}
func (smh *Sm3Hash) CreateAddress(b common.Address, nonce uint64) {
	smh.Address = sm3.CreateAddress(b, nonce)
}
func (smh *Sm3Hash) CreateAddress2(b common.Address, salt [32]byte, inithash []byte) {
	smh.Address = sm3.CreateAddress2(b, salt, inithash)
}

/*
ecdsa hash
*/
func (ecdsah *EcdsaHash) Keccak256Hash(data ...[]byte) {
	ecdsah.H = tycrpto.Keccak256Hash(data...)
}
func (ecdsah *EcdsaHash) Keccak256(data ...[]byte) {
	ecdsah.Ha = tycrpto.Keccak256(data...)
}
func (ecdsah *EcdsaHash) CreateAddress(b common.Address, nonce uint64) {
	ecdsah.Address = tycrpto.CreateAddress(b, nonce)
}
func (ecdsah *EcdsaHash) CreateAddress2(b common.Address, salt [32]byte, inithash []byte) {
	ecdsah.Address = tycrpto.CreateAddress2(b, salt, inithash)
}
func NewHash(config string) TaiHash {
	var smh Sm3Hash
	var ecd EcdsaHash
	switch config {
	case "HASH_CRYPTO_SHA3":
		return &ecd
	case "HASH_CRYPTO_SM3":
		return &smh
	}
	return nil
}
