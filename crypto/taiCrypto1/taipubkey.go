package taiCrypto1

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"github.com/ethereum/go-ethereum/common"
	tycrpto "github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/crypto/ecies"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm2"
	"github.com/taiyuechain/taiyuechain/crypto/p256"
	"github.com/taiyuechain/taiyuechain/crypto/taiCrypto"
)

/*
 ecdsa public method
*/

func (Tapub *EcdsaPublicKey) Verify(hash, sig []byte) bool {
	return tycrpto.VerifySignature(Tapub.ToBytes()[1:], hash, sig[:64])
}
func (Tapub *EcdsaPublicKey) ToBytes() []byte {
	return tycrpto.FromECDSAPub1((*ecdsa.PublicKey)(Tapub))
}
func (Tapub *EcdsaPublicKey) ToAddress() common.Address {
	return tycrpto.PubkeyToAddress((ecdsa.PublicKey)(*Tapub))
}
func (Tapub *EcdsaPublicKey) ToHex() string {
	pubbyte := Tapub.ToBytes()
	return hex.EncodeToString(pubbyte)
}
func (Tapub *EcdsaPublicKey) Encrypt(m []byte) (ct []byte, err error) {
	return ecies.Encrypt(rand.Reader, ecies.ImportECDSAPublic((*ecdsa.PublicKey)(Tapub)), m, nil, nil)
}

/*
sm method
*/
func (Tapub *Sm2PublicKey) Verify(hash, sig []byte) bool {
	return sm2.Verify((*sm2.PublicKey)(Tapub), nil, hash, sig)
}
func (Tapub *Sm2PublicKey) ToBytes() []byte {
	return (*sm2.PublicKey)(Tapub).GetRawBytes1()
}
func (Tapub *Sm2PublicKey) ToAddress() common.Address {
	var t taiCrypto.THash
	return common.BytesToAddress(t.Keccak256(Tapub.ToBytes()[1:])[12:])
}
func (Tapub *Sm2PublicKey) ToHex() string {
	pubbyte := Tapub.ToBytes()
	return hex.EncodeToString(pubbyte)
}
func (Tapub *Sm2PublicKey) Encrypt(m []byte) (ct []byte, err error) {
	return sm2.Encrypt((*sm2.PublicKey)(Tapub), m, sm2.C1C2C3)
}

/*
P256 method
*/
func (Tapub *P256PublicKey) Verify(hash, sig []byte) bool {

	return p256.VerifyP256((*ecies.PublicKey)(Tapub).ExportECDSA(), hash, sig)
}

func (Tapub *P256PublicKey) ToBytes() []byte {
	return tycrpto.FromECDSAPub((*ecies.PublicKey)(Tapub).ExportECDSA())
}
func (Tapub *P256PublicKey) ToAddress() common.Address {
	var t taiCrypto.THash
	return common.BytesToAddress(t.Keccak256(Tapub.ToBytes()[1:])[12:])
}
func (Tapub *P256PublicKey) ToHex() string {
	pubbyte := Tapub.ToBytes()
	return hex.EncodeToString(pubbyte)
}

func (Tapub *P256PublicKey) Encrypt(m []byte) (ct []byte, err error) {
	return ecies.Encrypt(rand.Reader, (*ecies.PublicKey)(Tapub), m, nil, nil)
}
func ToPublickey(pubkey []byte) (interface{}, error) {
	if pubkey[0] == 1 {
		return tycrpto.UnmarshalPubkey1(pubkey)
	}
	if pubkey[0] == 2 {
		return sm2.RawBytesToPublicKey1(pubkey)
	}
	return nil, nil
}
