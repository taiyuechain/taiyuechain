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
	return tycrpto.VerifySignature(Tapub.ToBytes()[1:], hash, sig[1:65])
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
func (Tapub *EcdsaPublicKey) CompressPubkey() []byte {
	ret := tycrpto.CompressPubkey((*ecdsa.PublicKey)(Tapub))
	ret = append([]byte{1}, ret...)
	return ret
}
func (Tapub *EcdsaPublicKey) PubkeyToAddress() common.Address {
	return tycrpto.PubkeyToAddressP256(*(*ecdsa.PublicKey)(Tapub))
}

/*
sm method
*/
func (Tapub *Sm2PublicKey) Verify(hash, sig []byte) bool {
	return sm2.Verify((*sm2.PublicKey)(Tapub), nil, hash, sig[1:])
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
func (Tapub *Sm2PublicKey) CompressPubkey() []byte {
	ret := sm2.Compress((*sm2.PublicKey)(Tapub))
	ret = append([]byte{2}, ret...)
	return ret
}
func (Tapub *Sm2PublicKey) PubkeyToAddress() common.Address {
	smpublickey := (*sm2.PublicKey)(Tapub)
	return sm2.GMPubkeyToAddress(*smpublickey)
}

/*
P256 method
*/
func (Tapub *P256PublicKey) Verify(hash, sig []byte) bool {

	return p256.Verify(hash, sig[1:], (*ecies.PublicKey)(Tapub).ExportECDSA())
}

func (Tapub *P256PublicKey) ToBytes() []byte {
	return tycrpto.FromECDSAPubP2561((*ecies.PublicKey)(Tapub).ExportECDSA())
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
func (Tapub *P256PublicKey) CompressPubkey() []byte {
	ret := p256.CompressPubkey((*ecies.PublicKey)(Tapub).ExportECDSA())
	ret = append([]byte{3}, ret...)
	return ret
}
func (Tapub *P256PublicKey) PubkeyToAddress() common.Address {
	return tycrpto.PubkeyToAddressP256(*(*ecies.PublicKey)(Tapub).ExportECDSA())
}
func ToPublickey(pubkey []byte) (interface{}, error) {
	if pubkey[0] == 1 {
		return tycrpto.UnmarshalPubkey1(pubkey)
	}
	if pubkey[0] == 2 {
		return sm2.RawBytesToPublicKey1(pubkey)
	}
	if pubkey[0] == 3 {
		return tycrpto.ToECDSAP2561(pubkey)
	}
	return nil, nil
}
func DecompressPublickey(pubkey []byte) (interface{}, error) {
	if pubkey[0] == 1 {
		return tycrpto.DecompressPubkey(pubkey[1:])
	}
	if pubkey[0] == 2 {
		return sm2.Decompress(pubkey[1:]), nil
	}
	if pubkey[0] == 3 {
		return p256.DecompressPubkey(pubkey[1:])
	}
	return nil, nil
}
func SigToPub(hash, sig []byte) (interface{}, error) {
	if sig[0] == 1 {
		/*	ecdsaPublickey, err := tycrpto.SigToPub(hash, sig[1:])
			if err != nil {
				return nil, err
			}*/
		return tycrpto.SigToPub(hash, sig[1:])
	}
	if sig[0] == 2 {
		/*sm2publickey, err := sm2.RecoverPubkey(hash, sig[1:])
		if err != nil {
			return nil, nil, err
		}*/

		return sm2.RecoverPubkey(hash, sig[1:])
	}
	if sig[0] == 3 {
		return p256.ECRecovery(hash, sig[1:])
	}
	return nil, nil
}
