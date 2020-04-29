package taiCrypto1

import (
	"crypto/ecdsa"
	"encoding/hex"
	tycrpto "github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/crypto/ecies"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm2"
	"github.com/taiyuechain/taiyuechain/crypto/p256"
)

/*
 ecdsa public method
*/

func (Taipri *EcdsaPrivateKey) Public() []byte {
	return tycrpto.FromECDSA1((*ecdsa.PrivateKey)(Taipri))
}
func (Taipri *EcdsaPrivateKey) Sign(digestHash []byte) ([]byte, error) {
	ret, err := tycrpto.Sign(digestHash, (*ecdsa.PrivateKey)(Taipri))
	if err != nil {
		return nil, err
	}
	ret = append([]byte{1}, ret...)
	return ret, nil
}
func (Taipri *EcdsaPrivateKey) ToHex() string {
	pribyte := Taipri.Public()
	return hex.EncodeToString(pribyte)
}
func (Taipri *EcdsaPrivateKey) Decrypt(ct []byte) (m []byte, err error) {
	return ecies.ImportECDSA((*ecdsa.PrivateKey)(Taipri)).Decrypt(ct, nil, nil)
}

/*
sm method
*/
func (Taipri *Sm2PrivateKey) Public() []byte {
	return ((*sm2.PrivateKey)(Taipri)).GetRawBytes1()
}
func (Taipri *Sm2PrivateKey) Sign(digestHash []byte) ([]byte, error) {
	ret, err := sm2.Sign((*sm2.PrivateKey)(Taipri), nil, digestHash)
	if err != nil {
		return nil, err
	}
	ret = append([]byte{2}, ret...)
	return ret, nil
}
func (Taipri *Sm2PrivateKey) ToHex() string {
	pribyte := Taipri.Public()
	return hex.EncodeToString(pribyte)
}
func (Taipri *Sm2PrivateKey) Decrypt(ct []byte) (m []byte, err error) {
	return sm2.Decrypt((*sm2.PrivateKey)(Taipri), ct, sm2.C1C2C3)
}

/*
P256 method
*/
func (Taipri *P256PrivateKey) Public() []byte {
	return tycrpto.FromECDSAP256((*ecies.PrivateKey)(Taipri).ExportECDSA())
}
func (Taipri *P256PrivateKey) Sign(digestHash []byte) ([]byte, error) {
	ret, err := p256.Sign(digestHash, (*ecies.PrivateKey)(Taipri).ExportECDSA())
	if err != nil {
		return nil, err
	}
	ret = append([]byte{3}, ret...)
	return ret, nil
}
func (Taipri *P256PrivateKey) ToHex() string {
	pribyte := Taipri.Public()
	return hex.EncodeToString(pribyte)
}
func (Taipri *P256PrivateKey) Decrypt(ct []byte) (m []byte, err error) {
	return (*ecies.PrivateKey)(Taipri).Decrypt(ct, nil, nil)
}
func ToPrivateKey(prikey []byte) (TaiPrivKey, error) {
	if prikey[0] == 1 {
		ecdsapri, err := tycrpto.ToECDSA1(prikey)
		if err != nil {
			return nil, err
		}
		return (*EcdsaPrivateKey)(ecdsapri), nil
	}
	if prikey[0] == 2 {

		smapri, err := sm2.RawBytesToPrivateKey1(prikey)
		if err != nil {
			return nil, err
		}
		return (*Sm2PrivateKey)(smapri), nil
	}
	if prikey[0] == 3 {

		p256pri, err := tycrpto.ToECDSAP256(prikey)
		if err != nil {
			return nil, err
		}
		return (*P256PrivateKey)(ecies.ImportECDSA(p256pri)), nil
	}
	return nil, nil
}
