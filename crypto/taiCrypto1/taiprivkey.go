package taiCrypto1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	tycrpto "github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/crypto/ecies"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm2"
	"github.com/taiyuechain/taiyuechain/crypto/p256"
	"io"
	"os"
)

/*
 ecdsa public method
*/

func (Taipri *EcdsaPrivateKey) Public() []byte {
	return tycrpto.FromECDSA1((*ecdsa.PrivateKey)(Taipri))
}
func (Taipri *EcdsaPrivateKey) ToPubkeyByte() []byte {
	return tycrpto.FromECDSAPub1((*ecdsa.PublicKey)(&Taipri.PublicKey))
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
func (Taipri *EcdsaPrivateKey) SavePrivate(file string) error {
	return tycrpto.SaveECDSA1(file, (*ecdsa.PrivateKey)(Taipri))
}

/*
sm method
*/
func (Taipri *Sm2PrivateKey) Public() []byte {
	return ((*sm2.PrivateKey)(Taipri)).GetRawBytes1()
}
func (Taipri *Sm2PrivateKey) ToPubkeyByte() []byte {
	return (*sm2.PublicKey)(&Taipri.PublicKey).GetRawBytes1()
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
func (Taipri *Sm2PrivateKey) SavePrivate(file string) error {
	return sm2.SaveSm2Private(file, (*sm2.PrivateKey)(Taipri))
}

/*func (Taipri *Sm2PrivateKey) Decrypt(ct []byte) (m []byte, err error) {
	return sm2.Decrypt((*sm2.PrivateKey)(Taipri), ct, sm2.C1C2C3)
}
P256 method
*/
func (Taipri *P256PrivateKey) Public() []byte {
	return tycrpto.FromECDSAP256((*ecies.PrivateKey)(Taipri).ExportECDSA())
}
func (Taipri *P256PrivateKey) ToPubkeyByte() []byte {
	return tycrpto.FromECDSAPubP2561((*ecies.PublicKey)(&Taipri.PublicKey).ExportECDSA())
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
func (Taipri *P256PrivateKey) SavePrivate(file string) error {
	return p256.SaveP256Private(file, (*ecies.PrivateKey)(Taipri).ExportECDSA())
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

		p256pri, err := tycrpto.ToECDSAP2561(prikey)
		if err != nil {
			return nil, err
		}
		return (*P256PrivateKey)(ecies.ImportECDSA(p256pri)), nil
	}
	return nil, nil
}
func GenerateKey(config string) TaiPrivKey {
	switch config {
	case "ASY_CRYPTO_S256":
		ecdsapri, _ := tycrpto.GenerateKey()
		return (*EcdsaPrivateKey)(ecdsapri)
	case "ASY_CRYPTO_SM2":
		smpri, _, _ := sm2.GenerateKey(rand.Reader)
		return (*Sm2PrivateKey)(smpri)
	case "ASY_CRYPTO_P256":
		eciespri, _ := ecies.GenerateKey(rand.Reader, elliptic.P256(), nil)
		return (*P256PrivateKey)(eciespri)
		//case params.TestnetChainConfig.AsymmetrischCryptoType==params.ASY_CRYPTO_SM2:
	}

	return nil
}
func HexToPrivate(hexkey string) (TaiPrivKey, error) {
	pribyte, err := hex.DecodeString(hexkey)
	if err != nil {
		return nil, err
	}
	return ToPrivateKey(pribyte)
}
func LoadECDSA(file string) (TaiPrivKey, error) {
	buf := make([]byte, 64)
	fd, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	if _, err := io.ReadFull(fd, buf); err != nil {
		return nil, err
	}

	key, err := hex.DecodeString(string(buf))
	if err != nil {
		return nil, err
	}
	return ToPrivateKey(key)
}
func NewPrivate(privkey interface{}) TaiPrivKey {
	switch pri := privkey.(type) {
	case ecdsa.PrivateKey:
		return (*EcdsaPrivateKey)(&pri)
	case sm2.PrivateKey:
		return (*Sm2PrivateKey)(&pri)
	case ecies.PrivateKey:
		return (*P256PrivateKey)(&pri)
	}
	return nil
}
