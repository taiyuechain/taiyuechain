package taiCrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	//"github.com/ethereum/go-ethereum/crypto"
	tycrpto "github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/crypto/ecies"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm2"
	"github.com/taiyuechain/taiyuechain/crypto/secp256k1"
	"io"
	"io/ioutil"
	"math/big"
	"os"
)

type TaiPrivKey interface {
	Public() *TaiPrivateKey
	Sign(digestHash []byte, tai TaiPrivateKey) ([]byte, error)
	FromECDSA(prikey TaiPrivateKey) []byte
	ToECDSA(d []byte) (*TaiPrivateKey, error)
	ToECDSAUnsafe(d []byte) *TaiPrivateKey
	HexToECDSA(hexkey string) (*TaiPrivateKey, error)
	LoadECDSA(file string) (*TaiPrivateKey, error)
	SaveECDSA(file string, key TaiPrivateKey) error
}
type TaiPubKey interface {
	CompressPubkey(pubkey TaiPublicKey) []byte
	DecompressPubkey(pubkey []byte) (*TaiPublicKey, error)
	UnmarshalPubkey(pub []byte) (*TaiPublicKey, error)
	FromECDSAPub(pubkey TaiPublicKey) []byte
	PubkeyToAddress(pubkey TaiPublicKey) common.Address
}
type SignerOpts interface {
	VerifySignature(digestHash []byte, signature []byte) bool
	SigToPub(hash []byte, sig []byte) (*TaiPublicKey, error)
}
type EciesPublicKey interface {
	ExportECDSA() *TaiPublicKey
	ImportECDSAPublic(pub *TaiPublicKey) *TaiPublicKey
	MaxSharedKeyLength(pub *TaiPublicKey) int
	Encrypt(rand io.Reader, pub *TaiPublicKey, m, s1, s2 []byte) (ct []byte, err error)
}
type EciesPrivateKey interface {
	ExportECDSA() *TaiPrivateKey
	ImportECDSA(prv *TaiPrivateKey) *TaiPrivateKey
	GenerateShared(pub *TaiPublicKey, skLen, macLen int) (sk []byte, err error)
	Decrypt(c, s1, s2 []byte) (m []byte, err error)
}

func (TPK *TaiPublicKey) DecompressPubkey(pubkey []byte) (*TaiPublicKey, error) {
	switch AsymmetricCryptoType {
	case ASYMMETRICCRYPTOSM2:
		smPublickey, err := sm2.RawBytesToPublicKey(pubkey)
		if err != nil {
			return nil, err
		}
		TPK.SmPublickey = *smPublickey
		return TPK, nil
	case ASYMMETRICCRYPTOECDSA:
		tpkpublic, err := tycrpto.DecompressPubkey(pubkey)
		if err != nil {
			return nil, err
		}
		TPK.Publickey = *tpkpublic
		return TPK, nil
	}
	return nil, nil
}
func (TPK *TaiPrivateKey) ExportECDSA() *TaiPrivateKey {
	TPK.Private = *TPK.EciesPrivate.ExportECDSA()
	return TPK

}
func (TPK *TaiPrivateKey) Decrypt(c, s1, s2 []byte) (m []byte, err error) {
	switch AsymmetricCryptoType {
	case ASYMMETRICCRYPTOSM2:
		return sm2.Decrypt(&TPK.GmPrivate, c, sm2.C1C2C3)
	case ASYMMETRICCRYPTOECDSA:
		return TPK.EciesPrivate.Decrypt(c, s1, s2)
	}
	return nil, nil
}
func (TPK *TaiPrivateKey) ImportECDSA(prv *TaiPrivateKey) *TaiPrivateKey {
	TPK.EciesPrivate = *ecies.ImportECDSA(&prv.Private)
	return TPK
}
func (TPK *TaiPublicKey) ExportECDSA() *TaiPublicKey {
	TPK.Publickey = *TPK.EciesPublickey.ExportECDSA()
	return TPK
}
func (TPK *TaiPrivateKey) GenerateShared(pub *TaiPublicKey, skLen, macLen int) (sk []byte, err error) {
	switch AsymmetricCryptoType {
	case ASYMMETRICCRYPTOSM2:
		return TPK.GmPrivate.GenerateShared(&pub.SmPublickey, skLen, macLen)
	case ASYMMETRICCRYPTOECDSA:
		return TPK.EciesPrivate.GenerateShared(&pub.EciesPublickey, skLen, macLen)
	}
	return nil, nil
}
func (TPK *TaiPublicKey) ImportECDSAPublic(pub *TaiPublicKey) *TaiPublicKey {
	TPK.EciesPublickey = *ecies.ImportECDSAPublic(&pub.Publickey)
	return TPK
}
func (TPK *TaiPublicKey) MaxSharedKeyLength(pub *TaiPublicKey) int {
	length := ecies.MaxSharedKeyLength(&pub.EciesPublickey)
	return length
}
func (TPK *TaiPublicKey) Encrypt(rand io.Reader, pub *TaiPublicKey, m, s1, s2 []byte) (ct []byte, err error) {
	switch AsymmetricCryptoType {
	case ASYMMETRICCRYPTOSM2:
		return sm2.Encrypt(&pub.SmPublickey, m, sm2.C1C2C3)
	case ASYMMETRICCRYPTOECDSA:
		return ecies.Encrypt(rand, &pub.EciesPublickey, m, s1, s2)
	}
	return nil, nil
}
func (TPK *TaiPrivateKey) SaveECDSA(file string, key TaiPrivateKey) error {
	switch AsymmetricCryptoType {
	case ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		k := hex.EncodeToString(TPK.FromECDSA(key))
		return ioutil.WriteFile(file, []byte(k), 0600)
	case ASYMMETRICCRYPTOECDSA:
		return tycrpto.SaveECDSA(file, &key.Private)
	}
	return nil
}
func (TPK *TaiPrivateKey) LoadECDSA(file string) (*TaiPrivateKey, error) {
	switch AsymmetricCryptoType {
	case ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
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
		return TPK.ToECDSA(key)
	case ASYMMETRICCRYPTOECDSA:
		private, err := tycrpto.LoadECDSA(file)
		if err != nil {
			return nil, err
		}
		TPK.Private = *private
		return TPK, nil
	}
	return TPK, nil
}
func (TPK *TaiPrivateKey) HexToECDSA(hexkey string) (*TaiPrivateKey, error) {
	switch AsymmetricCryptoType {
	case ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		b, err := hex.DecodeString(hexkey)
		if err != nil {
			return nil, errors.New("invalid hex string")
		}
		return TPK.ToECDSA(b)
	case ASYMMETRICCRYPTOECDSA:
		private, err := tycrpto.HexToECDSA(hexkey)
		if err != nil {
			return nil, err
		}
		TPK.Private = *private
		return TPK, nil
	}
	return TPK, nil
}
func (TPK *TaiPublicKey) PubkeyToAddress(pubkey TaiPublicKey) common.Address {
	var t THash
	switch AsymmetricCryptoType {
	case ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		pubBytes := TPK.FromECDSAPub(pubkey)
		return common.BytesToAddress(t.Keccak256(pubBytes[1:])[12:])
	case ASYMMETRICCRYPTOECDSA:
		return tycrpto.PubkeyToAddress(pubkey.Publickey)
	}
	return common.Address{}
}
func (TPK *TaiPublicKey) FromECDSAPub(pubkey TaiPublicKey) []byte {
	switch AsymmetricCryptoType {
	case ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		return pubkey.SmPublickey.GetRawBytes()
	case ASYMMETRICCRYPTOECDSA:
		return tycrpto.FromECDSAPubCA(&pubkey.Publickey)
	}
	return nil
}
func (TPK *TaiPublicKey) UnmarshalPubkey(pub []byte) (*TaiPublicKey, error) {
	switch AsymmetricCryptoType {
	case ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		sm2.RawBytesToPublicKey(pub)
		gmPublic, err := sm2.RawBytesToPublicKey(pub)
		if err != nil {
			return nil, err
		}
		TPK.SmPublickey = *gmPublic
		return TPK, nil

	case ASYMMETRICCRYPTOECDSA:
		public, err := tycrpto.UnmarshalPubkey(pub)
		if err != nil {
			return nil, err
		}
		TPK.Publickey = *public
		return TPK, nil
	}
	return TPK, nil
}
func (TPK *TaiPrivateKey) ToECDSAUnsafe(d []byte) *TaiPrivateKey {
	switch AsymmetricCryptoType {
	case ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		gmPrivate, _ := sm2.RawBytesToPrivateKey(d)
		TPK.GmPrivate = *gmPrivate
		return TPK

	case ASYMMETRICCRYPTOECDSA:
		private := tycrpto.ToECDSAUnsafe(d)
		TPK.Private = *private
		return TPK
	}
	return TPK
}
func (TPK *TaiPrivateKey) ToECDSA(d []byte) (*TaiPrivateKey, error) {
	switch AsymmetricCryptoType {
	case ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		//sm2.RawBytesToPrivateKey(d)
		gmPrivate, err := sm2.RawBytesToPrivateKey(d)
		if err != nil {
			return nil, err
		}
		TPK.GmPrivate = *gmPrivate
		taipub := togmpublickey(*TPK)
		TPK.GmPrivate.PublicKey = taipub.SmPublickey
		return TPK, nil

	case ASYMMETRICCRYPTOECDSA:
		private, err := tycrpto.ToECDSA(d)
		if err != nil {
			return nil, err
		}
		TPK.Private = *private
		return TPK, nil
	}
	return TPK, nil
}
func (TPK *TaiPrivateKey) FromECDSA(prikey TaiPrivateKey) []byte {
	switch AsymmetricCryptoType {
	case ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		return prikey.GmPrivate.GetRawBytes()

	case ASYMMETRICCRYPTOECDSA:
		return tycrpto.FromECDSA(&prikey.Private)
	}
	return nil
}
func (TPK *TaiPublicKey) CompressPubkey(pubkey TaiPublicKey) []byte {
	switch AsymmetricCryptoType {
	case ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		TPK.Publickey = pubkey.Publickey
		TPK.SmPublickey.GetRawBytes()
		return TPK.SmPublickey.GetRawBytes()

	case ASYMMETRICCRYPTOECDSA:
		//pk,err:=crypto.HexToECDSA(hexKey)
		//b, err := hex.DecodeString(hexKey)
		pubk := tycrpto.CompressPubkey(&pubkey.Publickey)
		return pubk
	}
	return nil
}
func (TPK *TaiPublicKey) SigToPub(hash, sig []byte) (*TaiPublicKey, error) {
	switch AsymmetricCryptoType {
	case ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		smPublicKey, err := sm2.RecoverPubkey(hash, sig)
		if err != nil {
			return nil, err
		}
		TPK.SmPublickey = *smPublicKey
		return TPK, nil

	case ASYMMETRICCRYPTOECDSA:
		//pk,err:=crypto.HexToECDSA(hexKey)
		//b, err := hex.DecodeString(hexKey)
		pubk, _ := tycrpto.SigToPub(hash, sig)
		TPK.Publickey = *pubk
		return TPK, nil
	}
	return nil, nil
}
func (TPK *TaiPublicKey) Ecrecover(hash, sig []byte) ([]byte, error) {
	switch AsymmetricCryptoType {
	case ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		smPublicKey, err := sm2.RecoverPubkey(hash, sig)
		if err != nil {
			return nil, err
		}
		smPublicKey.GetRawBytes()
		return smPublicKey.GetRawBytes(), nil

	case ASYMMETRICCRYPTOECDSA:
		//pk,err:=crypto.HexToECDSA(hexKey)
		//b, err := hex.DecodeString(hexKey)
		pubk, _ := tycrpto.Ecrecover(hash, sig)

		return pubk, nil
	}
	return nil, nil
}

type TaiPrivateKey struct {
	HexBytesPrivate []byte
	Private         ecdsa.PrivateKey
	GmPrivate       sm2.PrivateKey
	TaiPubKey       TaiPublicKey
	EciesPrivate    ecies.PrivateKey
}

func (TPK *TaiPrivateKey) Public() *TaiPrivateKey {

	switch AsymmetricCryptoType {
	case ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		pubk, _ := sm2.RawBytesToPrivateKey(TPK.HexBytesPrivate)
		TPK.GmPrivate = *pubk
		return TPK

	case ASYMMETRICCRYPTOECDSA:
		//pk,err:=crypto.HexToECDSA(hexKey)
		//b, err := hex.DecodeString(hexKey)
		pubk, _ := tycrpto.ToECDSA(TPK.HexBytesPrivate)
		TPK.Private = *pubk
		return TPK
	}
	return nil
}

func (TPK *TaiPrivateKey) Sign(digestHash []byte, tai TaiPrivateKey) ([]byte, error) {
	switch AsymmetricCryptoType {
	case ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		return sm2.Sign(&tai.GmPrivate, nil, digestHash)
	case ASYMMETRICCRYPTOECDSA:
		//privk, _ := tycrpto.ToECDSA(TPK.hexBytesPrivate)
		return tycrpto.Sign(digestHash, &tai.Private)
	}
	return nil, nil
}

type TaiPublicKey struct {
	HexBytesPublic []byte
	Publickey      ecdsa.PublicKey
	SmPublickey    sm2.PublicKey
	EciesPublickey ecies.PublicKey
}

func (TPK *TaiPublicKey) VerifySignature(digestHash, signature []byte) bool {
	switch AsymmetricCryptoType {
	case ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		//pubk, _ := sm2.RawBytesToPublicKey(TPK.hexBytesPublic)
		pubk := TPK.SmPublickey
		return sm2.Verify(&pubk, nil, digestHash, signature)
	case ASYMMETRICCRYPTOECDSA:
		//pk,err:=crypto.HexToECDSA(hexKey)
		//b, err := hex.DecodeString(hexKey)
		//TPK.HexBytesPublic = TPK.CompressPubkey(*TPK)
		return tycrpto.VerifySignature(TPK.HexBytesPublic, digestHash, signature)
	}
	return false
}

func HexToTaiPrivateKey(hexKey string) (*TaiPrivateKey, error) {
	var tai TaiPrivateKey
	switch AsymmetricCryptoType {
	case ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		b, err := hex.DecodeString(hexKey)
		if err != nil {
			return nil, errors.New("invalid hex string")
		}
		tai.HexBytesPrivate = b
		return &tai, nil
	case ASYMMETRICCRYPTOECDSA:
		//pk,err:=crypto.HexToECDSA(hexKey)
		b, err := hex.DecodeString(hexKey)
		if err != nil {
			return nil, errors.New("invalid hex string")
		}
		tai.HexBytesPrivate = b
		return &tai, nil
	}
	return nil, nil
}
func GenPrivKey() (*TaiPrivateKey, error) {
	var tai TaiPrivateKey
	switch AsymmetricCryptoType {
	case ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		prik, pubk, err := sm2.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		tai.GmPrivate = *prik
		tai.GmPrivate.PublicKey = *pubk
		return &tai, nil
	case ASYMMETRICCRYPTOECDSA:
		//pk,err:=crypto.HexToECDSA(hexKey)
		//b, err := hex.DecodeString(hexKey)
		prik, err := tycrpto.GenerateKey()
		if err != nil {
			return nil, err
		}
		tai.Private = *prik
		return &tai, nil
	}
	return nil, nil
}
func GenPrivKeyParam(reader io.Reader) (*TaiPrivateKey, error) {
	var tai TaiPrivateKey
	switch AsymmetricCryptoType {
	case ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		prik, pubk, err := sm2.GenerateKey(reader)
		if err != nil {
			return nil, err
		}
		tai.GmPrivate = *prik
		tai.GmPrivate.PublicKey = *pubk
		return &tai, nil
	case ASYMMETRICCRYPTOECDSA:
		//pk,err:=crypto.HexToECDSA(hexKey)
		//b, err := hex.DecodeString(hexKey)
		prik, err := ecdsa.GenerateKey(tycrpto.S256(), reader)
		if err != nil {
			return nil, err
		}
		tai.Private = *prik
		return &tai, nil
	}
	return nil, nil
}
func GenerateKey(rand io.Reader, curve elliptic.Curve, params *ecies.ECIESParams) (prv *TaiPrivateKey, err error) {
	var private TaiPrivateKey
	eciestpriv, err := ecies.GenerateKey(rand, curve, params)
	if err != nil {
		return nil, err
	}
	private.EciesPrivate = *eciestpriv
	return &private, nil
}
func ValidateSignatureValues(v byte, r, s *big.Int, homestead bool) bool {
	switch AsymmetricCryptoType {
	case ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		return sm2.ValidateSignatureValues(v, r, s, homestead)
	case ASYMMETRICCRYPTOECDSA:
		//pk,err:=crypto.HexToECDSA(hexKey)
		//b, err := hex.DecodeString(hexKey)
		return tycrpto.ValidateSignatureValues(v, r, s, homestead)
	}
	return false
}
func S256() elliptic.Curve {
	return secp256k1.S256()
}
func togmpublickey(pri TaiPrivateKey) TaiPublicKey {
	var taipublic TaiPublicKey
	pub := new(sm2.PublicKey)
	pub.Curve = pri.GmPrivate.Curve
	pub.X, pub.Y = pri.GmPrivate.Curve.ScalarBaseMult(pri.GmPrivate.D.Bytes())
	taipublic.SmPublickey = *pub
	return taipublic
}
