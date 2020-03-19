package taiCrypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/taiyuechain/taiyuechain/core"
	tycrpto "github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm2"
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
	UnmarshalPubkey(pub []byte) (*TaiPublicKey, error)
	FromECDSAPub(pubkey TaiPublicKey) []byte
	PubkeyToAddress(pubkey TaiPublicKey) common.Address
}

type SignerOpts interface {
	VerifySignature(digestHash []byte, signature []byte) bool
	SigToPub(hash []byte, sig []byte) (*TaiPublicKey, error)
}

func (TPK *TaiPrivateKey) SaveECDSA(file string, key TaiPrivateKey) error {
	switch core.AsymmetricCryptoType {
	case core.ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		k := hex.EncodeToString(TPK.FromECDSA(key))
		return ioutil.WriteFile(file, []byte(k), 0600)
	case core.ASYMMETRICCRYPTOECDSA:
		return tycrpto.SaveECDSA(file, &key.private)
	}
	return nil
}
func (TPK *TaiPrivateKey) LoadECDSA(file string) (*TaiPrivateKey, error) {
	switch core.AsymmetricCryptoType {
	case core.ASYMMETRICCRYPTOSM2:
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
	case core.ASYMMETRICCRYPTOECDSA:
		private, err := tycrpto.LoadECDSA(file)
		if err != nil {
			return nil, err
		}
		TPK.private = *private
		return TPK, nil
	}
	return TPK, nil
}
func (TPK *TaiPrivateKey) HexToECDSA(hexkey string) (*TaiPrivateKey, error) {
	switch core.AsymmetricCryptoType {
	case core.ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		b, err := hex.DecodeString(hexkey)
		if err != nil {
			return nil, errors.New("invalid hex string")
		}
		return TPK.ToECDSA(b)
	case core.ASYMMETRICCRYPTOECDSA:
		private, err := tycrpto.HexToECDSA(hexkey)
		if err != nil {
			return nil, err
		}
		TPK.private = *private
		return TPK, nil
	}
	return TPK, nil
}
func (TPK *TaiPublicKey) PubkeyToAddress(pubkey TaiPublicKey) common.Address {
	var t THash
	switch core.AsymmetricCryptoType {
	case core.ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		pubBytes := TPK.FromECDSAPub(pubkey)
		return common.BytesToAddress(t.Keccak256(pubBytes[1:])[12:])
	case core.ASYMMETRICCRYPTOECDSA:
		return tycrpto.PubkeyToAddress(pubkey.publickey)
	}
	return common.Address{}
}
func (TPK *TaiPublicKey) FromECDSAPub(pubkey TaiPublicKey) []byte {
	switch core.AsymmetricCryptoType {
	case core.ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		return pubkey.smPublickey.GetRawBytes()
	case core.ASYMMETRICCRYPTOECDSA:
		return tycrpto.FromECDSAPub(&pubkey.publickey)
	}
	return nil
}
func (TPK *TaiPublicKey) UnmarshalPubkey(pub []byte) (*TaiPublicKey, error) {
	switch core.AsymmetricCryptoType {
	case core.ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		sm2.RawBytesToPublicKey(pub)
		gmPublic, err := sm2.RawBytesToPublicKey(pub)
		if err != nil {
			return nil, err
		}
		TPK.smPublickey = *gmPublic
		return TPK, nil

	case core.ASYMMETRICCRYPTOECDSA:
		public, err := tycrpto.UnmarshalPubkey(pub)
		if err != nil {
			return nil, err
		}
		TPK.publickey = *public
		return TPK, nil
	}
	return TPK, nil
}
func (TPK *TaiPrivateKey) ToECDSAUnsafe(d []byte) *TaiPrivateKey {
	switch core.AsymmetricCryptoType {
	case core.ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		gmPrivate, _ := sm2.RawBytesToPrivateKey(d)
		TPK.gmPrivate = *gmPrivate
		return TPK

	case core.ASYMMETRICCRYPTOECDSA:
		private := tycrpto.ToECDSAUnsafe(d)

		TPK.private = *private
		return TPK
	}
	return TPK
}
func (TPK *TaiPrivateKey) ToECDSA(d []byte) (*TaiPrivateKey, error) {
	switch core.AsymmetricCryptoType {
	case core.ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		//sm2.RawBytesToPrivateKey(d)
		gmPrivate, err := sm2.RawBytesToPrivateKey(d)
		if err != nil {
			return nil, err
		}
		TPK.gmPrivate = *gmPrivate
		TPK.gmPrivate.PublicKey = gmPrivate.PublicKey
		return TPK, nil

	case core.ASYMMETRICCRYPTOECDSA:
		private, err := tycrpto.ToECDSA(d)
		if err != nil {
			return nil, err
		}
		TPK.private = *private
		return TPK, nil
	}
	return TPK, nil
}
func (TPK *TaiPrivateKey) FromECDSA(prikey TaiPrivateKey) []byte {
	switch core.AsymmetricCryptoType {
	case core.ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		return prikey.gmPrivate.GetRawBytes()

	case core.ASYMMETRICCRYPTOECDSA:
		return tycrpto.FromECDSA(&prikey.private)
	}
	return nil
}
func (TPK *TaiPublicKey) CompressPubkey(pubkey TaiPublicKey) []byte {
	switch core.AsymmetricCryptoType {
	case core.ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		TPK.publickey = pubkey.publickey
		TPK.smPublickey.GetRawBytes()
		return TPK.smPublickey.GetRawBytes()

	case core.ASYMMETRICCRYPTOECDSA:
		//pk,err:=crypto.HexToECDSA(hexKey)
		//b, err := hex.DecodeString(hexKey)
		pubk := tycrpto.CompressPubkey(&pubkey.publickey)
		return pubk
	}
	return nil
}
func (TPK *TaiPublicKey) SigToPub(hash, sig []byte) (*TaiPublicKey, error) {
	switch core.AsymmetricCryptoType {
	case core.ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		smPublicKey, err := sm2.RecoverPubkey(hash, sig)
		if err != nil {
			return nil, err
		}
		TPK.smPublickey = *smPublicKey
		return TPK, nil

	case core.ASYMMETRICCRYPTOECDSA:
		//pk,err:=crypto.HexToECDSA(hexKey)
		//b, err := hex.DecodeString(hexKey)
		pubk, _ := tycrpto.SigToPub(hash, sig)
		TPK.publickey = *pubk
		return TPK, nil
	}
	return nil, nil
}

type TaiPrivateKey struct {
	hexBytesPrivate []byte
	private         ecdsa.PrivateKey
	gmPrivate       sm2.PrivateKey
}

func (TPK *TaiPrivateKey) Public() *TaiPrivateKey {

	switch core.AsymmetricCryptoType {
	case core.ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		pubk, _ := sm2.RawBytesToPrivateKey(TPK.hexBytesPrivate)
		TPK.gmPrivate = *pubk
		return TPK

	case core.ASYMMETRICCRYPTOECDSA:
		//pk,err:=crypto.HexToECDSA(hexKey)
		//b, err := hex.DecodeString(hexKey)
		pubk, _ := tycrpto.ToECDSA(TPK.hexBytesPrivate)
		TPK.private = *pubk
		return TPK
	}
	return nil
}

func (TPK *TaiPrivateKey) Sign(digestHash []byte, tai TaiPrivateKey) ([]byte, error) {
	switch core.AsymmetricCryptoType {
	case core.ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		return sm2.Sign(&tai.gmPrivate, nil, digestHash)
	case core.ASYMMETRICCRYPTOECDSA:
		//privk, _ := tycrpto.ToECDSA(TPK.hexBytesPrivate)
		return tycrpto.Sign(digestHash, &tai.private)
	}
	return nil, nil
}

type TaiPublicKey struct {
	hexBytesPublic []byte
	publickey      ecdsa.PublicKey
	smPublickey    sm2.PublicKey
}

func (TPK *TaiPublicKey) VerifySignature(digestHash, signature []byte) bool {
	switch core.AsymmetricCryptoType {
	case core.ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		//pubk, _ := sm2.RawBytesToPublicKey(TPK.hexBytesPublic)
		pubk := TPK.smPublickey
		return sm2.Verify(&pubk, nil, digestHash, signature)
	case core.ASYMMETRICCRYPTOECDSA:
		//pk,err:=crypto.HexToECDSA(hexKey)
		//b, err := hex.DecodeString(hexKey)
		TPK.hexBytesPublic = TPK.CompressPubkey(*TPK)
		return tycrpto.VerifySignature(TPK.hexBytesPublic, digestHash, signature)
	}
	return false
}

func HexToTaiPrivateKey(hexKey string) (*TaiPrivateKey, error) {
	var tai TaiPrivateKey
	switch core.AsymmetricCryptoType {
	case core.ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		b, err := hex.DecodeString(hexKey)
		if err != nil {
			return nil, errors.New("invalid hex string")
		}
		tai.hexBytesPrivate = b
		return &tai, nil
	case core.ASYMMETRICCRYPTOECDSA:
		//pk,err:=crypto.HexToECDSA(hexKey)
		b, err := hex.DecodeString(hexKey)
		if err != nil {
			return nil, errors.New("invalid hex string")
		}
		tai.hexBytesPrivate = b
		return &tai, nil
	}
	return nil, nil
}
func GenPrivKey() *TaiPrivateKey {
	var tai TaiPrivateKey
	switch core.AsymmetricCryptoType {
	case core.ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		prik, pubk, _ := sm2.GenerateKey(rand.Reader)
		tai.gmPrivate = *prik
		tai.gmPrivate.PublicKey = *pubk
		return &tai
	case core.ASYMMETRICCRYPTOECDSA:
		//pk,err:=crypto.HexToECDSA(hexKey)
		//b, err := hex.DecodeString(hexKey)
		prik, _ := tycrpto.GenerateKey()
		tai.private = *prik
		return &tai
	}
	return nil
}
func ValidateSignatureValues(v byte, r, s *big.Int, homestead bool) bool {
	switch core.AsymmetricCryptoType {
	case core.ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
		return sm2.ValidateSignatureValues(v, r, s, homestead)
	case core.ASYMMETRICCRYPTOECDSA:
		//pk,err:=crypto.HexToECDSA(hexKey)
		//b, err := hex.DecodeString(hexKey)
		return tycrpto.ValidateSignatureValues(v, r, s, homestead)
	}
	return false
}
