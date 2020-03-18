package taiCrypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/taiyuechain/taiyuechain/core"
	tycrpto "github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm2"
)

type TaiPrivKey interface {
	Public() *TaiPrivateKey
	Sign(digestHash []byte, tai TaiPrivateKey) ([]byte, error)
	FromECDSA(prikey TaiPrivateKey) []byte
}
type TaiPubKey interface {
	CompressPubkey(pubkey TaiPublicKey) []byte
}

type SignerOpts interface {
	VerifySignature(digestHash []byte, signature []byte) bool
	SigToPub(hash []byte, sig []byte) (*TaiPublicKey, error)
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
