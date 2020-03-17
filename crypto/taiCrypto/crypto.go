package taiCrypto

import (
	"errors"
	"github.com/taiyuechain/taiyuechain/core"
	tycrpto "github.com/taiyuechain/taiyuechain/crypto"
	"encoding/hex"
)

type TaiPrivKey interface {
	

}
type TaiPubKey interface {

}
type SignerOpts interface {

}

type TaiPrivateKey struct {
	hexBytesPrivate []byte
}

func (TPK *TaiPrivateKey) Public() TaiPubKey{
	switch core.AsymmetricCryptoType {
	case core.ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
	case core.ASYMMETRICCRYPTOECDSA:
		//pk,err:=crypto.HexToECDSA(hexKey)
		//b, err := hex.DecodeString(hexKey)
		pubk ,_:=tycrpto.ToECDSA(TPK.hexBytesPrivate)
		return pubk
	}
	return nil
}

func (TPK *TaiPrivateKey) Sign(digestHash []byte)(sig []byte, err error){
	switch core.AsymmetricCryptoType {
	case core.ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
	case core.ASYMMETRICCRYPTOECDSA:
		//pk,err:=crypto.HexToECDSA(hexKey)
		//b, err := hex.DecodeString(hexKey)
		privk ,_:=tycrpto.ToECDSA(TPK.hexBytesPrivate)
		return tycrpto.Sign(digestHash,privk)
	}
	return nil,nil
}

type TaiPublicKey struct {
	hexBytesPublic []byte
}




func HexToTaiPrivateKey(hexKey string) (*TaiPrivateKey,error) {
	switch core.AsymmetricCryptoType {
	case core.ASYMMETRICCRYPTOSM2:
		//TODO need add SM2 to change hexKey
	case core.ASYMMETRICCRYPTOECDSA:
		//pk,err:=crypto.HexToECDSA(hexKey)
		b, err := hex.DecodeString(hexKey)
		if err != nil {
			return nil, errors.New("invalid hex string")
		}

		return &TaiPrivateKey{b},nil
	}
	return nil,nil
}