package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"github.com/taiyuechain/taiyuechain/crypto/taiCrypto"

	"github.com/taiyuechain/taiyuechain/consensus/tbft/help"
	tcrypyo "github.com/taiyuechain/taiyuechain/crypto"
	"github.com/tendermint/go-amino"
)

//-------------------------------------
const (
	EcdsaPrivKeyAminoRoute = "true/PrivKeyTrue"
	EcdsaPubKeyAminoRoute  = "true/PubKeyTrue"
	// Size of an Edwards25519 signature. Namely the size of a compressed
	// Edwards25519 point, and a field element. Both of which are 32 bytes.
	SignatureEd25519Size = 64
)

var cdc = amino.NewCodec()

func init() {
	cdc.RegisterInterface((*PubKey)(nil), nil)
	cdc.RegisterConcrete(PubKeyTrue{},
		EcdsaPubKeyAminoRoute, nil)

	cdc.RegisterInterface((*PrivKey)(nil), nil)
	cdc.RegisterConcrete(PrivKeyTrue{},
		EcdsaPrivKeyAminoRoute, nil)
}

// PrivKeyTrue implements PrivKey.
type PrivKeyTrue ecdsa.PrivateKey

// Bytes marshals the privkey using amino encoding.
func (priv PrivKeyTrue) Bytes() []byte {
	return cdc.MustMarshalBinaryBare(priv)
}

// Sign produces a signature on the provided message.
func (priv PrivKeyTrue) Sign(msg []byte) ([]byte, error) {
	var taiprivate taiCrypto.TaiPrivateKey
	priv1 := ecdsa.PrivateKey(priv)
	//caoliang modify
	taiprivate.Private = priv1
	//return tcrypyo.Sign(msg, &priv1)
	return taiprivate.Sign(msg, taiprivate)
}

// PubKey gets the corresponding public key from the private key.
func (priv PrivKeyTrue) PubKey() PubKey {
	priv1 := ecdsa.PrivateKey(priv)
	pub0, ok := priv1.Public().(*ecdsa.PublicKey)
	if !ok {
		panic(0)
	}
	pub := PubKeyTrue(*pub0)
	return &pub
}

// Equals - you probably don't need to use this.
// Runs in constant time based on length of the keys.
func (priv PrivKeyTrue) Equals(other PrivKey) bool {
	var taiprivate taiCrypto.TaiPrivateKey
	if otherEd, ok := other.(PrivKeyTrue); ok {
		priv0 := ecdsa.PrivateKey(otherEd)
		//caolaing modify
		//data0 := tcrypyo.FromECDSA(&priv0)
		taiprivate.Private = priv0
		data0 := taiprivate.FromECDSA(taiprivate)
		priv1 := ecdsa.PrivateKey(priv)
		//data1 := tcrypyo.FromECDSA(&priv1)
		taiprivate.Private = priv1
		data1 := taiprivate.FromECDSA(taiprivate)
		return bytes.Equal(data0[:], data1[:])
	}
	return false
}

// GenPrivKey  generates a new ed25519 private key.
func GenPrivKey() PrivKeyTrue {
	priv, err := tcrypyo.GenerateKey()
	if err != nil {
		panic(err)
	}
	privKey := PrivKeyTrue(*priv)
	return privKey
}

//-------------------------------------

// PubKeyTrue implements PubKey for the ecdsa.PublicKey signature scheme.
type PubKeyTrue ecdsa.PublicKey

// Address is the Keccak256 of the raw pubkey bytes.
func (pub PubKeyTrue) Address() help.Address {
	var taipublic taiCrypto.TaiPublicKey
	pub1 := ecdsa.PublicKey(pub)
	//caoliang modify
	//data := tcrypyo.PubkeyToAddress(pub1)
	taipublic.Publickey = pub1
	data := taipublic.PubkeyToAddress(taipublic)
	return help.Address(data[:])
}

// Bytes marshals the PubKey using amino encoding.
func (pub PubKeyTrue) Bytes() []byte {
	//bz, err := cdc.MarshalBinaryBare(pub)
	var taipublic taiCrypto.TaiPublicKey
	pub1 := ecdsa.PublicKey(pub)
	//caoliang modify
	taipublic.Publickey = pub1
	//bz := tcrypyo.FromECDSAPub(&pub1)
	bz := taipublic.FromECDSAPub(taipublic)
	//bz := elliptic.Marshal(tcrypyo.S256(), pub.X, pub.Y)
	//if err != nil {
	//	panic(err)
	//}
	return bz
}

//VerifyBytes is check msg
func (pub PubKeyTrue) VerifyBytes(msg []byte, sig []byte) bool {
	// make sure we use the same algorithm to sign
	//caoliang modify
	var taipublic taiCrypto.TaiPublicKey
	//if pub0, err := tcrypyo.SigToPub(msg, sig); err == nil {
	if pub0, err := taipublic.SigToPub(msg, sig); err == nil {
		//pub1 := PubKeyTrue(*pub0)
		pub1 := PubKeyTrue(pub0.Publickey)
		return pub.Equals(pub1)
	}
	return false
}

func (pub PubKeyTrue) String() string {
	var taipublic taiCrypto.TaiPublicKey
	pub1 := ecdsa.PublicKey(pub)
	//caoliang modify
	taipublic.Publickey = pub1
	data := taipublic.FromECDSAPub(taipublic)
	//data := tcrypyo.FromECDSAPub(&pub1)
	if data == nil {
		return ""
	}
	return fmt.Sprintf("PubKeyTrue{%X}", data[:])
}

// Equals is comp public key
func (pub PubKeyTrue) Equals(other PubKey) bool {
	var taipublic taiCrypto.TaiPublicKey
	if otherEd, ok := other.(PubKeyTrue); ok {
		pub0 := ecdsa.PublicKey(otherEd)
		pub1 := ecdsa.PublicKey(pub)
		//caoliang modify
		/*data0 := tcrypyo.FromECDSAPub(&pub0)
		data1 := tcrypyo.FromECDSAPub(&pub1)*/
		taipublic.Publickey = pub0
		data0 := taipublic.FromECDSAPub(taipublic)
		taipublic.Publickey = pub1
		data1 := taipublic.FromECDSAPub(taipublic)
		if data0 == nil || data1 == nil {
			return false
		}
		return bytes.Equal(data0[:], data1[:])
	}
	return false
}
