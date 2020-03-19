package taiCrypto

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/taiyuechain/taiyuechain/core"
	tycrpto "github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm3"
	"math/big"
	"reflect"
)

// Lengths of hashes and addresses in bytes.
const (
	// HashLength is the expected length of the hash
	TaiHashLength = 64
	// AddressLength is the expected length of the address
	TaiAddressLength = 20
)

var (
	hashT    = reflect.TypeOf(THash{})
	addressT = reflect.TypeOf(TAddress{})
)

type THash [TaiHashLength]byte
type TAddress [TaiAddressLength]byte
type TaiHash interface {
	Keccak256Hash(data ...[]byte) common.Hash
	Keccak256(data ...[]byte) []byte
	Keccak512(data ...[]byte) []byte
	CreateAddress(b common.Address, nonce uint64) common.Address
	CreateAddress2(b common.Address, salt [32]byte, inithash []byte) common.Address
}

func (t THash) CreateAddress2(b common.Address, salt [32]byte, inithash []byte) common.Address {
	switch core.HashCryptoType {
	case core.HASHCRYPTOSM3:
		return common.BytesToAddress(t.Keccak256([]byte{0xff}, b.Bytes(), salt[:], inithash)[12:])
	case core.HASHCRYPTOHAS3:
		return tycrpto.CreateAddress2(b, salt, inithash)
	}
	return common.Address{}

}

func (t THash) CreateAddress(b common.Address, nonce uint64) common.Address {

	switch core.HashCryptoType {
	case core.HASHCRYPTOSM3:
		data, _ := rlp.EncodeToBytes([]interface{}{b, nonce})
		return common.BytesToAddress(t.Keccak256(data)[12:])
	case core.HASHCRYPTOHAS3:
		return tycrpto.CreateAddress(b, nonce)
	}
	return common.Address{}
}
func (t THash) Keccak512(data ...[]byte) []byte {
	switch core.HashCryptoType {
	case core.HASHCRYPTOSM3:
		//TODO do GM hash
		sm := sm3.New()
		for _, v := range data {
			sm.Write(v)
		}
		s := sm.Sum(nil)
		hash := to512Hash(s)
		return thashtoBytes(hash)
	case core.HASHCRYPTOHAS3:
		return tycrpto.Keccak512(data...)
	}
	return nil
}
func (t THash) Keccak256Hash(data ...[]byte) common.Hash {
	switch core.HashCryptoType {
	case core.HASHCRYPTOSM3:
		//TODO do GM hash
		sm := sm3.New()
		for _, v := range data {
			sm.Write(v)
		}

		s := sm.Sum(nil)
		return hashToCommonHash(s)

	case core.HASHCRYPTOHAS3:
		tyhash := tycrpto.Keccak256Hash(data...)
		return tyhash

	}
	return common.Hash{}
}
func (t THash) Keccak256(data ...[]byte) []byte {
	switch core.HashCryptoType {
	case core.HASHCRYPTOSM3:
		//TODO do GM hash
		sm := sm3.New()
		for _, v := range data {
			sm.Write(v)
		}

		s := sm.Sum(nil)
		return s

	case core.HASHCRYPTOHAS3:
		tyhash := tycrpto.Keccak256(data...)
		return tyhash

	}
	return nil
}
func BytesToHash(b []byte) THash {

	var tHash THash
	switch core.HashCryptoType {
	case core.HASHCRYPTOSM3:
		//TODO do GM hash

	case core.HASHCRYPTOHAS3:
		gjhash := common.BytesToHash(b)
		tHash = gjHashToGmHash(gjhash)
	}
	return tHash
}

func BigToHash(b *big.Int) THash {
	var tHash THash
	switch core.HashCryptoType {
	case core.HASHCRYPTOSM3:
		//TODO do GM hash
	case core.HASHCRYPTOHAS3:
		gjhash := common.BigToHash(b)
		tHash = gjHashToGmHash(gjhash)
	}

	return tHash

}

func gjHashToGmHash(b common.Hash) THash {
	var tHash THash
	for i := 32; i < TaiHashLength; i++ {
		tHash[i] = b[i-32]
	}
	return tHash
}
func to512Hash(smHash []byte) THash {
	var tHash THash
	for i := 32; i < TaiHashLength; i++ {
		tHash[i] = smHash[i-32]
	}
	return tHash
}
func hashToCommonHash(smHash []byte) common.Hash {
	var cHash common.Hash
	for i := 0; i < common.HashLength; i++ {
		cHash[i] = smHash[i]
	}
	return cHash
}
func thashtoBytes(t THash) []byte {
	cHash := make([]byte, 0)
	for i := 0; i < TaiHashLength; i++ {
		cHash = append(cHash, t[i])
	}
	return cHash
}
