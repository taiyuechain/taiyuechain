package taiCrypto

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
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
	Keccak256Hash(data []byte) THash
}

func (t THash) Keccak256Hash(data []byte) THash {
	var tHash THash
	switch core.HashCryptoType {
	case core.HASHCRYPTOSM3:
		//TODO do GM hash
		sm := sm3.New()
		sm.Write(data)
		s := sm.Sum(nil)
		fmt.Println(len(s))
		for i := 32; i < TaiHashLength; i++ {
			tHash[i-32] = s[i-32]
		}
		return tHash

	case core.HASHCRYPTOHAS3:
		tyhash := tycrpto.Keccak256Hash(data)
		return gjHashToGmHash(tyhash)

	}
	return tHash
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
		tHash[i-32] = b[i-32]
	}
	return tHash
}
