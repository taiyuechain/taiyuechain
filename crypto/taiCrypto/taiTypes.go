package taiCrypto

import (
	"reflect"
	"github.com/taiyuechain/taiyuechain/core"
	"github.com/ethereum/go-ethereum/common"
	"math/big"
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



func BytesToHash(b []byte) THash {

	var tHash THash
	switch core.CryptoType{
	case core.GMCRYPTO:
		//TODO do GM hash
	case core.GJCRYPTO:
		gjhash := common.BytesToHash(b)
		tHash = gjHashToGmHash(gjhash)
	}
	return tHash
}

func BigToHash(b *big.Int) THash{
	var tHash THash
	switch core.CryptoType {
	case core.GMCRYPTO:
		//TODO do GM hash
	case core.GJCRYPTO:
		gjhash := common.BigToHash(b)
		tHash = gjHashToGmHash(gjhash)
	}

	return tHash

}

func gjHashToGmHash(b common.Hash)THash{
	var tHash THash
	for i:=32;i< TaiHashLength;i++ {
		tHash[i] = b[i-32]
	}
	return tHash
}

