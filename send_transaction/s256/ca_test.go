package test

import (
	"encoding/hex"
	"fmt"
	"github.com/taiyuechain/taiyuechain/common/hexutil"
	"github.com/taiyuechain/taiyuechain/crypto"
	"math/big"
	"os"
	"testing"

	"github.com/taiyuechain/taiyuechain/core"
	"github.com/taiyuechain/taiyuechain/core/state"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/log"
)

func init() {
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlInfo, log.StreamHandler(os.Stderr, log.TerminalFormat(false))))
}

//neo test cacert contract
func TestAllCaCert(t *testing.T) {
	// Create a helper to check if a gas allowance results in an executable transaction
	executable := func(number uint64, gen *core.BlockGen, fastChain *core.BlockChain, header *types.Header, statedb *state.StateDB) {
		sendTranction(number, gen, statedb, mAccount, saddr1, big.NewInt(6000000000000000000), priKey, signer, nil, header)
		cert44 := []byte{127}

		sendMultiProposalTranscation(number, gen, saddr1, cert44, pbft1Byte, true, skey1, signer, statedb, fastChain, abiCA, nil, p2p2Byte)
		sendMultiProposalTranscation(number, gen, saddr1, cert44, pbft2Byte, true, skey1, signer, statedb, fastChain, abiCA, nil, p2p2Byte)
		sendDelCaCertTranscation(number, gen, saddr1, cert44, skey1, signer, statedb, fastChain, abiCA, nil, p2p2Byte)
	}
	newTestPOSManager(2, executable)
	fmt.Println("staking addr", types.CACertListAddress,"Name",priKey.Curve.Params().Name)
}

func TestGetAddress(t *testing.T) {
	// Create a helper to check if a gas allowance results in an executable transaction
	for i := 0; i < 4; i++ {
		skey, _ := crypto.GenerateKey()
		fmt.Println("priv",hex.EncodeToString(crypto.FromECDSA(skey)),"pub",hexutil.Encode(crypto.FromECDSAPub(&skey.PublicKey)))
	}
	// c769a2bb5656d951ead8a00c9f426720aaee0d8fdb35ae2568b06cace803b095
	// f60d6a7b9f108dca4fdf968215c0942714324470fcfca85b006294beacd2b143
	// da888debf74c311ca97b1d500b1ffb1cda590dd29a325734d9f8d94b7683e649
	// 1727596dfdb521a56097be9b089ec0b775047dec227d5c5b23a8c420980fd1aa
}
