package test

import (
	"os"
	"fmt"
	"math/big"
	"testing"

	"github.com/taiyuechain/taiyuechain/core"
	"github.com/ethereum/go-ethereum/log"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/core/state"
)


func init() {
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlInfo, log.StreamHandler(os.Stderr, log.TerminalFormat(false))))
}

//neo test cacert contract
func TestAllCaCert(t *testing.T) {
	// Create a helper to check if a gas allowance results in an executable transaction
	executable := func(number uint64, gen *core.BlockGen, fastChain *core.BlockChain, header *types.Header, statedb *state.StateDB) {
		sendTranction(number, gen, statedb, mAccount, saddr1, big.NewInt(6000000000000000000), priKey, signer, nil, header)
		cert :=[]byte{123}

		sendAddCaCertTranscation(number, gen, saddr1, cert, skey1, signer, statedb, fastChain, abiStaking, nil)
		sendGetCaCertAmountTranscation(number, gen, saddr1, cert, skey1, signer, statedb, fastChain, abiStaking, nil)
		sendIsApproveCACertTranscation(number, gen, saddr1, cert, skey1, signer, statedb, fastChain, abiStaking, nil)
		sendDelCaCertTranscation(number, gen, saddr1, cert, skey1, signer, statedb, fastChain, abiStaking, nil)
	}
	newTestPOSManager(50, executable)
	fmt.Println("staking addr",types.CACertListAddress)
	//fmt.Println("CARootAddress",types.CACertListAddress)
	//fmt.Println(" saddr1 ", manager.GetBalance(saddr1), " StakingAddress ", manager.GetBalance(types.StakingAddress), " ", types.ToTrue(manager.GetBalance(types.StakingAddress)))
}

