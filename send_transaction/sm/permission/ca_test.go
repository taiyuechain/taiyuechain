package test

import (
	"fmt"
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
func TestAllPermission(t *testing.T) {
	// Create a helper to check if a gas allowance results in an executable transaction
	executable := func(number uint64, gen *core.BlockGen, fastChain *core.BlockChain, header *types.Header, statedb *state.StateDB) {
		sendTranction(number, gen, statedb, mAccount, saddr1, big.NewInt(6000000000000000000), priKey, signer, nil, header, p2p1Byte)
		sendGrantPermissionTranscation(number, gen, saddr1, saddr5, skey1, signer, statedb, fastChain, abiCA, nil, p2p2Byte)

		//sendIsApproveCACertTranscation(number, gen, saddr1, pbft1Byte, skey1, signer, statedb, fastChain, abiCA, nil, p2p2Byte)
		//cert44 := pbft5Byte
		//sendMultiProposalTranscation(number, gen, saddr1, cert44, pbft1Byte, true, skey1, signer, statedb, fastChain, abiCA, nil, p2p2Byte)
		//sendMultiProposalTranscation(number, gen, saddr1, cert44, pbft2Byte, true, skey1, signer, statedb, fastChain, abiCA, nil, p2p2Byte)
		//sendGrantPermissionTranscation(number-25, gen, saddr1, pbft1Byte, skey1, signer, statedb, fastChain, abiCA, nil, p2p2Byte)
		//sendGrantPermissionTranscation(number-25-1000, gen, saddr1, pbft1Byte, skey1, signer, statedb, fastChain, abiCA, nil, p2p2Byte)
		//sendMultiProposalTranscation(number-26-1000, gen, saddr1, cert44, pbft1Byte, false, skey1, signer, statedb, fastChain, abiCA, nil, p2p2Byte)
		//sendMultiProposalTranscation(number-27-1000, gen, saddr1, cert44, pbft2Byte, false, skey1, signer, statedb, fastChain, abiCA, nil, p2p2Byte)
		//sendMultiProposalTranscation(number-28-1000, gen, saddr1, cert44, pbft3Byte, false, skey1, signer, statedb, fastChain, abiCA, nil, p2p2Byte)
		//sendGrantPermissionTranscation(number-25-2000, gen, saddr1, pbft1Byte, skey1, signer, statedb, fastChain, abiCA, nil, p2p2Byte)
	}
	newTestPOSManager(6, executable)
	fmt.Println("staking addr", types.CACertListAddress)
}
