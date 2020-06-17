package test

import (
	"github.com/taiyuechain/taiyuechain/cim"
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
func TestGrantPermission(t *testing.T) {
	// Create a helper to check if a gas allowance results in an executable transaction
	executable := func(number uint64, gen *core.BlockGen, fastChain *core.BlockChain, header *types.Header, statedb *state.StateDB, cimList *cim.CimList) {
		sendTranction(number, gen, statedb, mAccount, saddr1, big.NewInt(6000000000000000000), priKey, signer, nil, header, pbft1Byte, cimList)
		sendTranction(number-1, gen, statedb, saddr1, saddr4, big.NewInt(5000000000000000000), prikey2, signer, nil, header, pbft2Byte, cimList)
		sendGrantPermissionTranscation(number, gen, saddr1, saddr4, prikey2, signer, statedb, fastChain, abiCA, nil, pbft2Byte)

		sendTranction(number-1-25, gen, statedb, saddr4, saddr1, big.NewInt(1000000000000000000), skey4, signer, nil, header, p2p4Byte, cimList)
		sendRevokePermissionTranscation(number, gen, saddr1, saddr4, prikey2, signer, statedb, fastChain, abiCA, nil, pbft2Byte)
		sendTranction(number-40, gen, statedb, saddr4, saddr1, big.NewInt(1000000000000000000), skey4, signer, nil, header, p2p4Byte, cimList)
	}
	newTestPOSManager(6, executable)
}

//neo test cacert contract
func TestCreateGroupPermission(t *testing.T) {
	gropAddr := crypto.CreateGroupkey(saddr4, 3)
	// Create a helper to check if a gas allowance results in an executable transaction
	executable := func(number uint64, gen *core.BlockGen, fastChain *core.BlockChain, header *types.Header, statedb *state.StateDB, cimList *cim.CimList) {
		sendTranction(number, gen, statedb, mAccount, saddr1, big.NewInt(6000000000000000000), priKey, signer, nil, header, pbft1Byte, cimList)
		sendTranction(number-1, gen, statedb, saddr1, saddr4, big.NewInt(5000000000000000000), prikey2, signer, nil, header, pbft2Byte, cimList)
		sendGrantPermissionTranscation(number, gen, saddr1, saddr4, prikey2, signer, statedb, fastChain, abiCA, nil, pbft2Byte)

		sendCreateGroupPermissionTranscation(number, gen, saddr4, "CA", skey4, signer, statedb, fastChain, abiCA, nil, p2p4Byte)
		sendDelGroupPermissionTranscation(number, gen, saddr4, gropAddr, skey4, signer, statedb, fastChain, abiCA, nil, p2p4Byte)
	}
	newTestPOSManager(6, executable)
}
