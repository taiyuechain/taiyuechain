package test

import (
	"encoding/hex"
	"fmt"
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
	skey, _ := crypto.GenerateKey()
	saddr := crypto.PubkeyToAddress(skey.PublicKey)

	fmt.Println("saddr", crypto.AddressToHex(saddr), "priv",hex.EncodeToString(crypto.FromECDSA(skey)))
}
