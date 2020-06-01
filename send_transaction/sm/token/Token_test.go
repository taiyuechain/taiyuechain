package test

import (
	"fmt"
	"github.com/taiyuechain/taiyuechain/accounts/abi/bind"
	"github.com/taiyuechain/taiyuechain/accounts/abi/bind/backends"
	"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/log"
	"math/big"
	"os"
	"testing"
)

func init() {
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlTrace, log.StreamHandler(os.Stderr, log.TerminalFormat(false))))
}

func TestENS(t *testing.T) {
	contractBackend := backends.NewSimulatedBackend(gspec, 10000000)
	transactOpts := bind.NewKeyedTransactor(priKey, p2p1Byte, gspec.Config.ChainID)

	// Deploy the ENS registry
	ensAddr, _, _, err := DeployToken(transactOpts, contractBackend)
	if err != nil {
		t.Fatalf("can't DeployContract: %v", err)
	}
	ens, err := NewToken(ensAddr, contractBackend)
	if err != nil {
		t.Fatalf("can't NewContract: %v", err)
	}
	fmt.Println("ensAddr ", crypto.AddressToHex(ensAddr))
	contractBackend.Commit()

	// Set ourself as the owner of the name.
	var name string
	err = ens.TokenCaller.contract.Call(nil, &name, "name")
	if err != nil {
		log.Error("Failed to retrieve token ", "name: %v", err)
	}
	fmt.Println("Token name:", name)

	var totalSupply *big.Int
	err = ens.TokenCaller.contract.Call(nil, &totalSupply, "totalSupply")
	if err != nil {
		log.Error("Failed to retrieve token ", "name: %v", err)
	}
	fmt.Println("totalSupply ", totalSupply)

	//tx, err := ens.Transfer(transactOpts, saddr1, big.NewInt(50000))
	//fmt.Println("tx ",tx)
	//if err != nil {
	//	log.Error("Failed to request token transfer", ": %v", err)
	//}
	//fmt.Printf("Transfer pending: 0x%x\n", tx.Hash())
	contractBackend.Commit()
}
