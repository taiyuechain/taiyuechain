package math

import (
	"fmt"
	"github.com/taiyuechain/taiyuechain/accounts/abi"
	"github.com/taiyuechain/taiyuechain/accounts/abi/bind"
	"github.com/taiyuechain/taiyuechain/accounts/abi/bind/backends"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/consensus/minerva"
	"github.com/taiyuechain/taiyuechain/core"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/core/vm"
	"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/log"
	"github.com/taiyuechain/taiyuechain/params"
	"github.com/taiyuechain/taiyuechain/taidb"
	"math/big"
	"os"
	"strings"
	"testing"
)

func init() {
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlTrace, log.StreamHandler(os.Stderr, log.TerminalFormat(false))))
}

var (
	pbft1Name = "pbft1priv"
	pbft2Name = "pbft2priv"
	pbft3Name = "pbft3priv"
	pbft4Name = "pbft4priv"
	p2p1Name  = "p2p1cert"
	p2p2Name  = "p2p2cert"
	pbft1path = "../../cim/testdata/testcert/" + pbft1Name + ".pem"
	pbft2path = "../../cim/testdata/testcert/" + pbft2Name + ".pem"
	pbft3path = "../../cim/testdata/testcert/" + pbft3Name + ".pem"
	pbft4path = "../../cim/testdata/testcert/" + pbft4Name + ".pem"
	p2p1path  = "../../cim/testdata/testcert/" + p2p1Name + ".pem"
	p2p2path  = "../../cim/testdata/testcert/" + p2p2Name + ".pem"

	engine   = minerva.NewFaker()
	db       = taidb.NewMemDatabase()
	gspec    = DefaulGenesisBlock()
	abiCA, _ = abi.JSON(strings.NewReader(vm.CACertStoreABIJSON))
	signer   = types.NewSigner(gspec.Config.ChainID)

	//p2p 1
	priKey, _ = crypto.HexToECDSA("41c8bcf352894b132db095b0ef67b1c7ea9f4d7afd72a36b16c62c9fc582a5df")
	// p2p 2
	skey1, _ = crypto.HexToECDSA("200854f6bdcd2f94ecf97805ec95f340026375b347a6efe6913d5287afbabeed")
	// pbft 1
	dkey1, _ = crypto.HexToECDSA("8c2c3567667bf29509afabb7e1178e8a40a849b0bd22e0455cff9bab5c97a247")
	mAccount = crypto.PubkeyToAddress(priKey.PublicKey)
	saddr1   = crypto.PubkeyToAddress(skey1.PublicKey)
	daddr1   = crypto.PubkeyToAddress(dkey1.PublicKey)

	p2p1Byte, _  = crypto.ReadPemFileByPath(p2p1path)
	p2p2Byte, _  = crypto.ReadPemFileByPath(p2p2path)
	pbft1Byte, _ = crypto.ReadPemFileByPath(pbft1path)
	pbft2Byte, _ = crypto.ReadPemFileByPath(pbft2path)
	pbft3Byte, _ = crypto.ReadPemFileByPath(pbft3path)
	pbft4Byte, _ = crypto.ReadPemFileByPath(pbft4path)
)

func DefaulGenesisBlock() *core.Genesis {
	i, _ := new(big.Int).SetString("10000000000000000000000", 10)
	key1 := crypto.FromECDSAPub(&dkey1.PublicKey)
	prikey2, _ := crypto.HexToECDSA("f7f9ffe124547d3375765539aa3ccb4533057903e18f034045d233e547506d4e")
	key2 := crypto.FromECDSAPub(&prikey2.PublicKey)
	prikey3, _ := crypto.HexToECDSA("acac261a29d3abdff1a96859cebaacdf73744279986349a3f8bc98884fccb641")
	key3 := crypto.FromECDSAPub(&prikey3.PublicKey)
	prikey4, _ := crypto.HexToECDSA("7decea0bad634a9cfcaf5442321a2668b791c064f48c1f7a2112624d022fc5eb")
	key4 := crypto.FromECDSAPub(&prikey4.PublicKey)

	var certList = [][]byte{pbft1Byte, pbft2Byte, pbft3Byte, pbft4Byte}
	coinbase := daddr1

	return &core.Genesis{
		Config:     params.DevnetChainConfig,
		Nonce:      928,
		ExtraData:  nil,
		GasLimit:   88080384,
		Difficulty: big.NewInt(20000),
		Alloc: map[common.Address]types.GenesisAccount{
			mAccount: {Balance: i},
		},
		Committee: []*types.CommitteeMember{
			&types.CommitteeMember{Coinbase: coinbase, Publickey: key1, LocalCert: pbft1Byte},
			&types.CommitteeMember{Coinbase: coinbase, Publickey: key2, LocalCert: pbft2Byte},
			&types.CommitteeMember{Coinbase: coinbase, Publickey: key3, LocalCert: pbft3Byte},
			&types.CommitteeMember{Coinbase: coinbase, Publickey: key4, LocalCert: pbft4Byte},
		},
		CertList: certList,
	}
}

func TestMath(t *testing.T) {
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
	fmt.Println("11111111111111111111111111111111111111111111111111111111111111111111111111111")
	_, err = ens.Add(transactOpts, big.NewInt(50000))
	if err != nil {
		log.Error("Failed to request token transfer", ": %v", err)
	}
	fmt.Println("2222222222222222222222222222222222222222222222222222222222222222222222222222222")

	//fmt.Printf("Transfer pending: 0x%x\n", tx.Hash())
	contractBackend.Commit()
}
