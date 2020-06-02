package math

import (
	"encoding/hex"
	"fmt"
	"github.com/taiyuechain/taiyuechain/accounts/abi/bind"
	"github.com/taiyuechain/taiyuechain/accounts/abi/bind/backends"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/core"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/log"
	"github.com/taiyuechain/taiyuechain/params"
	"golang.org/x/crypto/sha3"
	"math/big"
	"os"
	"testing"
)

func init() {
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlTrace, log.StreamHandler(os.Stderr, log.TerminalFormat(false))))
}

var (
	pbft1Name = "pbft1priv"
	p2p1Name  = "p2p1cert"
	pbft1path = "../testcert/" + pbft1Name + ".pem"
	p2p1path  = "../testcert/" + p2p1Name + ".pem"

	gspec = DefaulGenesisBlock()

	//p2p 1
	priKey, _ = crypto.HexToECDSA("d5939c73167cd3a815530fd8b4b13f1f5492c1c75e4eafb5c07e8fb7f4b09c7c")
	// p2p 2
	skey1, _ = crypto.HexToECDSA("ea4297749d514cc476fe971a7fe20100cbd29f010864341b3e624e8744d46cec")
	// pbft 1
	dkey1, _ = crypto.HexToECDSA("7631a11e9d28563cdbcf96d581e4b9a19e53ad433a53c25a9f18c74ddf492f75")
	mAccount = crypto.PubkeyToAddress(priKey.PublicKey)
	saddr1   = crypto.PubkeyToAddress(skey1.PublicKey)
	daddr1   = crypto.PubkeyToAddress(dkey1.PublicKey)

	p2p1Byte, _  = crypto.ReadPemFileByPath(p2p1path)
	pbft1Byte, _ = crypto.ReadPemFileByPath(pbft1path)
)

func DefaulGenesisBlock() *core.Genesis {
	i, _ := new(big.Int).SetString("10000000000000000000000", 10)
	key1 := crypto.FromECDSAPub(&dkey1.PublicKey)

	var certList = [][]byte{pbft1Byte}
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
		},
		CertList: certList,
	}
}

func TestMath(t *testing.T) {
	contractBackend := backends.NewSimulatedBackend(gspec, 10000000)
	transactOpts := bind.NewKeyedTransactor(priKey, p2p1Byte, gspec.Config.ChainID)

	// Deploy the ENS registry
	ensAddr, _, _, err := DeployMath(transactOpts, contractBackend)
	if err != nil {
		t.Fatalf("can't DeployContract: %v", err)
	}
	ens, err := NewMath(ensAddr, contractBackend)
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

func TestMethod(t *testing.T) {
	method := []byte("add(uint256)")
	sig := crypto.Keccak256(method)[:4]
	fmt.Println(" ", hex.EncodeToString(sig))
	d := sha3.NewLegacyKeccak256()
	d.Write(method)
	fmt.Println(" ", hex.EncodeToString(d.Sum(nil)[:4]))
}
