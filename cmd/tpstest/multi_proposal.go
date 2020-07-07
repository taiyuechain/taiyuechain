package main

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/taiyuechain/taiyuechain/cim"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/consensus/minerva"
	"github.com/taiyuechain/taiyuechain/core"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/core/vm"
	"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/metrics"
	"github.com/taiyuechain/taiyuechain/params"
	"github.com/taiyuechain/taiyuechain/yuedb"
	"time"

	taicert "github.com/taiyuechain/taiyuechain/cert"
	"gopkg.in/urfave/cli.v1"
	"io/ioutil"
	"log"
	"math/big"
)

var (
	pbft1Name = "pbft1priv"
	pbft2Name = "pbft2priv"
	pbft3Name = "pbft3priv"
	pbft4Name = "pbft4priv"
	p2p1Name  = "p2p1cert"
	p2p2Name  = "p2p2cert"
	pbft1path =  pbft1Name + ".pem"
	pbft2path =  pbft2Name + ".pem"
	pbft3path =  pbft3Name + ".pem"
	pbft4path =  pbft4Name + ".pem"
	p2p1path  =  p2p1Name + ".pem"
	p2p2path  =  p2p2Name + ".pem"

	db     = yuedb.NewMemDatabase()
	gspec  = DefaulGenesisBlock()
	signer = types.NewSigner(gspec.Config.ChainID)

	//p2p 1
	pKey1, _ = crypto.HexToECDSA("d5939c73167cd3a815530fd8b4b13f1f5492c1c75e4eafb5c07e8fb7f4b09c7c")
	// p2p 2
	pKey2, _ = crypto.HexToECDSA("ea4297749d514cc476fe971a7fe20100cbd29f010864341b3e624e8744d46cec")
	// pbft 1
	prikey1, _ = crypto.HexToECDSA("7631a11e9d28563cdbcf96d581e4b9a19e53ad433a53c25a9f18c74ddf492f75")
	prikey2, _ = crypto.HexToECDSA("f7f9ffe124547d3375765539aa3ccb4533057903e18f034045d233e547506d4e")
	prikey3, _ = crypto.HexToECDSA("acac261a29d3abdff1a96859cebaacdf73744279986349a3f8bc98884fccb641")
	prikey4, _ = crypto.HexToECDSA("7decea0bad634a9cfcaf5442321a2668b791c064f48c1f7a2112624d022fc5eb")

	pAccount1 = crypto.PubkeyToAddress(pKey1.PublicKey)

	p2p1Byte, _  = taicert.ReadPemFileByPath(p2p1path)
	pbft1Byte, _ = taicert.ReadPemFileByPath(pbft1path)
	pbft2Byte, _ = taicert.ReadPemFileByPath(pbft2path)
	pbft3Byte, _ = taicert.ReadPemFileByPath(pbft3path)
	pbft4Byte, _ = taicert.ReadPemFileByPath(pbft4path)
)

func DefaulGenesisBlock() *core.Genesis {
	i, _ := new(big.Int).SetString("10000000000000000000000", 10)
	key1 := crypto.FromECDSAPub(&prikey1.PublicKey)
	key2 := crypto.FromECDSAPub(&prikey2.PublicKey)
	key3 := crypto.FromECDSAPub(&prikey3.PublicKey)
	key4 := crypto.FromECDSAPub(&prikey4.PublicKey)

	var certList = [][]byte{pbft1Byte, pbft2Byte, pbft3Byte, pbft4Byte}
	coinbase := pAccount1

	return &core.Genesis{
		Config:              params.DevnetChainConfig,
		ExtraData:           nil,
		GasLimit:            88080384,
		UseGas:              1,
		IsCoin:              1,
		KindOfCrypto:        2,
		PermisionWlSendTx:   1,
		PermisionWlCreateTx: 1,
		Timestamp:           1537891200,
		Alloc: map[common.Address]types.GenesisAccount{
			pAccount1: {Balance: i},
		},
		Committee: []*types.CommitteeMember{
			&types.CommitteeMember{Coinbase: coinbase, Publickey: key1},
			&types.CommitteeMember{Coinbase: coinbase, Publickey: key2},
			&types.CommitteeMember{Coinbase: coinbase, Publickey: key3},
			&types.CommitteeMember{Coinbase: coinbase, Publickey: key4},
		},
		CertList: certList,
	}
}

type ChainParams struct {
	Verify   bool
	BlockTxs uint64
	Accounts uint64
}

func proposal(ctx *cli.Context) error {

	var cp  ChainParams
	if ctx.GlobalIsSet(VerifyBlockFlag.Name) {
		cp.Verify = true
	}

	initBlockChain(cp)
	return nil
}

func initBlockChain(cp ChainParams) {
	//new cimList
	cimList := cim.NewCIMList(uint8(crypto.CryptoType))
	engine := minerva.NewFaker(cimList)

	genesis := gspec.MustCommit(db)
	blockchain, _ := core.NewBlockChain(db, nil, gspec.Config, engine, vm.Config{}, cimList)
	//init cert list to
	// need init cert list to statedb
	stateDB, err := blockchain.State()
	if err != nil {
		panic(err)
	}
	err = cimList.InitCertAndPermission(blockchain.CurrentBlock().Number(), stateDB)
	if err != nil {
		panic(err)
	}

	if cp.Accounts > 0 {
		sendNumber := int(cp.Accounts)
		delegateKey := make([]*ecdsa.PrivateKey, sendNumber)
		delegateAddr := make([]common.Address, sendNumber)
		for i := 0; i < sendNumber; i++ {
			delegateKey[i], _ = crypto.GenerateKey()
			delegateAddr[i] = crypto.PubkeyToAddress(delegateKey[i].PublicKey)
		}
	}

	var txs []*types.Transaction
	nonce := stateDB.GetNonce(pAccount1)
	for i := 0; i < 2000 ; i++ {
		tx := addTx(nonce,pKey1,signer,p2p1Byte)
		txs = append(txs,tx)
		nonce++
	}
	fmt.Println("Produce txs ",len(txs))

	tpsMetrics := metrics.NewRegisteredMeter("tps", nil)
	t0 := time.Now()
	t1 := t0
	usedIndex := 0
	find := false
	core.GenerateChain(gspec.Config, genesis, engine, db, 50, func(i int, gen *core.BlockGen) {
		for i := 0; i < 400 ; i++ {
			if i + usedIndex < 2000 {
				gen.AddTx(txs[i+ usedIndex])
			}
		}
		usedIndex = usedIndex + 400

		old := gen.PrevBlock(i-1)
		tpsMetrics.Mark(2000)
		if cp.Verify {
			current := blockchain.CurrentBlock().Number().Uint64()
			if old.NumberU64() == current+1 {
				if _, err := blockchain.InsertChain(types.Blocks{old}); err != nil {
					panic(err)
				}
			}
		}
		fmt.Println("number",gen.Number()," ",common.PrettyDuration(time.Since(t1)))
		if old.NumberU64() > 0 && len(old.Transactions()) == 0 && !find {
			fmt.Println(time.Since(t1)/1000,"tps",tpsMetrics.RateMean())
			tpsMetrics.Stop()
			find = true
		}
		t1 = time.Now()
	})
	fmt.Println("times ",common.PrettyDuration(time.Since(t0)))
}

func addTx(nonce uint64, priKey *ecdsa.PrivateKey, signer types.Signer, cert []byte) *types.Transaction {
	tx, err := types.SignTx(types.NewTransaction(nonce, common.BytesToAddress([]byte("1234")), new(big.Int).SetInt64(1000), params.TxGas, big.NewInt(1000000000), nil, cert), signer, priKey)
	if err != nil {
		panic(err)
	}
	return tx
}

func getAllFile(path string) (string, error) {
	rd, err := ioutil.ReadDir(path)
	if err != nil {
		printError("path ", err)
	}
	for _, fi := range rd {
		if fi.IsDir() {
			fmt.Printf("[%s]\n", path+"\\"+fi.Name())
			getAllFile(path + fi.Name() + "\\")
			return "", errors.New("path error")
		} else {
			fmt.Println(path, "dir has ", fi.Name(), "file")
			return fi.Name(), nil
		}
	}
	return "", err
}

func printError(error ...interface{}) {
	log.Fatal(error)
}

func getPubFromFile(certfile string) ([]byte, *ecdsa.PublicKey) {
	if !common.FileExist(certfile) {
		printError("cert file not exist", certfile)
	}
	certByte, err := taicert.ReadPemFileByPath(certfile)
	if err != nil {
		printError("can't read cert from file ", certfile)
	}
	pub, err := taicert.FromCertBytesToPubKey(certByte)
	if err != nil {
		printError("cert convert to pub, no correct cert file", certfile)
	}
	return certByte, pub
}
