package test

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/taiyuechain/taiyuechain/cim"

	"strings"

	"github.com/taiyuechain/taiyuechain/accounts/abi"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/consensus/minerva"
	"github.com/taiyuechain/taiyuechain/core"
	"github.com/taiyuechain/taiyuechain/core/state"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/core/vm"
	"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/log"
	"github.com/taiyuechain/taiyuechain/params"
	"github.com/taiyuechain/taiyuechain/yuedb"
	taicert "github.com/taiyuechain/taiyuechain/cert"
)

var (
	pbft1Name = "pbft1priv"
	pbft2Name = "pbft2priv"
	pbft3Name = "pbft3priv"
	pbft4Name = "pbft4priv"
	p2p1Name  = "p2p1cert"
	p2p2Name  = "p2p2cert"
	pbft1path = "../testcert/" + pbft1Name + ".pem"
	pbft2path = "../testcert/" + pbft2Name + ".pem"
	pbft3path = "../testcert/" + pbft3Name + ".pem"
	pbft4path = "../testcert/" + pbft4Name + ".pem"
	p2p1path  = "../testcert/" + p2p1Name + ".pem"
	p2p2path  = "../testcert/" + p2p2Name + ".pem"

	db       = yuedb.NewMemDatabase()
	gspec    = DefaulGenesisBlock()
	abiCA, _ = abi.JSON(strings.NewReader(vm.CACertStoreABIJSON))
	signer   = types.NewSigner(gspec.Config.ChainID)

	//p2p 1
	priKey, _ = crypto.HexToECDSA("d5939c73167cd3a815530fd8b4b13f1f5492c1c75e4eafb5c07e8fb7f4b09c7c")
	// p2p 2
	skey1, _ = crypto.HexToECDSA("ea4297749d514cc476fe971a7fe20100cbd29f010864341b3e624e8744d46cec")
	// pbft 1
	dkey1, _ = crypto.HexToECDSA("7631a11e9d28563cdbcf96d581e4b9a19e53ad433a53c25a9f18c74ddf492f75")
	mAccount = crypto.PubkeyToAddress(priKey.PublicKey)
	saddr1   = crypto.PubkeyToAddress(skey1.PublicKey)
	daddr1   = crypto.PubkeyToAddress(dkey1.PublicKey)

	p2p1Byte, _  = taicert.ReadPemFileByPath(p2p1path)
	p2p2Byte, _  = taicert.ReadPemFileByPath(p2p2path)
	pbft1Byte, _ = taicert.ReadPemFileByPath(pbft1path)
	pbft2Byte, _ = taicert.ReadPemFileByPath(pbft2path)
	pbft3Byte, _ = taicert.ReadPemFileByPath(pbft3path)
	pbft4Byte, _ = taicert.ReadPemFileByPath(pbft4path)
	pbft5Name    = "pbft5priv"
	pbft5path    = "../testcert/" + pbft5Name + ".pem"
	pbft5Byte, _ = taicert.ReadPemFileByPath(pbft5path)

	p2p5Name    = "p2p5cert"
	p2p5path    = "../testcert/" + p2p5Name + ".pem"
	p2p5Byte, _ = taicert.ReadPemFileByPath(p2p5path)
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
		Config:       params.DevnetChainConfig,
		ExtraData:    nil,
		GasLimit:     88080384,
		UseGas:       0,
		BaseReward:   0,
		KindOfCrypto: 2,
		Timestamp:    1537891200,
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

func newTestPOSManager(sBlocks int, executableTx func(uint64, *core.BlockGen, *core.BlockChain, *types.Header, *state.StateDB, *cim.CimList)) {

	//new cimList
	cimList := cim.NewCIMList(uint8(crypto.CryptoType))
	engine   := minerva.NewFaker(cimList)

	params.MinTimeGap = big.NewInt(0)
	params.SnailRewardInterval = big.NewInt(3)

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
	chain, _ := core.GenerateChain(gspec.Config, genesis, engine, db, sBlocks*60, func(i int, gen *core.BlockGen) {

		header := gen.GetHeader()
		stateDB := gen.GetStateDB()
		executableTx(header.Number.Uint64(), gen, blockchain, header, stateDB,cimList)
	})
	if _, err := blockchain.InsertChain(chain); err != nil {
		panic(err)
	}
}

//neo test
func sendAddCaCertTranscation(height uint64, gen *core.BlockGen, from common.Address, cert []byte, priKey *ecdsa.PrivateKey, signer types.Signer, state *state.StateDB, blockchain *core.BlockChain, abiStaking abi.ABI, txPool txPool, txCert []byte) {
	if height == 20 {
		log.Info("sendAddCaCertTranscation", "blockNumber", height)
		nonce, _ := getNonce(gen, from, state, "sendAddCaCertTranscation", txPool)
		//input := packInput(abiCA, "deposit", "sendAddCaCertTranscation", pub, new(big.Int).SetInt64(5000), value)
		input := packInput(abiStaking, "addCaCert", "sendAddCaCertTranscation", cert)

		addTx(gen, blockchain, nonce, nil, input, txPool, priKey, signer, txCert)
	}
}

//neo test
func sendDelCaCertTranscation(height uint64, gen *core.BlockGen, from common.Address, cert []byte, priKey *ecdsa.PrivateKey, signer types.Signer, state *state.StateDB, blockchain *core.BlockChain, abiStaking abi.ABI, txPool txPool, txCert []byte) {
	if height == 40 {
		nonce, _ := getNonce(gen, from, state, "sendDelCaCertTranscation", txPool)
		//input := packInput(abiCA, "deposit", "sendDelCaCertTranscation", pub, new(big.Int).SetInt64(5000), value)
		input := packInput(abiStaking, "delCaCert", "sendDelCaCertTranscation", cert)

		addTx(gen, blockchain, nonce, nil, input, txPool, priKey, signer, txCert)
	}
}

//neo test
func sendGetCaCertAmountTranscation(height uint64, gen *core.BlockGen, from common.Address, cert []byte, priKey *ecdsa.PrivateKey, signer types.Signer, state *state.StateDB, blockchain *core.BlockChain, abiStaking abi.ABI, txPool txPool, txCert []byte) {
	if height == 25 {
		input := packInput(abiStaking, "getCaAmount", "sendGetCaCertAmountTranscation")
		var args uint64
		readTx(gen, blockchain, 0, big.NewInt(0), input, txPool, priKey, signer, "getCaAmount", &args, txCert)
		printTest("---get Cert Amount is ", "arges = ", args)

	}
}

//neo test
func sendMultiProposalTranscation(height uint64, gen *core.BlockGen, from common.Address, cert []byte, certPar []byte, isAdd bool, priKey *ecdsa.PrivateKey, signer types.Signer, state *state.StateDB, blockchain *core.BlockChain, abiStaking abi.ABI, txPool txPool, txCert []byte) {
	if height == 40 {
		nonce, _ := getNonce(gen, from, state, "sendMultiProposalTranscation", txPool)
		fmt.Println("multiProposal ", hex.EncodeToString(cert), " ", hex.EncodeToString(certPar))
		input := packInput(abiStaking, "multiProposal", "sendMultiProposalTranscation", certPar, cert, isAdd)
		addTx(gen, blockchain, nonce, nil, input, txPool, priKey, signer, txCert)
	}
}

//neo test
func sendIsApproveCACertTranscation(height uint64, gen *core.BlockGen, from common.Address, cert []byte, priKey *ecdsa.PrivateKey, signer types.Signer, state *state.StateDB, blockchain *core.BlockChain, abiStaking abi.ABI, txPool txPool, txCert []byte) {
	if height == 30 {
		input := packInput(abiStaking, "isApproveCaCert", "sendIsApproveCACertTranscation", cert)
		var args bool
		readTx(gen, blockchain, 0, big.NewInt(0), input, txPool, priKey, signer, "isApproveCaCert", &args, txCert)
		printTest("get Cert Amount is ", args)
	}
}

func addTx(gen *core.BlockGen, blockchain *core.BlockChain, nonce uint64, value *big.Int, input []byte, txPool txPool, priKey *ecdsa.PrivateKey, signer types.Signer, cert []byte) {
	//2426392 1000000000
	//866328  1000000
	//2400000
	tx, _ := types.SignTx(types.NewTransaction(nonce, types.CACertListAddress, value, 2446392, big.NewInt(1000000000), input, cert), signer, priKey)

	if gen != nil {
		gen.AddTxWithChain(blockchain, tx)
	} else {
		txPool.AddRemotes([]*types.Transaction{tx})
	}
}

func readTx(gen *core.BlockGen, blockchain *core.BlockChain, nonce uint64, value *big.Int, input []byte, txPool txPool, priKey *ecdsa.PrivateKey, signer types.Signer, abiMethod string, result interface{}, cert []byte) {
	tx, _ := types.SignTx(types.NewTransaction(nonce, types.CACertListAddress, value, 866328, big.NewInt(1000000), input, cert), signer, priKey)

	if gen != nil {
		output, gas := gen.ReadTxWithChain(blockchain, tx)
		err := abiCA.Unpack(result, abiMethod, output)
		if err != nil {
			printTest(abiMethod, " error ", err)
		}
		printTest("readTx gas ", gas)
	} else {
		txPool.AddRemotes([]*types.Transaction{tx})
	}
}
func packInput(abiStaking abi.ABI, abiMethod, method string, params ...interface{}) []byte {
	input, err := abiStaking.Pack(abiMethod, params...)
	if err != nil {
		printTest(method, " error ", err)
	}
	return input
}

type txPool interface {
	// AddRemotes should add the given transactions to the pool.
	AddRemotes([]*types.Transaction) []error
	State() *state.ManagedState
}

func printTest(a ...interface{}) {
	log.Info("test", "SendTX", a)
}

func getNonce(gen *core.BlockGen, from common.Address, state1 *state.StateDB, method string, txPool txPool) (uint64, *state.StateDB) {
	var nonce uint64
	var stateDb *state.StateDB
	if gen != nil {
		nonce = gen.TxNonce(from)
		stateDb = gen.GetStateDB()
	} else {
		stateDb = state1
		nonce = txPool.State().GetNonce(from)
	}
	return nonce, stateDb
}

func sendTranction(height uint64, gen *core.BlockGen, state *state.StateDB, from, to common.Address, value *big.Int, privateKey *ecdsa.PrivateKey, signer types.Signer, txPool txPool, header *types.Header, cert []byte) {
	if height == 10 {
		nonce, statedb := getNonce(gen, from, state, "sendTranction", txPool)
		balance := statedb.GetBalance(to)
		remaining := new(big.Int).Sub(value, balance)
		printTest("sendTranction ", balance.Uint64(), " remaining ", remaining.Uint64(), " height ", height, " current ", header.Number.Uint64(), " from ", types.ToTai(state.GetBalance(from)))
		if remaining.Sign() > 0 {
			tx, _ := types.SignTx(types.NewTransaction(nonce, to, remaining, params.TxGas, new(big.Int).SetInt64(1000000), nil, cert), signer, privateKey)
			if gen != nil {
				gen.AddTx(tx)
			} else {
				txPool.AddRemotes([]*types.Transaction{tx})
			}
		} else {
			printTest("to ", crypto.AddressToHex(to), " have balance ", balance.Uint64(), " height ", height, " current ", header.Number.Uint64())
		}
	}
}
