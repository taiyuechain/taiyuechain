package test

import (
	"crypto/ecdsa"
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
)

var (
	pbft1Name = "pbft1priv"
	pbft2Name = "pbft2priv"
	pbft3Name = "pbft3priv"
	pbft4Name = "pbft4priv"
	pbft1path = "../testcert/" + pbft1Name + ".pem"
	pbft2path = "../testcert/" + pbft2Name + ".pem"
	pbft3path = "../testcert/" + pbft3Name + ".pem"
	pbft4path = "../testcert/" + pbft4Name + ".pem"

	engine   = minerva.NewFaker()
	db       = yuedb.NewMemDatabase()
	gspec    = DefaulGenesisBlock()
	abiCA, _ = abi.JSON(strings.NewReader(vm.PermissionABIJSON))
	signer   = types.NewSigner(gspec.Config.ChainID)

	// pbft 1
	priKey, _ = crypto.HexToECDSA("7631a11e9d28563cdbcf96d581e4b9a19e53ad433a53c25a9f18c74ddf492f75")
	// pbft 2
	prikey2, _ = crypto.HexToECDSA("bab8dbdcb4d974eba380ff8b2e459efdb6f8240e5362e40378de3f9f5f1e67bb")
	// pbft 3
	prikey3, _ = crypto.HexToECDSA("122d186b77a030e04f5654e13d934b21af2aac03b942c3ecda4632364d81cbab")
	mAccount   = crypto.PubkeyToAddress(priKey.PublicKey)
	saddr1     = crypto.PubkeyToAddress(prikey2.PublicKey)
	daddr1     = crypto.PubkeyToAddress(prikey3.PublicKey)

	pbft1Byte, _ = crypto.ReadPemFileByPath(pbft1path)
	pbft2Byte, _ = crypto.ReadPemFileByPath(pbft2path)
	pbft3Byte, _ = crypto.ReadPemFileByPath(pbft3path)
	pbft4Byte, _ = crypto.ReadPemFileByPath(pbft4path)

	skey5, _ = crypto.HexToECDSA("77b4e6383502fd145cae5c2f8db28a9b750394bd70c0c138b915bb1327225489")
	saddr5   = crypto.PubkeyToAddress(skey5.PublicKey)

	pbft5Name    = "pbft5priv"
	pbft5path    = "../testcert/" + pbft5Name + ".pem"
	pbft5Byte, _ = crypto.ReadPemFileByPath(pbft5path)
)

func DefaulGenesisBlock() *core.Genesis {
	i, _ := new(big.Int).SetString("10000000000000000000000", 10)
	key1 := crypto.FromECDSAPub(&priKey.PublicKey)
	key2 := crypto.FromECDSAPub(&prikey2.PublicKey)
	key3 := crypto.FromECDSAPub(&prikey3.PublicKey)
	prikey4, _ := crypto.HexToECDSA("fe44cbc0e164092a6746bd57957422ab165c009d0299c7639a2f4d290317f20f")
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

func newTestPOSManager(sBlocks int, executableTx func(uint64, *core.BlockGen, *core.BlockChain, *types.Header, *state.StateDB)) {

	//new cimList
	cimList := cim.NewCIMList(uint8(crypto.CryptoType))

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
	caCertList := vm.NewCACertList()
	err = caCertList.LoadCACertList(stateDB, types.CACertListAddress)
	height := blockchain.CurrentBlock().Number()
	epoch := types.GetEpochIDFromHeight(height)
	cimList.SetCertEpoch(epoch)
	for _, caCert := range caCertList.GetCACertMapByEpoch(epoch.Uint64()).CACert {
		cimCa, err := cim.NewCIM()
		if err != nil {
			panic(err)
		}

		cimCa.SetUpFromCA(caCert)
		cimList.AddCim(cimCa)
	}
	engine.SetCimList(cimList)

	chain, _ := core.GenerateChain(gspec.Config, genesis, engine, db, sBlocks*60, func(i int, gen *core.BlockGen) {

		header := gen.GetHeader()
		stateDB := gen.GetStateDB()
		executableTx(header.Number.Uint64(), gen, blockchain, header, stateDB)
	})
	if _, err := blockchain.InsertChain(chain); err != nil {
		panic(err)
	}
}

//neo test
func sendGrantPermissionTranscation(height uint64, gen *core.BlockGen, from, to common.Address, priKey *ecdsa.PrivateKey, signer types.Signer, state *state.StateDB, blockchain *core.BlockChain, abiStaking abi.ABI, txPool txPool, txCert []byte) {
	if height == 25 {
		nonce, _ := getNonce(gen, from, state, "grantPermission", txPool)
		input := packInput(abiStaking, "grantPermission", "grantPermission", from, to, common.Address{}, new(big.Int).SetInt64(int64(vm.ModifyPerminType_AddSendTxPerm)), false)
		addTx(gen, blockchain, nonce, nil, input, txPool, priKey, signer, txCert)
	}
}

//neo test
func sendRevokePermissionTranscation(height uint64, gen *core.BlockGen, from, to common.Address, priKey *ecdsa.PrivateKey, signer types.Signer, state *state.StateDB, blockchain *core.BlockChain, abiStaking abi.ABI, txPool txPool, txCert []byte) {
	if height == 30 {
		nonce, _ := getNonce(gen, from, state, "sendRevokePermissionTranscation", txPool)
		input := packInput(abiStaking, "revokePermission", "sendRevokePermissionTranscation", from, to, common.Address{}, new(big.Int).SetInt64(int64(vm.ModifyPerminType_DelSendTxPerm)), false)
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
	tx, _ := types.SignTx(types.NewTransaction(nonce, types.PermiTableAddress, value, 2446392, big.NewInt(1000000000), input, cert), signer, priKey)

	if gen != nil {
		gen.AddTxWithChain(blockchain, tx)
	} else {
		txPool.AddRemotes([]*types.Transaction{tx})
	}
}

func readTx(gen *core.BlockGen, blockchain *core.BlockChain, nonce uint64, value *big.Int, input []byte, txPool txPool, priKey *ecdsa.PrivateKey, signer types.Signer, abiMethod string, result interface{}, cert []byte) {
	tx, _ := types.SignTx(types.NewTransaction(nonce, types.PermiTableAddress, value, 866328, big.NewInt(1000000), input, cert), signer, priKey)

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
		printTest("sendTranction ", balance.Uint64(), " height ", height, " current ", header.Number.Uint64(), " from ", types.ToTai(state.GetBalance(from)))
		tx, _ := types.SignTx(types.NewTransaction(nonce, to, value, params.TxGas, new(big.Int).SetInt64(1000000), nil, cert), signer, privateKey)
		if gen != nil {
			gen.AddTx(tx)
		} else {
			txPool.AddRemotes([]*types.Transaction{tx})
		}
	}
}
