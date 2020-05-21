package test

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/taiyuechain/taiyuechain/accounts/abi"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/common/hexutil"
	"github.com/taiyuechain/taiyuechain/consensus/minerva"
	"github.com/taiyuechain/taiyuechain/core"
	"github.com/taiyuechain/taiyuechain/core/state"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/core/vm"
	"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/log"
	"github.com/taiyuechain/taiyuechain/params"
	"github.com/taiyuechain/taiyuechain/taidb"
	"strings"
)

var (
	engine    = minerva.NewFaker()
	db        = taidb.NewMemDatabase()
	gspec     = DefaulGenesisBlock()
	abiCA, _  = abi.JSON(strings.NewReader(vm.CACertStoreABIJSON))
	signer    = types.NewSigner(gspec.Config.ChainID)
	priKey, _ = crypto.HexToECDSA("0260c952edc49037129d8cabbe4603d15185d83aa718291279937fb6db0fa7a2")
	mAccount  = common.HexToAddress("0xC02f50f4F41f46b6a2f08036ae65039b2F9aCd69")
	skey1, _  = crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	saddr1    = crypto.PubkeyToAddress(skey1.PublicKey)
	dkey1, _  = crypto.HexToECDSA("49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee")
	daddr1    = crypto.PubkeyToAddress(dkey1.PublicKey)
)

func DefaulGenesisBlock() *core.Genesis {
	i, _ := new(big.Int).SetString("10000000000000000000000", 10)
	key1 := hexutil.MustDecode("0x04d341c94a16b02cee86a627d0f6bc6e814741af4cab5065637aa013c9a7d9f26051bb6546030cd67e440d6df741cb65debaaba6c0835579f88a282193795ed369")
	key2 := hexutil.MustDecode("0x0496e0f18d4bf38e0b0de161edd2aa168adaf6842706e5ebf31e1d46cb79fe7b720c750a9e7a3e1a528482b0da723b5dfae739379e555a2893e8693747559f83cd")
	key3 := hexutil.MustDecode("0x0418196ee090081bdec01e8840941b9f6a141a713dd3461b78825edf0d8a7f8cdf3f612832dc9d94249c10c72629ea59fbe0bdd09bea872ddab2799748964c93a8")
	key4 := hexutil.MustDecode("0x04c4935993a3ce206318ab884871fbe2d4dce32a022795c674784f58e7faf3239631b6952b82471fe1e93ef999108a18d028e5d456cd88bb367d610c5e57c7e443")

	return &core.Genesis{
		Config:     params.DevnetChainConfig,
		Nonce:      928,
		ExtraData:  nil,
		GasLimit:   88080384,
		Difficulty: big.NewInt(20000),
		Alloc: map[common.Address]types.GenesisAccount{
			common.HexToAddress("0xC02f50f4F41f46b6a2f08036ae65039b2F9aCd69"): {Balance: i},
			common.HexToAddress("0x6d348e0188Cc2596aaa4046a1D50bB3BA50E8524"): {Balance: i},
			common.HexToAddress("0xE803895897C3cCd35315b2E41c95F817543811A5"): {Balance: i},
			common.HexToAddress("0x3F739ffD8A59965E07e1B8d7CCa938125BCe8CFb"): {Balance: i},
		},
		Committee: []*types.CommitteeMember{
			{Coinbase: common.HexToAddress("0x3f9061bf173d8f096c94db95c40f3658b4c7eaad"), Publickey: key1},
			{Coinbase: common.HexToAddress("0x2cdac3658f85b5da3b70223cc3ad3b2dfe7c1930"), Publickey: key2},
			{Coinbase: common.HexToAddress("0x41acde8dd7611338c2a30e90149e682566716e9d"), Publickey: key3},
			{Coinbase: common.HexToAddress("0x0ffd116a3bf97a7112ff8779cc770b13ea3c66a5"), Publickey: key4},
		},
	}
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
	//printBalance(stateDb, from, method)
	return nonce, stateDb
}

func sendTranction(height uint64, gen *core.BlockGen, state *state.StateDB, from, to common.Address, value *big.Int, privateKey *ecdsa.PrivateKey, signer types.Signer, txPool txPool, header *types.Header) {
	if height == 10 {
		nonce, statedb := getNonce(gen, from, state, "sendTranction", txPool)
		balance := statedb.GetBalance(to)
		remaining := new(big.Int).Sub(value, balance)
		printTest("1----sendTranction ", balance.Uint64(), " remaining ", remaining.Uint64(), " height ", height, " current ", header.Number.Uint64())
		if remaining.Sign() > 0 {
			//tx, _ := types.SignTx(types.NewTransaction(nonce, to, remaining, params.TxGas, new(big.Int).SetInt64(1000000), nil), signer, privateKey)
			tx, _ := types.SignTx(types.NewTransaction(nonce, to, remaining, params.TxGas, new(big.Int).SetInt64(0), nil, nil), signer, privateKey)
			if gen != nil {
				gen.AddTx(tx)
			} else {
				txPool.AddRemotes([]*types.Transaction{tx})
			}
		} else {
			printTest("to ", to.String(), " have balance ", balance.Uint64(), " height ", height, " current ", header.Number.Uint64())
		}
	}
}

func newTestPOSManager(sBlocks int, executableTx func(uint64, *core.BlockGen, *core.BlockChain, *types.Header, *state.StateDB)) {

	params.MinTimeGap = big.NewInt(0)
	params.SnailRewardInterval = big.NewInt(3)
	params.ElectionMinLimitForStaking = new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18))

	//gspec.Config.TIP7 = &params.BlockConfig{FastNumber: big.NewInt(0)}
	//gspec.Config.TIP8 = &params.BlockConfig{FastNumber: big.NewInt(0), CID: big.NewInt(-1)}

	genesis := gspec.MustFastCommit(db)
	blockchain, _ := core.NewBlockChain(db, nil, gspec.Config, engine, vm.Config{})

	parentFast := genesis
	for i := 0; i < sBlocks; i++ {

		chain, _ := core.GenerateChain(gspec.Config, parentFast, engine, db, 60, func(i int, gen *core.BlockGen) {

			header := gen.GetHeader()
			stateDB := gen.GetStateDB()
			executableTx(header.Number.Uint64(), gen, blockchain, header, stateDB)
		})
		if _, err := blockchain.InsertChain(chain); err != nil {
			panic(err)
		}
	}
}

//neo test
func sendAddCaCertTranscation(height uint64, gen *core.BlockGen, from common.Address, cert []byte, priKey *ecdsa.PrivateKey, signer types.Signer, state *state.StateDB, blockchain *core.BlockChain, abiStaking abi.ABI, txPool txPool) {
	if height == 20 {
		log.Info("sendAddCaCertTranscation", "blockNumber", height)
		nonce, _ := getNonce(gen, from, state, "sendAddCaCertTranscation", txPool)
		//pub := crypto.FromECDSAPub(&priKey.PublicKey)
		//input := packInput(abiCA, "deposit", "sendAddCaCertTranscation", pub, new(big.Int).SetInt64(5000), value)

		input := packInput(abiStaking, "addCaCert", "sendAddCaCertTranscation", cert)

		addTx(gen, blockchain, nonce, nil, input, txPool, priKey, signer)
	}
}

//neo test
func sendDelCaCertTranscation(height uint64, gen *core.BlockGen, from common.Address, cert []byte, priKey *ecdsa.PrivateKey, signer types.Signer, state *state.StateDB, blockchain *core.BlockChain, abiStaking abi.ABI, txPool txPool) {
	if height == 40 {
		nonce, _ := getNonce(gen, from, state, "sendDelCaCertTranscation", txPool)
		//pub := crypto.FromECDSAPub(&priKey.PublicKey)
		//input := packInput(abiCA, "deposit", "sendDelCaCertTranscation", pub, new(big.Int).SetInt64(5000), value)
		input := packInput(abiStaking, "delCaCert", "sendDelCaCertTranscation", cert)

		addTx(gen, blockchain, nonce, nil, input, txPool, priKey, signer)
	}
}

//neo test
func sendGetCaCertAmountTranscation(height uint64, gen *core.BlockGen, from common.Address, cert []byte, priKey *ecdsa.PrivateKey, signer types.Signer, state *state.StateDB, blockchain *core.BlockChain, abiStaking abi.ABI, txPool txPool) {
	if height == 30 {
		input := packInput(abiStaking, "getCaAmount", "sendGetCaCertAmountTranscation")
		var args uint64
		readTx(gen, blockchain, 0, big.NewInt(0), input, txPool, priKey, signer, "getCaAmount", &args)
		printTest("---get Cert Amount is ", "arges = ", args)

	}
}

//neo test
func sendMultiProposalTranscation(height uint64, gen *core.BlockGen, from common.Address, cert []byte, certPar []byte, isAdd bool, priKey *ecdsa.PrivateKey, signer types.Signer, state *state.StateDB, blockchain *core.BlockChain, abiStaking abi.ABI, txPool txPool) {
	if height == 30 {
		nonce, _ := getNonce(gen, from, state, "sendMultiProposalTranscation", txPool)

		input := packInput(abiStaking, "multiProposal", "sendMultiProposalTranscation", certPar, cert, isAdd)
		printTest("---sendMultiProposalTranscation ", "arges = ", certPar, "cert", cert, "input", input)
		addTx(gen, blockchain, nonce, nil, input, txPool, priKey, signer)
	}
}

//neo test
func sendIsApproveCACertTranscation(height uint64, gen *core.BlockGen, from common.Address, cert []byte, priKey *ecdsa.PrivateKey, signer types.Signer, state *state.StateDB, blockchain *core.BlockChain, abiStaking abi.ABI, txPool txPool) {
	if height == 25 || height == 45 {
		input := packInput(abiStaking, "isApproveCaCert", "sendIsApproveCACertTranscation", cert)
		var args bool
		readTx(gen, blockchain, 0, big.NewInt(0), input, txPool, priKey, signer, "isApproveCaCert", &args)
		printTest("get Cert Amount is ", args)
	}
}

func addTx(gen *core.BlockGen, blockchain *core.BlockChain, nonce uint64, value *big.Int, input []byte, txPool txPool, priKey *ecdsa.PrivateKey, signer types.Signer) {
	//2426392 1000000000
	//866328  1000000
	//2400000
	//tx, _ := types.SignTx(types.NewTransaction(nonce, types.CACertListAddress, value, 2446392, big.NewInt(1000000000), input), signer, priKey)
	tx, _ := types.SignTx(types.NewTransaction(nonce, types.CACertListAddress, value, 2446392, big.NewInt(0), input, nil), signer, priKey)

	if gen != nil {
		gen.AddTxWithChain(blockchain, tx)
	} else {
		txPool.AddRemotes([]*types.Transaction{tx})
	}
}

func readTx(gen *core.BlockGen, blockchain *core.BlockChain, nonce uint64, value *big.Int, input []byte, txPool txPool, priKey *ecdsa.PrivateKey, signer types.Signer, abiMethod string, result interface{}) {
	tx, _ := types.SignTx(types.NewTransaction(nonce, types.CACertListAddress, value, 866328, big.NewInt(1000000), input, nil), signer, priKey)

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
