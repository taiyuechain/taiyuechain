package test

import (
	"crypto/ecdsa"
	"github.com/taiyuechain/taiyuechain/cim"
	"math"
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
	pbft1Name = "pbft1priv"
	pbft2Name = "pbft2priv"
	p2p1Name  = "p2p1cert"
	p2p2Name  = "p2p2cert"
	pbft1path = "../../cim/testdata/testcert/" + pbft1Name + ".pem"
	pbft2path = "../../cim/testdata/testcert/" + pbft2Name + ".pem"
	p2p1path  = "../../cim/testdata/testcert/" + p2p1Name + ".pem"
	p2p2path  = "../../cim/testdata/testcert/" + p2p2Name + ".pem"
	CryptoSM2 = uint8(2)

	engine   = minerva.NewFaker()
	db       = taidb.NewMemDatabase()
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

	p2p1Byte, _  = crypto.ReadPemFileByPath(p2p1path)
	p2p2Byte, _  = crypto.ReadPemFileByPath(p2p2path)
	pbft1Byte, _ = crypto.ReadPemFileByPath(pbft1path)
	pbft2Byte, _ = crypto.ReadPemFileByPath(pbft2path)
)

func DefaulGenesisBlock() *core.Genesis {
	i, _ := new(big.Int).SetString("10000000000000000000000", 10)
	key1 := hexutil.MustDecode("0x04bdf9699d20b4ebabe76e76260480e5492c87aaeda51b138bd22c6d66b69549313dc3eb8c96dc9a1cbbf3b347322c51c05afdd609622277444e0f07e6bd35d8bd")
	key2 := hexutil.MustDecode("0x045e1711b6cd8550a5e5466f7f0868b5507929cb69c2f0fca84f8f94816eb40a808ea8a77c3d83c9d16341acb037fbea2f7d9d4af46326defa39b408f40f28fb98")
	key3 := hexutil.MustDecode("0x041b931d350257e881f27bce2563d98c99b13ca4f525a0662f5e7d53f085edff0dca8ceaae550c9f4ceecf217f72806a48a48fb024916392ae41d7c45168e89b94")
	key4 := hexutil.MustDecode("0x049923777d866fd80485be57a126d638cc7dda78a5d6958aff784ca7ed9d9c7be494125bf75fd0328490ae51020274427b9fbb07f59e4c9b5104ac6924721a4438")

	cert3 := []byte{48, 130, 2, 142, 48, 130, 2, 58, 160, 3, 2, 1, 2, 2, 1, 255, 48, 10, 6, 8, 42, 129, 28, 207, 85, 1, 131, 117, 48, 48, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12, 10, 206, 163, 32, 65, 99, 109, 101, 32, 67, 111, 49, 25, 48, 23, 6, 3, 85, 4, 3, 19, 16, 116, 101, 115, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 30, 23, 13, 50, 48, 48, 53, 49, 50, 49, 49, 49, 57, 49, 54, 90, 23, 13, 50, 51, 48, 55, 49, 51, 50, 49, 48, 53, 53, 54, 90, 48, 48, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12, 10, 206, 163, 32, 65, 99, 109, 101, 32, 67, 111, 49, 25, 48, 23, 6, 3, 85, 4, 3, 19, 16, 116, 101, 115, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 129, 28, 207, 85, 1, 130, 45, 3, 66, 0, 4, 27, 147, 29, 53, 2, 87, 232, 129, 242, 123, 206, 37, 99, 217, 140, 153, 177, 60, 164, 245, 37, 160, 102, 47, 94, 125, 83, 240, 133, 237, 255, 13, 202, 140, 234, 174, 85, 12, 159, 76, 238, 207, 33, 127, 114, 128, 106, 72, 164, 143, 176, 36, 145, 99, 146, 174, 65, 215, 196, 81, 104, 232, 155, 148, 163, 130, 1, 67, 48, 130, 1, 63, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 4, 48, 38, 6, 3, 85, 29, 37, 4, 31, 48, 29, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 2, 42, 3, 6, 3, 129, 11, 1, 48, 15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3, 1, 1, 255, 48, 13, 6, 3, 85, 29, 14, 4, 6, 4, 4, 1, 2, 3, 4, 48, 95, 6, 8, 43, 6, 1, 5, 5, 7, 1, 1, 4, 83, 48, 81, 48, 35, 6, 8, 43, 6, 1, 5, 5, 7, 48, 1, 134, 23, 104, 116, 116, 112, 58, 47, 47, 111, 99, 115, 112, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 42, 6, 8, 43, 6, 1, 5, 5, 7, 48, 2, 134, 30, 104, 116, 116, 112, 58, 47, 47, 99, 114, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 116, 48, 26, 6, 3, 85, 29, 17, 4, 19, 48, 17, 130, 15, 102, 111, 111, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 15, 6, 3, 85, 29, 32, 4, 8, 48, 6, 48, 4, 6, 2, 42, 3, 48, 87, 6, 3, 85, 29, 31, 4, 80, 48, 78, 48, 37, 160, 35, 160, 33, 134, 31, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 49, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 108, 48, 37, 160, 35, 160, 33, 134, 31, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 50, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 108, 48, 10, 6, 8, 42, 129, 28, 207, 85, 1, 131, 117, 3, 66, 0, 23, 99, 174, 106, 168, 143, 97, 153, 142, 22, 9, 195, 162, 11, 204, 116, 48, 40, 149, 188, 129, 27, 73, 87, 44, 255, 22, 78, 131, 126, 150, 132, 56, 217, 250, 135, 153, 217, 27, 154, 225, 182, 2, 128, 193, 77, 27, 112, 199, 26, 195, 78, 146, 192, 47, 101, 168, 118, 251, 254, 110, 238, 154, 61, 252}
	cert4 := []byte{48, 130, 2, 142, 48, 130, 2, 58, 160, 3, 2, 1, 2, 2, 1, 255, 48, 10, 6, 8, 42, 129, 28, 207, 85, 1, 131, 117, 48, 48, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12, 10, 206, 163, 32, 65, 99, 109, 101, 32, 67, 111, 49, 25, 48, 23, 6, 3, 85, 4, 3, 19, 16, 116, 101, 115, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 30, 23, 13, 50, 48, 48, 53, 49, 50, 49, 49, 49, 57, 49, 54, 90, 23, 13, 50, 51, 48, 55, 49, 51, 50, 49, 48, 53, 53, 54, 90, 48, 48, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12, 10, 206, 163, 32, 65, 99, 109, 101, 32, 67, 111, 49, 25, 48, 23, 6, 3, 85, 4, 3, 19, 16, 116, 101, 115, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 129, 28, 207, 85, 1, 130, 45, 3, 66, 0, 4, 153, 35, 119, 125, 134, 111, 216, 4, 133, 190, 87, 161, 38, 214, 56, 204, 125, 218, 120, 165, 214, 149, 138, 255, 120, 76, 167, 237, 157, 156, 123, 228, 148, 18, 91, 247, 95, 208, 50, 132, 144, 174, 81, 2, 2, 116, 66, 123, 159, 187, 7, 245, 158, 76, 155, 81, 4, 172, 105, 36, 114, 26, 68, 56, 163, 130, 1, 67, 48, 130, 1, 63, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 4, 48, 38, 6, 3, 85, 29, 37, 4, 31, 48, 29, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 2, 42, 3, 6, 3, 129, 11, 1, 48, 15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3, 1, 1, 255, 48, 13, 6, 3, 85, 29, 14, 4, 6, 4, 4, 1, 2, 3, 4, 48, 95, 6, 8, 43, 6, 1, 5, 5, 7, 1, 1, 4, 83, 48, 81, 48, 35, 6, 8, 43, 6, 1, 5, 5, 7, 48, 1, 134, 23, 104, 116, 116, 112, 58, 47, 47, 111, 99, 115, 112, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 42, 6, 8, 43, 6, 1, 5, 5, 7, 48, 2, 134, 30, 104, 116, 116, 112, 58, 47, 47, 99, 114, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 116, 48, 26, 6, 3, 85, 29, 17, 4, 19, 48, 17, 130, 15, 102, 111, 111, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 15, 6, 3, 85, 29, 32, 4, 8, 48, 6, 48, 4, 6, 2, 42, 3, 48, 87, 6, 3, 85, 29, 31, 4, 80, 48, 78, 48, 37, 160, 35, 160, 33, 134, 31, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 49, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 108, 48, 37, 160, 35, 160, 33, 134, 31, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 50, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 108, 48, 10, 6, 8, 42, 129, 28, 207, 85, 1, 131, 117, 3, 66, 0, 73, 105, 46, 107, 12, 203, 248, 158, 67, 242, 104, 99, 83, 203, 126, 29, 111, 44, 140, 197, 57, 122, 49, 73, 25, 32, 96, 22, 151, 95, 174, 87, 52, 219, 117, 204, 227, 227, 32, 6, 11, 152, 89, 254, 173, 69, 140, 8, 156, 233, 7, 38, 117, 88, 223, 205, 150, 34, 231, 133, 66, 105, 110, 244, 46}

	var certList = [][]byte{pbft1Byte, pbft2Byte, cert3, cert4}
	coinbase := common.HexToAddress("0x9331cf34D0e3E43bce7de1bFd30a59d3EEc106B6")

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
			&types.CommitteeMember{Coinbase: coinbase, Publickey: key3, LocalCert: cert3},
			&types.CommitteeMember{Coinbase: coinbase, Publickey: key4, LocalCert: cert4},
		},
		CertList: certList,
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
	printBalance(stateDb, from, method)
	return nonce, stateDb
}

func sendTranction(height uint64, gen *core.BlockGen, state *state.StateDB, from, to common.Address, value *big.Int, privateKey *ecdsa.PrivateKey, signer types.Signer, txPool txPool, header *types.Header, cert []byte) {
	if height == 10 {
		nonce, statedb := getNonce(gen, from, state, "sendTranction", txPool)
		balance := statedb.GetBalance(to)
		remaining := new(big.Int).Sub(value, balance)
		printTest("1----sendTranction ", balance.Uint64(), " remaining ", remaining.Uint64(), " height ", height, " current ", header.Number.Uint64())
		if remaining.Sign() > 0 {
			tx, _ := types.SignTx(types.NewTransaction(nonce, to, remaining, params.TxGas, new(big.Int).SetInt64(1000000), nil, cert), signer, privateKey)
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

	//new cimList
	cimList := cim.NewCIMList(CryptoSM2)
	cimList.AddCim(cim.CreateCim(pbft1Byte))
	cimList.AddCim(cim.CreateCim(pbft2Byte))

	params.MinTimeGap = big.NewInt(0)
	params.SnailRewardInterval = big.NewInt(3)
	params.ElectionMinLimitForStaking = new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18))

	genesis := gspec.MustFastCommit(db)
	blockchain, _ := core.NewBlockChain(db, nil, gspec.Config, engine, vm.Config{}, cimList)

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

func printBalance(stateDb *state.StateDB, from common.Address, method string) {
	balance := stateDb.GetBalance(types.CACertListAddress)
	fbalance := new(big.Float)
	fbalance.SetString(balance.String())
	StakinValue := new(big.Float).Quo(fbalance, big.NewFloat(math.Pow10(18)))

	printTest(method, " from ", types.ToTai(stateDb.GetBalance(from)), " Staking fbalance ", fbalance, " StakinValue ", StakinValue, "from ", from.String())
}
