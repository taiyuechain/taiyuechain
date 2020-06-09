package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/taiyuechain/taiyuechain"
	"github.com/taiyuechain/taiyuechain/accounts/abi"
	"github.com/taiyuechain/taiyuechain/accounts/keystore"
	"github.com/taiyuechain/taiyuechain/cmd/utils"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/console"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/core/vm"
	"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/yueclient"
	"gopkg.in/urfave/cli.v1"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	key   string
	store string
	ip    string
	port  int
)

var (
	abiStaking, _ = abi.JSON(strings.NewReader(vm.CACertStoreABIJSON))
	priKey        *ecdsa.PrivateKey
	from          common.Address
	trueValue     uint64
	holder        common.Address
	cert          []byte
)

const (
	datadirPrivateKey = "key"
)

func proposal(ctx *cli.Context) error {

	loadPrivate(ctx)

	conn, url := dialConn(ctx)

	printBaseInfo(conn, url)

	PrintBalance(conn, from)
	if !ctx.GlobalIsSet(BftCertFlag.Name) {
		printError("Must specify --bftcert for multi proposal")
	}
	if !ctx.GlobalIsSet(ProposalCertFlag.Name) {
		printError("Must specify --proposalcert for proposal validator")
	}
	bftfile := ctx.GlobalString(BftCertFlag.Name)
	bftByte, _ := getPubFromFile(bftfile)
	proposalfile := ctx.GlobalString(ProposalCertFlag.Name)
	proposalByte, _ := getPubFromFile(proposalfile)

	input := packInput("multiProposal", bftByte, proposalByte, true)
	txHash := sendContractTransaction(conn, from, types.CACertListAddress, nil, priKey, input, cert)

	getResult(conn, txHash, true, false)

	return nil
}

func sendContractTransaction(client *yueclient.Client, from, toAddress common.Address, value *big.Int, privateKey *ecdsa.PrivateKey, input []byte, cert []byte) common.Hash {
	// Ensure a valid value field and resolve the account nonce
	nonce, err := client.PendingNonceAt(context.Background(), from)
	if err != nil {
		log.Fatal(err)
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	gasLimit := uint64(2100000) // in units
	// If the contract surely has code (or code is not needed), estimate the transaction
	msg := taiyuechain.CallMsg{From: from, To: &toAddress, GasPrice: gasPrice, Value: value, Data: input}
	gasLimit, err = client.EstimateGas(context.Background(), msg)
	if err != nil {
		fmt.Println("Contract exec failed", err)
	}
	if gasLimit < 1 {
		gasLimit = 866328
	}

	// Create the transaction, sign it and schedule it for execution
	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, input, cert)

	chainID, err := client.ChainID(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("TX data nonce ", nonce, " transfer value ", value, " gasLimit ", gasLimit, " gasPrice ", gasPrice, " chainID ", chainID)

	signedTx, err := types.SignTx(tx, types.NewSigner(chainID), privateKey)
	if err != nil {
		log.Fatal(err)
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatal(err)
	}

	return signedTx.Hash()
}

func loadPrivateKey(path string) common.Address {
	var err error
	if path == "" {
		file, err := getAllFile(datadirPrivateKey)
		if err != nil {
			printError(" getAllFile file name error", err)
		}
		kab, _ := filepath.Abs(datadirPrivateKey)
		path = filepath.Join(kab, file)
	}
	priKey, err = crypto.LoadECDSA(path)
	if err != nil {
		printError("LoadECDSA error", err)
	}
	from = crypto.PubkeyToAddress(priKey.PublicKey)
	return from
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

func trueToWei(ctx *cli.Context, zero bool) *big.Int {
	trueValue = ctx.GlobalUint64(TrueValueFlag.Name)
	if !zero && trueValue <= 0 {
		printError("Value must bigger than 0")
	}
	baseUnit := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	value := new(big.Int).Mul(big.NewInt(int64(trueValue)), baseUnit)
	return value
}

func weiToTrue(value *big.Int) uint64 {
	baseUnit := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	valueT := new(big.Int).Div(value, baseUnit).Uint64()
	return valueT
}

func getResult(conn *yueclient.Client, txHash common.Hash, contract bool, delegate bool) {
	fmt.Println("Please waiting ", " txHash ", txHash.String())

	count := 0
	for {
		time.Sleep(time.Millisecond * 200)
		_, isPending, err := conn.TransactionByHash(context.Background(), txHash)
		if err != nil {
			log.Fatal(err)
		}
		count++
		if !isPending {
			break
		}
		if count >= 40 {
			fmt.Println("Please use querytx sub command query later.")
			os.Exit(0)
		}
	}

	queryTx(conn, txHash, false)
}

func queryTx(conn *yueclient.Client, txHash common.Hash, pending bool) {

	if pending {
		_, isPending, err := conn.TransactionByHash(context.Background(), txHash)
		if err != nil {
			log.Fatal(err)
		}
		if isPending {
			println("In tx_pool no validator  process this, please query later")
			os.Exit(0)
		}
	}

	receipt, err := conn.TransactionReceipt(context.Background(), txHash)
	if err != nil {
		log.Fatal(err)
	}

	if receipt.Status == types.ReceiptStatusSuccessful {
		block, err := conn.BlockByHash(context.Background(), receipt.BlockHash)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Transaction Success", " block Number", receipt.BlockNumber.Uint64(), " block txs", len(block.Transactions()), "blockhash", block.Hash().Hex())
	} else if receipt.Status == types.ReceiptStatusFailed {
		fmt.Println("Transaction Failed ", " Block Number", receipt.BlockNumber.Uint64())
	}
}

func packInput(abiMethod string, params ...interface{}) []byte {
	input, err := abiStaking.Pack(abiMethod, params...)
	if err != nil {
		printError(abiMethod, " error ", err)
	}
	return input
}

func PrintBalance(conn *yueclient.Client, from common.Address) {
	balance, err := conn.BalanceAt(context.Background(), from, nil)
	if err != nil {
		log.Fatal(err)
	}
	fbalance := new(big.Float)
	fbalance.SetString(balance.String())
	trueValue := new(big.Float).Quo(fbalance, big.NewFloat(math.Pow10(18)))

	sbalance, err := conn.BalanceAt(context.Background(), from, nil)
	fmt.Println("Your wallet valid balance is ", trueValue, "'true ", " lock balance is ", weiToTrue(sbalance), "'true ")
}

func loadPrivate(ctx *cli.Context) {
	key = ctx.GlobalString(KeyFlag.Name)
	store = ctx.GlobalString(KeyStoreFlag.Name)
	if key != "" {
		loadPrivateKey(key)
	} else if store != "" {
		loadSigningKey(store)
	} else {
		printError("Must specify --key or --keystore")
	}

	if priKey == nil {
		printError("load privateKey failed")
	}
	if !ctx.GlobalIsSet(CertKeyFlag.Name) {
		printError("Must specify --certpath for send transaction")
	}
	certfile := ctx.GlobalString(CertKeyFlag.Name)
	certByte, pub := getPubFromFile(certfile)
	address := crypto.PubkeyToAddress(*pub)
	if from != address {
		printError("The certificate  not match account")
	}
	cert = certByte
}

func getPubFromFile(certfile string) ([]byte, *ecdsa.PublicKey) {
	if !common.FileExist(certfile) {
		printError("cert file not exist", certfile)
	}
	certByte, err := crypto.ReadPemFileByPath(certfile)
	if err != nil {
		printError("can't read cert from file ", certfile)
	}
	pub, err := crypto.FromCertBytesToPubKey(certByte)
	if err != nil {
		printError("cert convert to pub, no correct cert file", certfile)
	}
	return certByte, pub
}

func dialConn(ctx *cli.Context) (*yueclient.Client, string) {
	ip = ctx.GlobalString(utils.RPCListenAddrFlag.Name)
	port = ctx.GlobalInt(utils.RPCPortFlag.Name)

	url := fmt.Sprintf("http://%s", fmt.Sprintf("%s:%d", ip, port))
	// Create an IPC based RPC connection to a remote node
	// "http://39.100.97.129:8545"
	conn, err := yueclient.Dial(url)
	if err != nil {
		log.Fatalf("Failed to connect to the Truechain client: %v", err)
	}
	return conn, url
}

func printBaseInfo(conn *yueclient.Client, url string) *types.Header {
	header, err := conn.HeaderByNumber(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}

	if common.IsHexAddress(crypto.AddressToHex(from)) {
		fmt.Println("Connect url ", url, " current number ", header.Number.String(), " address ", crypto.AddressToHex(from))
	} else {
		fmt.Println("Connect url ", url, " current number ", header.Number.String())
	}

	return header
}

// loadSigningKey loads a private key in Ethereum keystore format.
func loadSigningKey(keyfile string) common.Address {
	keyjson, err := ioutil.ReadFile(keyfile)
	if err != nil {
		printError(fmt.Errorf("failed to read the keyfile at '%s': %v", keyfile, err))
	}
	password, _ := console.Stdin.PromptPassword("Please enter the password for '" + keyfile + "': ")
	//password := "secret"
	key, err := keystore.DecryptKey(keyjson, password)
	if err != nil {
		printError(fmt.Errorf("error decrypting key: %v", err))
	}
	priKey = key.PrivateKey
	from = crypto.PubkeyToAddress(priKey.PublicKey)
	//fmt.Println("address ", from.Hex(), "key", hex.EncodeToString(crypto.FromECDSA(priKey)))
	return from
}

func queryStakingInfo(conn *yueclient.Client, query bool) {
	header, err := conn.HeaderByNumber(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}
	input := packInput("getCaAmount")
	msg := taiyuechain.CallMsg{From: from, To: &types.CACertListAddress, Data: input}
	output, err := conn.CallContract(context.Background(), msg, header.Number)
	if err != nil {
		printError("method CallContract error", err)
	}
	if len(output) != 0 {
		var args uint64
		err = abiStaking.Unpack(&args, "getCaAmount", output)
		if err != nil {
			printError("abi error", err)
		}
		fmt.Println("Amount ", args)
	} else {
		fmt.Println("Contract query failed result len == 0")
	}
}
