package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/taiyuechain/taiyuechain/cim"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/crypto/taiCrypto"
	"github.com/taiyuechain/taiyuechain/etrueclient"
	"github.com/taiyuechain/taiyuechain/params"

	//"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/rpc"
	"math/big"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	//"crypto/x509"
	//"fmt"
	//"github.com/taiyuechain/taiyuechain/crypto/gm/sm2"
	//sm2_cert "github.com/taiyuechain/taiyuechain/crypto/gm/sm2/cert"
)

//Count send complete
var Count int64

//Transaction from to account id
var from, to, frequency = 0, 0, 1

//Two transmission intervals
var interval = time.Millisecond * 0

//get all account
var account []string

//get all account
var noBalance []int

// The message state
var msg = make(chan bool)

// Restart the number
var num int

// SLEEPTIME The interval between reconnections
const SLEEPTIME = 120

// SLEEPTX The interval between send son address
const SLEEPTX = 5

// get par
func main() {
	if len(os.Args) < 4 {
		fmt.Printf("invalid args : %s [count] [frequency] [interval] [from] [to] [\"port\"]\n", os.Args[0])
		return
	}

	/*count, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println("count err")
		return
	}*/

	var err error
	frequency, err = strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Println("frequency err")
		return
	}

	intervalCount, err := strconv.Atoi(os.Args[3])
	if err != nil {
		fmt.Println("interval err")
		return
	}

	interval = time.Millisecond * time.Duration(intervalCount)

	from, err = strconv.Atoi(os.Args[4])
	if err != nil {
		fmt.Println("from err default 0")
	}

	if len(os.Args) > 5 {
		to, err = strconv.Atoi(os.Args[5])
	} else {
		fmt.Println("to 0：Local address 1: Generate address")
	}

	ip := "127.0.0.1:"
	if len(os.Args) == 7 {
		ip = ip + os.Args[6]
	} else {
		ip = ip + "8888"
	}

	SendP256Transtion(ip)
	/*go send(count, ip)*/

	for {
		if !<-msg {
			fmt.Println("======================send Transaction restart=========================")
			num++
			time.Sleep(time.Second * SLEEPTIME)
			//go send(count, ip)
		} else {
			fmt.Println("=======================send Transaction end=========================")
			break
		}
	}
	//fmt.Println("send Transaction num is:", num)
}

func SendP256Transtion(ip string) {

	fmt.Println("send Transaction num is:", num)
	//client, err := rpc.Dial("http://" + ip)
	url := "http://" + ip
	client, err := etrueclient.Dial(url)
	defer client.Close()
	if err != nil {
		fmt.Println("Dail:", ip, err.Error())
		msg <- false
		return
	}

	//sendRawTransaction(client *rpc.Client, from string, to string, value string) (string, error)
	var toPrive, _ = crypto.HexToECDSAP256("696b0620068602ecdda42ada206f74952d8c305a811599d463b89cfa3ba3bb98")
	var fromPrive, _ = crypto.HexToECDSAP256("c1094d6cc368fa78f0175974968e9bf3d82216e87a6dfd59328220ac74181f47")

	from := crypto.PubkeyToAddressP256(fromPrive.PublicKey)
	amount := new(big.Int).SetInt64(1000000000000000000)
	fmt.Println("amount", amount)
	nonce := uint64(2)
	//nonce := client.GetNonceAtBlockNumber(context.Background(),from,)

	//to
	tocertbyte := cim.CreateCertP256(toPrive)

	toCert, err := x509.ParseCertificate(tocertbyte)
	if err != nil {
		return
	}
	//fmt.Println(tocert.Version)
	var topubk ecdsa.PublicKey
	switch pub := toCert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		topubk.Curve = pub.Curve
		topubk.X = pub.X
		topubk.Y = pub.Y
	}

	// from
	fromcert := cim.CreateCertP256(fromPrive)

	chainID, err := client.ChainID(context.Background())
	if err != nil {
		msg <- false
		return
	}

	fmt.Println("the chain id ", "is", chainID)
	//from := crypto.PubkeyToAddressP256(fromPrive.PublicKey)
	to := crypto.PubkeyToAddressP256(topubk)
	fmt.Println("--from address", hexutil.Encode(from.Bytes()), "--to address", hexutil.Encode(to.Bytes()))

	//send true transfer
	tx := types.NewP256Transaction(nonce, &to, nil, amount,
		new(big.Int).SetInt64(0), params.TxGas, new(big.Int).SetInt64(0), nil, fromcert, chainID, nil)

	//send create contract transaction
	//tx := generateCreateContractTx(nonce, amount, fromcert, chainID)

	//send erc20 transfer tx
	//tx := sendErc20TokenTx(nonce, fromcert, chainID)

	signer := types.NewTIP1Signer(chainID)
	signTx, _ := types.SignTxBy266(tx, signer, fromPrive)

	fmt.Println("--start send ")
	err = client.SendPayTransaction(context.Background(), signTx)
	if err != nil {
		msg <- false
		fmt.Println("err", "is", err)
		return //log.Fatal(err)
	}
	fmt.Println("--end send ")

	fmt.Println("tx Hash", "is", hexutil.Encode(signTx.Hash().Bytes()))

}

func generateCreateContractTx(nonce uint64, amount *big.Int, fromcert []byte, chainID *big.Int) *types.Transaction {
	data := "0x608060405260008060006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550600060015534801561005657600080fd5b506012600a0a6402540be40002600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550610da0806100b56000396000f300608060405260043610610099576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806306fdde031461009e578063095ea7b31461012e57806318160ddd1461019357806323b872dd146101be578063313ce5671461024357806370a082311461026e57806395d89b41146102c5578063a9059cbb14610355578063dd62ed3e146103ba575b600080fd5b3480156100aa57600080fd5b506100b3610431565b6040518080602001828103825283818151815260200191508051906020019080838360005b838110156100f35780820151818401526020810190506100d8565b50505050905090810190601f1680156101205780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b34801561013a57600080fd5b50610179600480360381019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035906020019092919050505061046a565b604051808215151515815260200191505060405180910390f35b34801561019f57600080fd5b506101a861055c565b6040518082815260200191505060405180910390f35b3480156101ca57600080fd5b50610229600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035906020019092919050505061056b565b604051808215151515815260200191505060405180910390f35b34801561024f57600080fd5b50610258610999565b6040518082815260200191505060405180910390f35b34801561027a57600080fd5b506102af600480360381019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919050505061099e565b6040518082815260200191505060405180910390f35b3480156102d157600080fd5b506102da6109e7565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561031a5780820151818401526020810190506102ff565b50505050905090810190601f1680156103475780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b34801561036157600080fd5b506103a0600480360381019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610a20565b604051808215151515815260200191505060405180910390f35b3480156103c657600080fd5b5061041b600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610cb6565b6040518082815260200191505060405180910390f35b6040805190810160405280600981526020017f4d6172636f506f6c6f000000000000000000000000000000000000000000000081525081565b600081600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925846040518082815260200191505060405180910390a36001905092915050565b6012600a0a6402540be4000281565b6000808373ffffffffffffffffffffffffffffffffffffffff16141515156105d6576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526000815260200160200191505060405180910390fd5b81600260008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054101580156106a1575081600360008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205410155b15156106f0576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526000815260200160200191505060405180910390fd5b61077f82600360008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054610d3d90919063ffffffff16565b600360008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208190555061085182600260008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054610d3d90919063ffffffff16565b600260008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055506108e682600260008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054610d5690919063ffffffff16565b600260008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040518082815260200191505060405180910390a3600190509392505050565b601281565b6000600260008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b6040805190810160405280600381526020017f4d4150000000000000000000000000000000000000000000000000000000000081525081565b6000808373ffffffffffffffffffffffffffffffffffffffff1614151515610a8b576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526000815260200160200191505060405180910390fd5b81600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205410151515610b1d576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526000815260200160200191505060405180910390fd5b610b6f82600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054610d3d90919063ffffffff16565b600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550610c0482600260008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054610d5690919063ffffffff16565b600260008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040518082815260200191505060405180910390a36001905092915050565b6000600360008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905092915050565b6000828211151515610d4b57fe5b818303905092915050565b6000808284019050838110151515610d6a57fe5b80915050929150505600a165627a7a723058201345897f32ad02e42a2ac96e6516a45ad7e34eb5f1b129be86e17739d50dd8a50029"
	Databytes, _ := hexutil.Decode(data)
	return types.NewP256Transaction(nonce, nil, nil, amount, new(big.Int).SetInt64(0),
		6000000, new(big.Int).SetInt64(0), Databytes,
		fromcert, chainID, nil)
}
func sendErc20TokenTx(nonce uint64, fromcert []byte, chainID *big.Int) *types.Transaction {
	data := "0xa9059cbb0000000000000000000000008926a8d6c4480205a73dbc7712e8578827ce84fb0000000000000000000000000000000000000000000000000de0b6b3a7640000"
	toByte, _ := hexutil.Decode("0xdc465e830637c9d50098a3d0b8245294c4091064")
	to := common.BytesToAddress(toByte)
	Databytes, _ := hexutil.Decode(data)
	return types.NewP256Transaction(nonce, &to, nil, new(big.Int).SetInt64(0),
		new(big.Int).SetInt64(1000000),
		6000000, new(big.Int).SetInt64(1000), Databytes,
		fromcert, chainID, nil)
}

//send transaction init
func send(count int, ip string) {
	//dial etrue
	client, err := rpc.Dial("http://" + ip)

	defer client.Close()

	if err != nil {
		fmt.Println("Dail:", ip, err.Error())
		msg <- false
		return
	}

	err = client.Call(&account, "etrue_accounts")
	if err != nil {
		fmt.Println("etrue_accounts Error", err.Error())
		msg <- false
		return
	}
	if len(account) == 0 {
		fmt.Println("no account")
		return
	}

	fmt.Println("already have accounts is in local:", len(account))

	fmt.Println("personal_newAccount success ", len(account), " result ", createSonAccount(client, count), "main address ", account[from])

	// get balance
	result := getAccountBalance(client, account[from])
	if result == "" {
		return
	}
	balance := getBalanceValue(result, true)

	//main unlock account
	_, err = unlockAccount(client, account[from], "admin", 9000000, "main")
	if err != nil {
		fmt.Println("personal_unlockAccount Error:", err.Error())
		msg <- false
		return
	}

	//send main to son address
	fmt.Println("send balance to ", count, "  new account ", sendBalanceNewAccount(client, count, balance))

	//son address unlock account
	fmt.Println("unlock ", count, " son account ", unlockCountNewAccount(client, count))

	//son address check account
	fmt.Println("check ", count, " son account ", checkSonAccountBalance(client, count, balance))

	// send
	fmt.Println("start sendTransactions from ", count, " account to other new account")
	waitMain := &sync.WaitGroup{}
	for {
		waitMain.Add(1)
		go sendTransactions(client, account, count, waitMain)
		frequency--
		if frequency <= 0 {
			break
		}
		time.Sleep(interval)
	}
	waitMain.Wait()
	msg <- true
}

//send count transaction
func sendTransactions(client *rpc.Client, account []string, count int, wait *sync.WaitGroup) {
	defer wait.Done()
	waitGroup := &sync.WaitGroup{}
	Time := time.Now()

	for i := 0; i < count; i++ {

		result := getAccountBalance(client, account[i])
		if result == "" {
			return
		}

		balance := getBalanceValue(result, false)
		if balance.Cmp(big.NewInt(int64(100000))) < 0 {
			fmt.Println(" Lack of balance  ", balance, " i ", i)
			continue
		}

		waitGroup.Add(1)
		go sendTransaction(client, account[i], i, "", "0x2100", waitGroup)
	}
	waitGroup.Wait()
	fmt.Println(" Complete ", Count, " time ", Time, " count ", count)
}

//send one transaction
func sendTransaction(client *rpc.Client, from string, index int, son string, value string, wait *sync.WaitGroup) {
	defer wait.Done()

	var address string

	if son == "" {
		address = genAddress()
		if to == 1 {
			if account[to] != "" {
				address = account[to]
			}
		}
	} else {
		address = son
	}

	result, err := sendRawTransaction(client, from, address, value)

	if err != nil {
		fmt.Println("sendRawTransaction", "result ", result, "index", index, " error", err, " address ", address)
	}

	if result != "" {
		Count++
	}
}

func sendRawTransaction(client *rpc.Client, from string, to string, value string) (string, error) {

	mapData := make(map[string]interface{})

	mapData["from"] = from
	mapData["to"] = to
	mapData["value"] = value

	var result string
	err := client.Call(&result, "etrue_sendTransaction", mapData)
	return result, err
}

func unlockAccount(client *rpc.Client, account string, password string, time int, name string) (bool, error) {
	var reBool bool
	err := client.Call(&reBool, "personal_unlockAccount", account, password, time)
	fmt.Println(name, " personal_unlockAccount Ok", reBool)
	return reBool, err
}

// Genesis address
func genAddress() string {
	//caolaing modify
	var taipublic taiCrypto.TaiPublicKey
	priKey, _ := taiCrypto.GenPrivKey()
	//address := crypto.PubkeyToAddress(priKey.PublicKey)
	taipublic = priKey.TaiPubKey
	address := taipublic.PubkeyToAddress(taipublic)
	return address.Hex()
}

func getBalanceValue(hex string, print bool) *big.Int {
	if strings.HasPrefix(hex, "0x") {
		hex = strings.TrimPrefix(hex, "0x")
	}
	value, _ := new(big.Int).SetString(hex, 16)
	balance := new(big.Int).Set(value)
	if print {
		fmt.Println("etrue_getBalance Ok:", " true ", balance.Div(balance, big.NewInt(1000000000000000000)), " value ", value, " hex ", hex)
	}
	return value
}

func getAccountBalance(client *rpc.Client, account string) string {
	var result string
	// get balance
	err := client.Call(&result, "etrue_getBalance", account, "latest")
	if err != nil {
		fmt.Println("etrue_getBalance Error:", err)
		msg <- false
		return ""
	}
	return result
}

func createSonAccount(client *rpc.Client, count int) bool {
	for i := len(account); i < count; i++ {
		//new account
		var address string
		err := client.Call(&address, "personal_newAccount", "admin")
		if err != nil {
			fmt.Println("personal_newAccount Error:", err.Error())
			msg <- false
			return false
		}
		account = append(account, address)
		fmt.Println("personal_newAccount ", i, " accounts ", " Ok ", len(account), "address", address)
	}
	return true
}

func sendBalanceNewAccount(client *rpc.Client, count int, main *big.Int) bool {
	average := main.Div(main, big.NewInt(int64(len(account)*2)))
	value := "0x" + fmt.Sprintf("%x", average)
	averageTrue := new(big.Int).Set(average)
	fmt.Println("sendBalanceNewAccount ", " true ", averageTrue.Div(averageTrue, big.NewInt(1000000000000000000)), " average ", average, " hex ", value)

	waitGroup := &sync.WaitGroup{}
	for i := 0; i < count; i++ {
		// get balance
		result := getAccountBalance(client, account[i])
		if result == "" {
			return false
		}
		balance := getBalanceValue(result, true)

		if balance.Cmp(average) < 0 {
			waitGroup.Add(1)
			go sendTransaction(client, account[from], i, account[i], value, waitGroup)
		}
	}
	waitGroup.Wait()

	return true
}

func checkSonAccountBalance(client *rpc.Client, count int, main *big.Int) bool {
	find := false
	getBalance := true
	average := main
	value := "0x" + fmt.Sprintf("%x", average)
	averageTrue := new(big.Int).Set(average)
	fmt.Println("checkSonAccountBalance ", " true ", averageTrue.Div(averageTrue, big.NewInt(1000000000000000000)), " average ", average, " hex ", value)

	for {
		for i := 0; i < count; i++ {
			//main unlock account
			if from == i {
				continue
			}

			for j := 0; j < len(noBalance); j++ {
				if i == noBalance[j] {
					getBalance = true
					noBalance = append(noBalance[:j], noBalance[j+1:]...)
					break
				} else if i > noBalance[j] {
					getBalance = true
				} else {
					getBalance = false
				}
			}

			if !getBalance {
				continue
			}

			if getBalance {
				// get balance
				result := getAccountBalance(client, account[i])
				if result == "" {
					return false
				}
				balance := getBalanceValue(result, true)
				balanceTrue := new(big.Int).Set(balance)
				fmt.Println("etrue_getBalance son address ", account[i], " result ", balance, " i ", i, " true ", balanceTrue.Div(balanceTrue, big.NewInt(1000000000000000000)))
				if balance.Cmp(average) >= 0 {
					if i == count-1 && len(noBalance) == 0 {
						find = true
						break
					}
					continue
				} else {
					noBalance = append(noBalance, i)
				}
			}
			fmt.Println(i, " Transaction main address ", account[from], " son address ", account[i], " value ", value)
			if result, err := sendRawTransaction(client, account[from], account[i], value); err != nil {
				fmt.Println("sendRawTransaction son address error ", result, " err ", err)
				return false
			}
		}

		if find {
			break
		}
	}
	return true
}

func unlockCountNewAccount(client *rpc.Client, count int) bool {
	waitGroup := &sync.WaitGroup{}
	for i := 0; i < count; i++ {
		if from == i {
			continue
		}
		waitGroup.Add(1)

		unlockSonAccount(client, account[i], i, waitGroup)
	}
	waitGroup.Wait()
	return true
}

// unlockSonAccount
func unlockSonAccount(client *rpc.Client, account string, index int, wait *sync.WaitGroup) {
	defer wait.Done()
	fmt.Println("unlockAccount address index ", index, " son address ", account)
	_, err := unlockAccount(client, account, "admin", 9000000, "son address")
	if err != nil {
		fmt.Println("personal_unlockAccount Error:", err.Error(), " index ", index, "addr", account)
		msg <- false
	}
}
