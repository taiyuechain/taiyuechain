package test

import (
	"fmt"
	"github.com/taiyuechain/taiyuechain/accounts/abi"
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

// ContractABI is the input ABI used to generate the binding from.
const ContractABI = `[
{
"inputs":[],"stateMutability":"nonpayable","type":"constructor"},
{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"from","type":"address"},
							{"indexed":false,"internalType":"address","name":"to","type":"address"},
							{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],
							"name":"Sent","type":"event"},
{"inputs":[{"internalType":"address","name":"","type":"address"}],
"name":"balances",
"outputs":[{"internalType":"uint256","name":"","type":"uint256"}],
"stateMutability":"view","type":"function"},
		{"inputs":[{"internalType":"address","name":"receiver","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],
		"name":"mint","outputs":[],"stateMutability":"nonpayable","type":"function"},
		{"inputs":[],"name":"minter",
		"outputs":[{"internalType":"address","name":"","type":"address"}],
		"stateMutability":"view","type":"function"},
		{"inputs":[{"internalType":"address","name":"receiver","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],
		"name":"send",
		"outputs":[],"stateMutability":"nonpayable","type":"function"}]`

// ContractBin is the compiled bytecode used for deploying new contracts.
const ContractBin = `60806040526000805534801561001457600080fd5b506a52b7d2dcc80cd2e4000000600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550610b91806100736000396000f3fe608060405234801561001057600080fd5b50600436106100935760003560e01c8063313ce56711610066578063313ce5671461022557806370a082311461024357806395d89b411461029b578063a9059cbb1461031e578063dd62ed3e1461038457610093565b806306fdde0314610098578063095ea7b31461011b57806318160ddd1461018157806323b872dd1461019f575b600080fd5b6100a06103fc565b6040518080602001828103825283818151815260200191508051906020019080838360005b838110156100e05780820151818401526020810190506100c5565b50505050905090810190601f16801561010d5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b6101676004803603604081101561013157600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610435565b604051808215151515815260200191505060405180910390f35b6101896104c2565b6040518082815260200191505060405180910390f35b61020b600480360360608110156101b557600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001909291905050506104d1565b604051808215151515815260200191505060405180910390f35b61022d610854565b6040518082815260200191505060405180910390f35b6102856004803603602081101561025957600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610859565b6040518082815260200191505060405180910390f35b6102a36108a2565b6040518080602001828103825283818151815260200191508051906020019080838360005b838110156102e35780820151818401526020810190506102c8565b50505050905090810190601f1680156103105780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b61036a6004803603604081101561033457600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001909291905050506108db565b604051808215151515815260200191505060405180910390f35b6103e66004803603604081101561039a57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610aa1565b6040518082815260200191505060405180910390f35b6040518060400160405280600881526020017f455243546f6b656e00000000000000000000000000000000000000000000000081525081565b600081600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055506001905092915050565b6a52b7d2dcc80cd2e400000081565b600081600160008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020541015801561059e575081600260008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205410155b610610576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252600b8152602001807f6e6f7420656e672061616100000000000000000000000000000000000000000081525060200191505060405180910390fd5b61069f82600260008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054610b2890919063ffffffff16565b600260008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208190555061077182600160008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054610b2890919063ffffffff16565b600160008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208190555061080682600160008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054610b3f90919063ffffffff16565b600160008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550600190509392505050565b601281565b6000600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b6040518060400160405280600381526020017f455243000000000000000000000000000000000000000000000000000000000081525081565b600081600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054101561096d576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526000815260200160200191505060405180910390fd5b6109bf82600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054610b2890919063ffffffff16565b600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550610a5482600160008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054610b3f90919063ffffffff16565b600160008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055506001905092915050565b6000600260008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905092915050565b600082821115610b3457fe5b818303905092915050565b600080828401905083811015610b5157fe5b809150509291505056fea2646970667358221220debdb75469c3e7939d48285c47b8ff4cb1e302cdacf6266e888103beda5cc93b64736f6c63430006060033`

var (
	contractABI, _  = abi.JSON(strings.NewReader(ContractABI))
	bytecode        = common.FromHex(ContractBin)
	contractAddress common.Address
)

func TestDeployContract(t *testing.T) {
	var (
		db  = taidb.NewMemDatabase()
		pow = minerva.NewFaker()
	)

	params.MinTimeGap = big.NewInt(0)
	params.SnailRewardInterval = big.NewInt(3)
	genesis := gspec.MustCommit(db)

	// Import the chain. This runs all block validation rules.
	blockchain, _ := core.NewBlockChain(db, nil, gspec.Config, pow, vm.Config{}, nil)
	defer blockchain.Stop()

	// This call generates a chain of 5 blocks. The function runs for
	// each block and adds different features to gen based on the
	// block index.
	chain, _ := core.GenerateChain(gspec.Config, genesis, pow, db, 10, func(i int, gen *core.BlockGen) {
		switch i {
		case 1:
			tx, _ := types.SignTx(types.NewContractCreation(gen.TxNonce(mAccount), big.NewInt(30), 1000000, new(big.Int).SetUint64(1), bytecode, nil), signer, priKey)
			gen.AddTx(tx)
			contractAddress = crypto.CreateAddress(mAccount, tx.Nonce())
			fmt.Println("contractAddress", crypto.AddressToHex(contractAddress))
		case 2:
			// In block 2, addr1 sends some more ether to addr2.
			// addr2 passes it on to addr3.
			input := packInput(contractABI, "minter", "sendGetDepositTransaction")
			args := struct {
				common.Address
			}{}
			tx1, _ := types.SignTx(types.NewTransaction(gen.TxNonce(mAccount), contractAddress, big.NewInt(1000), 500000, nil, input, nil), signer, priKey)
			gen.AddTx(tx1)
			output, gas := gen.ReadTxWithChain(blockchain, tx1)
			UnpackOutput(contractABI, "minter", output, &args)
			fmt.Println("gas", gas, " address ", crypto.AddressToHex(args.Address))
		case 3:
			// Block 3 is empty but was mined by addr3.
			gen.SetExtra([]byte("yeehaw"))
		}
	})

	if i, err := blockchain.InsertChain(chain); err != nil {
		fmt.Printf("insert error (block %d): %v\n", chain[i].NumberU64(), err)
		return
	}

	state, _ := blockchain.State()
	fmt.Printf("last block: #%d\n", blockchain.CurrentBlock().Number())
	fmt.Println("balance of addr1:", state.GetBalance(mAccount))
}

func UnpackOutput(abiStaking abi.ABI, abiMethod string, output []byte, result interface{}) {
	err := abiStaking.Unpack(result, abiMethod, output)
	if err != nil {
		printTest(abiMethod, " error ", err)
	}
}
