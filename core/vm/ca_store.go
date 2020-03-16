// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.
package vm

import (
	//"math/big"
	"strings"
	"errors"
	//"time"
	"fmt"

	"github.com/taiyuechain/taiyuechain/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/ethereum/go-ethereum/log"
	lru "github.com/hashicorp/golang-lru"
	"github.com/taiyuechain/taiyuechain/consensus/tbft/help"
	"github.com/ethereum/go-ethereum/rlp"
	"math/big"
)


//*************************
//store logic
//*************************

var CASC *CAStoreCache //CA store cache

const (
	proposalAddCert = 0
	proposalDelCert = 1
	proposalTimeLine = 1000 // 1000 block Hight
	pStateNil = 0
	pStatePending = 1
	pStateSuccless = 2
	pStateFail = 3
)

func init() {
	CASC = newCAStoreCache()
}

type CAStoreCache struct {
	Cache 		*lru.Cache
	size 		int
}

func newCAStoreCache() *CAStoreCache {
	cc := &CAStoreCache{
		size:	20,
	}
	cc.Cache,_ = lru.New(cc.size)
	return cc
}


type CACert struct {
	cACert []byte
	isStore bool
}

type ProposalState struct {
	pHash common.Hash
	cACert []byte
	startHight *big.Int
	endHight *big.Int
	pState uint8
	needPconfirmNumber uint64 // muti need confir len
	pNeedDo uint8 // only supprot add and del
	signList []common.Hash
	signMap map[common.Hash]bool
}


type CACertList struct {
	cAAmount uint64
	caCertMap   map[uint64]*CACert
	proposalMap map[common.Hash]*ProposalState
}

// new a CACerList
func NewCACertList() *CACertList{
	return &CACertList{
		cAAmount:0,
		caCertMap:make(map[uint64]*CACert),
	}
}

func CloneCaCache(cachaList *CACertList) *CACertList {
	if cachaList == nil{
		return nil
	}

	tmp := &CACertList{
		cAAmount: cachaList.cAAmount,
		caCertMap: make(map[uint64]*CACert),
	}
	for k,val := range cachaList.caCertMap {
		log.Info("---clone","k",k,"value",val.cACert,"isstart",val.isStore)
		items := &CACert{
			val.cACert,
			val.isStore,
		}

		tmp.caCertMap[k] = items

	}
	return tmp
}

func (ca *CACertList ) LoadCACertList(state StateDB, preAddress common.Address)  error{

	key := common.BytesToHash(preAddress[:])
	data := state.GetCAState(preAddress, key)
	lenght := len(data)
	if lenght == 0 {
		return errors.New("Load data = 0")
	}
	hash := types.RlpHash(data)
	var temp CACertList
	watch1 := help.NewTWatch(0.005, "Load impawn")
	if cc, ok := CASC.Cache.Get(hash); ok {
		caList := cc.(*CACertList)
		temp = *(CloneCaCache(caList))
		log.Info("--load --come to cache","ca amount",temp.cAAmount)
		for k,val := range temp.caCertMap {
			log.Info("--clone","k",k,"val",val.cACert)

		}
	} else {
		if err := rlp.DecodeBytes(data, &temp); err != nil {
			watch1.EndWatch()
			watch1.Finish("DecodeBytes")
			log.Error(" Invalid CACertList entry RLP", "err", err)
			return errors.New(fmt.Sprintf("Invalid CACertList entry RLP %s", err.Error()))
		}
		tmp := CloneCaCache(&temp)

		if tmp != nil {
			CASC.Cache.Add(hash, tmp)
		}
	}
	ca.cAAmount = temp.cAAmount
	for k,val := range temp.caCertMap {
		log.Info("---clone","k",k,"value",val.cACert,"isstart",val.isStore)
		items := &CACert{
			val.cACert,
			val.isStore,
		}

		ca.caCertMap[k] = items

	}

	for k,val := range ca.caCertMap {
		log.Info("--clone 2","k",k,"val",val.cACert)

	}
	watch1.EndWatch()
	watch1.Finish("DecodeBytes")
	return nil
}

func (ca *CACertList ) SaveCACertList(state StateDB, preAddress common.Address)  error{
	//log.Info("---save ","amount ",ca.cAAmount)
	key := common.BytesToHash(preAddress[:])
	watch1 := help.NewTWatch(0.005, "Save impawn")
	data, err := rlp.EncodeToBytes(ca)
	watch1.EndWatch()
	watch1.Finish("EncodeToBytes")

	if err != nil {
		log.Crit("Failed to RLP encode CACertList", "err", err)
	}
	hash := types.RlpHash(data)
	for _,val := range ca.caCertMap {
		log.Info("-=-==-=save CA info","Ce name",val.cACert,"is store",val.isStore)

	}
	state.SetCAState(preAddress, key, data)
	tmp := CloneCaCache(ca)
	if tmp != nil {
		CASC.Cache.Add(hash, tmp)
	}
	return err
}

func(ca *CACertList ) IsInList(caCert []byte) (bool ,error) {
	hash := types.RlpHash(caCert)
	for _,val := range ca.caCertMap {
		log.Info("-=-==-=CA info","Ce name",val.cACert,"is store",val.isStore)
		if hash == types.RlpHash(val.cACert) && val.isStore == true{
			return true,nil
		}
	}
	return false,errors.New("not in List")
}

func (ca *CACertList) addCertToList(caCert []byte) (bool ,error){
	if len(caCert) ==0 {
		return false,errors.New("ca cert len is zeor")
	}
	ok,_ := ca.IsInList(caCert)
	log.Info("---addCertToList","isInlist",ok,"caCert",caCert)
	if ok {
		return false,errors.New("ca cert is alread exit")
	}


	amount := ca.cAAmount
	cac :=&CACert{
		caCert,
		true,
	}
	log.Info("ccc","caamount",cac.cACert)
	ca.caCertMap = make(map[uint64]*CACert)
	/*if(amount == 0){
		ca.caCertMap[uint64(0)] = cac
	}else{
		ca.caCertMap[uint64(amount++)] = cac
	}*/
	ca.caCertMap[uint64(amount+1)] = cac

	ca.cAAmount++

	return true,nil

}

func (ca *CACertList) delCertToList(caCert []byte) (bool ,error){
	if len(caCert) ==0 {
		return false,errors.New("ca cert len is zeor")
	}

	amount :=len(ca.caCertMap)

	hash := types.RlpHash(caCert)
	for i,val := range ca.caCertMap {
		if hash == types.RlpHash(val.cACert){
			ca.caCertMap[uint64(i)] = ca.caCertMap[uint64(amount)]
			ca.caCertMap[uint64(amount)].isStore = false

			ca.cAAmount--
			return true,nil
		}
	}
	
	return false,errors.New("not find the ca cert")
}

func (ca *CACertList)GetCaCertAmount() uint64{
	return ca.cAAmount
}



//*************************
//contract logic
//*************************

// StakingGas defines all method gas
var CaCertStoreGas = map[string]uint64{
	"getCaAmount":       360000,
	"addCaCert":      	 450000,
	"delCaCert":         30000,
	"isApproveCaCert":   2400000,
}

// Staking contract ABI
var abiCaCertStore abi.ABI

//type CaRootContract struct{}
type CaCertContract struct{}

func init() {
	abiCaCertStore, _ = abi.JSON(strings.NewReader(CACertStoreABIJSON))
}


// RunStaking execute truechain staking contract
func RunCaCertStore(evm *EVM, contract *Contract, input []byte) (ret []byte, err error) {
	method, err := abiCaCertStore.MethodById(input)
	if err != nil {
		log.Error("No method found RunCaCertStore")
		return nil, ErrCACertStoreInvalidInput
	}
	log.Info("---------------------func RunCaCertStore neo2020310 ","name",method.Name)
	data := input[4:]

	switch method.Name {
	case "getCaAmount":
		ret, err = getCaAmount(evm, contract, data)
	case "addCaCert":
		ret, err = addCaCert(evm, contract, data)
	case "delCaCert":
		ret, err = delCaCert(evm, contract, data)
	case "isApproveCaCert":
		ret, err = isApproveCaCert(evm, contract, data)
	default:
		log.Warn("CA cert store call fallback function")
		err = ErrCACertStoreInvalidInput
	}

	return ret, err
}


// logN add event log to receipt with topics up to 4
func logForReceipt(evm *EVM, contract *Contract, topics []common.Hash, data []byte) ([]byte, error) {
	evm.StateDB.AddLog(&types.Log{
		Address: contract.Address(),
		Topics:  topics,
		Data:    data,
		// This is a non-consensus field, but assigned here because
		// core/state doesn't know the current block number.
		BlockNumber: evm.BlockNumber.Uint64(),
	})
	return nil, nil
}

func getCaAmount(evm *EVM, contract *Contract, input []byte) (ret []byte, err error){

	method, _ := abiCaCertStore.Methods["getCaAmount"]
	caCertList := NewCACertList()
	err = caCertList.LoadCACertList(evm.StateDB, types.CACertListAddress)
	if err != nil {
		log.Error("Staking load error", "error", err)
		return nil, err
	}

	//amount

	amount := caCertList.GetCaCertAmount()
	log.Info("----amount","is",amount)
	ret, err = method.Outputs.Pack(amount)

	return ret,err
}

func addCaCert(evm *EVM, contract *Contract, input []byte) (ret []byte, err error){
	from := contract.caller.Address()
	var caCert []byte

	method, _ := abiCaCertStore.Methods["addCaCert"]
	err = method.Inputs.Unpack(&caCert, input)
	if err != nil {
		log.Error("Unpack append value error", "err", err)
		return nil, ErrCACertStoreInvalidInput
	}
	//todo neo verify caCert

	caCertList := NewCACertList()
	err = caCertList.LoadCACertList(evm.StateDB, types.CACertListAddress)
	if err != nil {
		log.Error("Staking load error", "error", err)
		return nil, err
	}

	//add
	_,err = caCertList.addCertToList(caCert)
	if err != nil{
		log.Error("addCertToList error")
		return nil, err
	}

	//store
	err = caCertList.SaveCACertList(evm.StateDB, types.CACertListAddress)
	if err != nil {
		log.Error("Ca Cert save state error", "error", err)
		return nil, err
	}

	//event
	event := abiCaCertStore.Events["AddCaCert"]
	logData, err := event.Inputs.PackNonIndexed(caCert)
	if err != nil {
		log.Error("Pack staking log error", "error", err)
		return nil, err
	}
	topics := []common.Hash{
		event.ID(),
		common.BytesToHash(from[:]),
	}
	logForReceipt(evm, contract, topics, logData)
	return nil, nil
}

func delCaCert(evm *EVM, contract *Contract, input []byte) (ret []byte, err error){
	from := contract.caller.Address()
	var caCert []byte

	method, _ := abiCaCertStore.Methods["delCaCert"]
	err = method.Inputs.Unpack(&caCert, input)
	if err != nil {
		log.Error("Unpack append value error", "err", err)
		return nil, ErrCACertStoreInvalidInput
	}
	//todo neo verify caCert

	caCertList := NewCACertList()
	err = caCertList.LoadCACertList(evm.StateDB, types.CACertListAddress)
	if err != nil {
		log.Error("Staking load error", "error", err)
		return nil, err
	}

	//is in list
	var ok bool
	ok,err =caCertList.IsInList(caCert)
	if !ok{
		//not in list
		return nil,err
	}

	//del
	_,err = caCertList.delCertToList(caCert)
	if err != nil{
		log.Error("addCertToList error")
		return nil, err
	}

	//store
	err = caCertList.SaveCACertList(evm.StateDB, types.CACertListAddress)
	if err != nil {
		log.Error("Ca Cert save state error", "error", err)
		return nil, err
	}

	//event
	event := abiCaCertStore.Events["DelCaCert"]
	logData, err := event.Inputs.PackNonIndexed(caCert)
	if err != nil {
		log.Error("Pack staking log error", "error", err)
		return nil, err
	}
	topics := []common.Hash{
		event.ID(),
		common.BytesToHash(from[:]),
	}
	logForReceipt(evm, contract, topics, logData)
	return nil, nil
}

func isApproveCaCert(evm *EVM, contract *Contract, input []byte) (ret []byte, err error){

	var caCert []byte

	log.Info(" isApproveCaCert 1")
	method, _ := abiCaCertStore.Methods["isApproveCaCert"]
	err = method.Inputs.Unpack(&caCert, input)
	log.Info(" isApproveCaCert 2","ca",caCert)
	caCertList := NewCACertList()
	err = caCertList.LoadCACertList(evm.StateDB, types.CACertListAddress)
	if err != nil {
		log.Error("Staking load error", "error", err)
		return nil, err
	}

	//is in list
	var ok bool
	log.Info(" isApproveCaCert 3","ca",caCert,"calist amount" ,caCertList.cAAmount)
	ok,_ =caCertList.IsInList(caCert)

	ret, err = method.Outputs.Pack(ok)

	return ret,err
}




const CACertStoreABIJSON = `
[
	{
    	"name": "AddCaCert",
    	"outputs": [],
    	"inputs": [
	 	 {
        	"type": "bytes",
        	"name": "CaCert",
        	"indexed": false
		 }
    	],
    	"anonymous": false,
    	"type": "event"
   	},
	{
    	"name": "DelCaCert",
    	"outputs": [],
    	"inputs": [
	  	 {
        	"type": "bytes",
        	"name": "CaCert",
        	"indexed": false
      	 }
    	],
    	"anonymous": false,
    	"type": "event"
   	},
	{
    	"name": "getCaAmount",
    	"outputs": [
			{
        		"type": "uint64",
        		"name": "caAmount"
      		}
		],
    	"inputs": [],
    	"constant": true,
    	"payable": false,
    	"type": "function"
	},
	{
    	"name": "addCaCert",
    	"outputs": [],
    	"inputs": [
	 	 {
        	"type": "bytes",
        	"name": "caCert",
        	"indexed": false
		 }
    	],
    	"constant": false,
    	"payable": false,
    	"type": "function"
   	},
	{
    	"name": "delCaCert",
    	"outputs": [],
    	"inputs": [
	  	 {
        	"type": "bytes",
        	"name": "caCert",
        	"indexed": false
      	 }
    	],
    	"constant": false,
    	"payable": false,
    	"type": "function"
   	},
	{
    	"name": "isApproveCaCert",
    	"outputs": [
			{
				"type": "bool",
				"name": "isApproveCC"
			}
		],
    	"inputs": [
	  	{
        	"type": "bytes",
        	"name": "CaCert",
        	"indexed": false
      	}
    	],
    	"constant": true,
    	"payable": false,
    	"type": "function"
   	}
]
`

/*
// Staking Contract json abi
const CACertStoreABIJSONTest = `
[
  {
    "name": "AddCaCert",
    "inputs": [
      {
        "type": "bytes",
        "name": "caCert",
        "indexed": true
      }
    ],
    "anonymous": false,
    "type": "event"
  },
  {
    "name": "DelCaCert",
    "inputs": [
      {
        "type": "bytes",
        "name": "caCert",
        "indexed": true
      }
    ],
    "anonymous": false,
    "type": "event"
  },
  {
    "name": "getCaAmount",
    "outputs": [],
    "inputs": [
      {
        "type": "bytes",
        "name": "caCert"
      }
    ],
    "constant": false,
    "payable": false,
    "type": "function"
  },
  {
    "name": "addCaCert",
    "outputs": [
      {
        "type": "uint256",
        "name": "out"
      }
    ],
    "inputs": [
      {
        "type": "address",
        "name": "owner"
      }
    ],
    "constant": true,
    "payable": false,
    "type": "function"
  },
  {
    "name": "delCaCert",
    "outputs": [
      {
        "type": "uint256",
        "unit": "wei",
        "name": "staked"
      },
      {
        "type": "uint256",
        "unit": "wei",
        "name": "locked"
      },
      {
        "type": "uint256",
        "unit": "wei",
        "name": "unlocked"
      }
    ],
    "inputs": [
      {
        "type": "address",
        "name": "owner"
      }
    ],
    "constant": true,
    "payable": false,
    "type": "function"
  },
  {
    "name": "isApproveCaCert",
    "outputs": [],
    "inputs": [
      {
        "type": "address",
        "name": "holder"
      },
      {
        "type": "uint256",
        "unit": "wei",
        "name": "value"
      }
    ],
    "constant": false,
    "payable": false,
    "type": "function"
  }
]
`*/

