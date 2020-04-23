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
	"errors"
	"strings"
	//"time"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	lru "github.com/hashicorp/golang-lru"
	"github.com/taiyuechain/taiyuechain/accounts/abi"
	"github.com/taiyuechain/taiyuechain/consensus/tbft/help"
	"github.com/taiyuechain/taiyuechain/core/types"
	"math/big"
)

//*************************
//store logic
//*************************

var CASC *CAStoreCache //CA store cache

const (
	proposalAddCert  = 0
	proposalDelCert  = 1
	proposalTimeLine = 1000 // 1000 block Hight
	pStateNil        = 0
	pStatePending    = 1
	pStateSuccless   = 2
	pStateFail       = 3
)

func init() {
	CASC = newCAStoreCache()
}

type CAStoreCache struct {
	Cache *lru.Cache
	size  int
}

func newCAStoreCache() *CAStoreCache {
	cc := &CAStoreCache{
		size: 20,
	}
	cc.Cache, _ = lru.New(cc.size)
	return cc
}

type CACert struct {
	cACert  []byte
	isStore bool
}

func (cacert *CACert) GetByte() []byte {
	return cacert.cACert
}

type ProposalState struct {
	pHash              common.Hash
	cACert             []byte
	startHight         *big.Int
	endHight           *big.Int
	pState             uint8
	needPconfirmNumber uint64 // muti need confir len
	pNeedDo            uint8  // only supprot add and del
	signList           []common.Hash
	signMap            map[common.Hash]bool
}

type CACertList struct {
	cAAmount    uint64
	caCertMap   map[uint64]*CACert
	proposalMap map[common.Hash]*ProposalState
}

// new a CACerList
func NewCACertList() *CACertList {
	return &CACertList{
		cAAmount:    0,
		caCertMap:   make(map[uint64]*CACert),
		proposalMap: make(map[common.Hash]*ProposalState),
	}
}

func (ca *CACertList) InitCACertList(caList [][]byte)  {

	len:= len(caList)
	for i:=0; i<len; i++{
		ca.addCertToList(caList[i]);
	}
}

func CloneCaCache(cachaList *CACertList) *CACertList {
	if cachaList == nil {
		return nil
	}

	tmp := &CACertList{
		cAAmount:    cachaList.cAAmount,
		caCertMap:   make(map[uint64]*CACert),
		proposalMap: make(map[common.Hash]*ProposalState),
	}
	for k, val := range cachaList.caCertMap {
		//log.Info("-----------clone cert map","k",k)
		items := &CACert{
			val.cACert,
			val.isStore,
		}

		tmp.caCertMap[k] = items
	}

	for key, value := range cachaList.proposalMap {
		//log.Info("---clone", "k", key, "value", value.cACert, "isstart", value.pHash)
		item := &ProposalState{
			value.pHash,
			value.cACert,
			value.startHight,
			value.endHight,
			value.pState,
			value.needPconfirmNumber,
			value.pNeedDo,
			value.signList,
			value.signMap,
		}
		tmp.proposalMap[key] = item
	}
	return tmp
}

func (ca *CACertList) GetCACertMap() map[uint64]*CACert {
	return ca.caCertMap
}

func (ca *CACertList) LoadCACertList(state StateDB, preAddress common.Address) error {

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
	for k, val := range temp.caCertMap {
		//log.Info("---clone","k",k,"value",val.cACert,"isstart",val.isStore)
		items := &CACert{
			val.cACert,
			val.isStore,
		}

		ca.caCertMap[k] = items

	}

	for k, val := range temp.proposalMap {
		//log.Info("--clone 2","k",k,"val",val.cACert)
		item := &ProposalState{
			val.pHash,
			val.cACert,
			val.startHight,
			val.endHight,
			val.pState,
			val.needPconfirmNumber,
			val.pNeedDo,
			val.signList,
			val.signMap,
		}

		ca.proposalMap[k] = item
	}
	watch1.EndWatch()
	watch1.Finish("DecodeBytes")
	return nil
}

func (ca *CACertList) SaveCACertList(state StateDB, preAddress common.Address) error {
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
	for _, val := range ca.proposalMap {
		log.Info("-=-==-=save CA info", "Ce name", val.cACert, "is store", val.pHash)

	}
	state.SetCAState(preAddress, key, data)
	tmp := CloneCaCache(ca)
	if tmp != nil {
		CASC.Cache.Add(hash, tmp)
	}
	return err
}

func (ca *CACertList) IsInList(caCert []byte) (bool, error) {
	hash := types.RlpHash(caCert)
	for _, val := range ca.caCertMap {
		//log.Info("-=-==-=CA info", "Ce name", val.cACert, "is store", val.isStore)
		if hash == types.RlpHash(val.cACert) && val.isStore == true {
			return true, nil
		}
	}
	return false, errors.New("not in List")
}

func (ca *CACertList) addCertToList(caCert []byte) (bool, error) {
	if len(caCert) == 0 {
		return false, errors.New("ca cert len is zeor")
	}
	ok, _ := ca.IsInList(caCert)
	//log.Info("---addCertToList", "isInlist", ok, "caCert", caCert)
	if ok {
		return false, errors.New("ca cert is alread exit")
	}

	amount := ca.cAAmount
	cac := &CACert{
		caCert,
		true,
	}
	//log.Info("ccc", "caamount", cac.cACert)
	//ca.caCertMap = make(map[uint64]*CACert)
	/*if(amount == 0){
		ca.caCertMap[uint64(0)] = cac
	}else{
		ca.caCertMap[uint64(amount++)] = cac
	}*/
	ca.caCertMap[uint64(amount+1)] = cac

	ca.cAAmount++

	return true, nil

}



func (ca *CACertList) delCertToList(caCert []byte) (bool, error) {
	if len(caCert) == 0 {
		return false, errors.New("ca cert len is zeor")
	}

	amount := len(ca.caCertMap)

	hash := types.RlpHash(caCert)
	for i, val := range ca.caCertMap {
		if hash == types.RlpHash(val.cACert) {
			ca.caCertMap[uint64(i)] = ca.caCertMap[uint64(amount)]
			ca.caCertMap[uint64(amount)].isStore = false

			ca.cAAmount--
			return true, nil
		}
	}

	return false, errors.New("not find the ca cert")
}

func (ca *CACertList) GetCaCertAmount() uint64 {
	return ca.cAAmount
}

func (ca *CACertList) checkProposal(pHash common.Hash, senderCert []byte, cACert []byte, evm *EVM, needDo uint8) (bool, error) {

	if ca.proposalMap[pHash] == nil {
		log.Info("--why is nil??", "senderCert", senderCert, "pHash", pHash)
		ca.proposalMap[pHash] = &ProposalState{pState: pStateNil}
		ca.proposalMap[pHash].signMap = make(map[common.Hash]bool)
	}
	ppState := ca.proposalMap[pHash].pState

	if ppState != pStateNil && ppState != pStatePending {
		// need new one proposal
		log.Info("retrurn err?? checkProposal ")
		return false, errors.New("the proposal state not rgiht")
	}

	senderCertHash := types.RlpHash(senderCert)
	if !ca.proposalMap[pHash].signMap[senderCertHash] {
		ca.proposalMap[pHash].signList = append(ca.proposalMap[pHash].signList, senderCertHash)
		ca.proposalMap[pHash].signMap[senderCertHash] = true
	}

	if ppState == pStateNil {
		log.Info("the new one")
		ca.proposalMap[pHash].pHash = pHash
		ca.proposalMap[pHash].cACert = cACert
		ca.proposalMap[pHash].startHight = evm.Context.BlockNumber
		ca.proposalMap[pHash].endHight = new(big.Int).Add(evm.Context.BlockNumber, big.NewInt(proposalTimeLine))
		ca.proposalMap[pHash].needPconfirmNumber = (ca.cAAmount / 3) * 2
		ca.proposalMap[pHash].pNeedDo = needDo
		ca.proposalMap[pHash].pState = pStatePending
	} else {
		if ppState == pStatePending {
			//check time
			log.Info("have lote of pepole check")
			newHight := evm.Context.BlockNumber
			if newHight.Cmp(ca.proposalMap[pHash].endHight) > 0 {
				ca.proposalMap[pHash].pState = pStateFail
				return false, errors.New("proposal time is over 1000 block hight")
			}

			confirmLen := len(ca.proposalMap[pHash].signList)
			if uint64(confirmLen) >= ca.proposalMap[pHash].needPconfirmNumber {
				// do proposal
				res, err := ca.exeProposal(pHash)

				return res, err
			}
		}
	}
	return true, nil
}

func (ca *CACertList) exeProposal(pHash common.Hash) (bool, error) {
	ca.proposalMap[pHash].pState = pStateFail

	var res bool
	var err error
	if ca.proposalMap[pHash].pNeedDo == proposalAddCert {
		res, err = ca.addCertToList(ca.proposalMap[pHash].cACert)
		if res && err == nil {
			ca.proposalMap[pHash].pState = pStateSuccless
			return true, nil
		}
	} else {
		if ca.proposalMap[pHash].pNeedDo == proposalDelCert {
			res, err = ca.delCertToList(ca.proposalMap[pHash].cACert)
			if res && err == nil {
				ca.proposalMap[pHash].pState = pStateSuccless
				return true, nil
			}
		}
	}
	return res, err
}

//*************************
//contract logic
//*************************

// StakingGas defines all method gas
var CaCertStoreGas = map[string]uint64{
	"getCaAmount":     360000,
	"addCaCert":       450000,
	"delCaCert":       30000,
	"isApproveCaCert": 2400000,
	"multiProposal":   2400000,
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
	log.Info("---------------------func RunCaCertStore neo2020310 ", "name", method.Name)
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
	case "multiProposal":
		ret, err = multiProposal(evm, contract, data)
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

func getCaAmount(evm *EVM, contract *Contract, input []byte) (ret []byte, err error) {

	method, _ := abiCaCertStore.Methods["getCaAmount"]
	caCertList := NewCACertList()
	err = caCertList.LoadCACertList(evm.StateDB, types.CACertListAddress)
	if err != nil {
		log.Error("Staking load error", "error", err)
		return nil, err
	}

	//amount

	amount := caCertList.GetCaCertAmount()
	log.Info("----amount", "is", amount)
	ret, err = method.Outputs.Pack(amount)

	return ret, err
}

func addCaCert(evm *EVM, contract *Contract, input []byte) (ret []byte, err error) {
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
	_, err = caCertList.addCertToList(caCert)
	if err != nil {
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

func delCaCert(evm *EVM, contract *Contract, input []byte) (ret []byte, err error) {
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
	ok, err = caCertList.IsInList(caCert)
	if !ok {
		//not in list
		return nil, err
	}

	//del
	_, err = caCertList.delCertToList(caCert)
	if err != nil {
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

func isApproveCaCert(evm *EVM, contract *Contract, input []byte) (ret []byte, err error) {

	var caCert []byte

	log.Info(" isApproveCaCert 1")
	method, _ := abiCaCertStore.Methods["isApproveCaCert"]
	err = method.Inputs.Unpack(&caCert, input)
	log.Info(" isApproveCaCert 2", "ca", caCert)
	caCertList := NewCACertList()
	err = caCertList.LoadCACertList(evm.StateDB, types.CACertListAddress)
	if err != nil {
		log.Error("Staking load error", "error", err)
		return nil, err
	}

	//is in list
	var ok bool
	log.Info(" isApproveCaCert 3", "ca", caCert, "calist amount", caCertList.cAAmount)
	ok, _ = caCertList.IsInList(caCert)

	ret, err = method.Outputs.Pack(ok)

	return ret, err
}

func multiProposal(evm *EVM, contract *Contract, input []byte) (ret []byte, err error) {
	args := struct {
		SenderCert []byte
		CaCert     []byte
		IsAdd      bool
	}{}

	//log.Info("--multiProposal",)
	method, _ := abiCaCertStore.Methods["multiProposal"]
	err = method.Inputs.Unpack(&args, input)
	if err != nil {
		return nil, err
	}

	caCertList := NewCACertList()
	err = caCertList.LoadCACertList(evm.StateDB, types.CACertListAddress)
	if err != nil {
		log.Error("Staking load error", "error", err)
		return nil, err
	}

	pHash := types.RlpHash(args.CaCert)
	log.Info("multiProposal arg is ", "senderca", args.SenderCert, "ca", args.CaCert, "isAdd", args.IsAdd)
	//check cacert
	if !args.IsAdd {
		// del this cacert to this group
		res, err := caCertList.IsInList(args.CaCert)

		if !res {
			return nil, err
		}

		//check propsal
		res, err = caCertList.checkProposal(pHash, args.SenderCert, args.CaCert, evm, proposalDelCert)

	} else {
		//add
		caCertList.checkProposal(pHash, args.SenderCert, args.CaCert, evm, proposalAddCert)
	}

	//caCertList.proposalMap[pHash]
	//store
	err = caCertList.SaveCACertList(evm.StateDB, types.CACertListAddress)
	if err != nil {
		log.Error("Ca Cert save state error", "error", err)
		return nil, err
	}
	return nil, nil
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
   	},
	{
    	"name": "multiProposal",
    	"outputs": [],
    	"inputs": [
	  	{
        	"type": "bytes",
        	"name": "SenderCert"
      	},
		{
        	"type": "bytes",
        	"name": "CaCert"
      	},
		{
        	"type": "bool",
        	"name": "IsAdd"
      	}
    	],
    	"constant": false,
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
