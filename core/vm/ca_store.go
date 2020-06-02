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
	"encoding/hex"
	//"math/big"
	"errors"
	"strings"
	//"time"
	"fmt"

	lru "github.com/hashicorp/golang-lru"
	"github.com/taiyuechain/taiyuechain/accounts/abi"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/consensus/tbft/help"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/log"
	"github.com/taiyuechain/taiyuechain/rlp"
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
	electionHgiht    = 1000
	electionPerHgith = electionHgiht - 100
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
	CACert  [][]byte
	IsStore []bool
}

func (cacert *CACert) GetByte(point int) []byte {
	if point > len(cacert.CACert) && point >= 0 {
		return nil
	}
	return cacert.CACert[point]
}

func (cacert *CACert) GetIsStore(point int) bool {
	if point > len(cacert.CACert) && point >= 0 {
		return false
	}
	return cacert.IsStore[point]
}

type ProposalState struct {
	PHash              common.Hash
	CACert             []byte
	StartHeight        *big.Int
	EndHeight          *big.Int
	PState             uint8
	NeedPconfirmNumber uint64 // muti need confir len
	PNeedDo            uint8  // only supprot add and del
	SignList           []common.Hash
	SignMap            map[common.Hash]bool
}

type CACertList struct {
	caCertMap   map[uint64]*CACert
	proposalMap map[common.Hash]*ProposalState
}

// new a CACerList
func NewCACertList() *CACertList {
	return &CACertList{
		caCertMap:   make(map[uint64]*CACert),
		proposalMap: make(map[common.Hash]*ProposalState),
	}
}

func (ca *CACertList) InitCACertList(caList [][]byte, blockHight *big.Int) {

	len := len(caList)
	epoch := blockHight.Uint64() / electionHgiht
	for i := 0; i < len; i++ {
		ca.addCertToList(caList[i], epoch)
	}
}

func CloneCaCache(cachaList *CACertList) *CACertList {
	if cachaList == nil {
		return nil
	}

	tmp := &CACertList{

		caCertMap:   make(map[uint64]*CACert),
		proposalMap: make(map[common.Hash]*ProposalState),
	}

	for k, val := range cachaList.caCertMap {
		items := &CACert{
			val.CACert,
			val.IsStore,
		}

		tmp.caCertMap[k] = items
	}

	for key, value := range cachaList.proposalMap {
		//log.Info("---clone", "k", key, "value", value.CACert, "isstart", value.PHash)
		item := &ProposalState{
			value.PHash,
			value.CACert,
			value.StartHeight,
			value.EndHeight,
			value.PState,
			value.NeedPconfirmNumber,
			value.PNeedDo,
			value.SignList,
			value.SignMap,
		}
		tmp.proposalMap[key] = item
	}
	return tmp
}

func (ca *CACertList) GetCACertMapByEpoch(epoch uint64) *CACert {
	return ca.caCertMap[epoch]
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

	for k, val := range temp.caCertMap {
		//log.Info("---clone","k",k,"value",val.CACert,"isstart",val.IsStore)
		items := &CACert{
			val.CACert,
			val.IsStore,
		}

		ca.caCertMap[k] = items

	}

	for k, val := range temp.proposalMap {
		//log.Info("--clone 2","k",k,"val",val.CACert)
		item := &ProposalState{
			val.PHash,
			val.CACert,
			val.StartHeight,
			val.EndHeight,
			val.PState,
			val.NeedPconfirmNumber,
			val.PNeedDo,
			val.SignList,
			val.SignMap,
		}

		ca.proposalMap[k] = item
	}
	watch1.EndWatch()
	watch1.Finish("DecodeBytes")
	return nil
}

func (ca *CACertList) SaveCACertList(state StateDB, preAddress common.Address) error {

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
		log.Info("-=-==-=save CA info", "Ce name", val.CACert, "is store", val.PHash)

	}
	state.SetCAState(preAddress, key, data)
	tmp := CloneCaCache(ca)
	if tmp != nil {
		CASC.Cache.Add(hash, tmp)
	}
	return err
}

func (ca *CACertList) IsInList(caCert []byte, epoch uint64) (bool, error) {
	hash := types.RlpHash(caCert)
	certList := ca.caCertMap[epoch]
	for i, val := range certList.CACert {
		//log.Info("-=-==-=CA info", "Ce name", val.CACert, "is store", val.IsStore)
		if hash == types.RlpHash(val) && certList.IsStore[i] == true {
			return true, nil
		}
	}
	return false, errors.New("not in List")
}

func (ca *CACertList) addCertToList(caCert []byte, epoch uint64) (bool, error) {
	if len(caCert) == 0 {
		return false, errors.New("ca cert len is zeor")
	}
	if ca.caCertMap[epoch] == nil {
		return false, errors.New("ca cert list epoch is nil")
	}
	ok, _ := ca.IsInList(caCert, epoch)
	//log.Info("---addCertToList", "isInlist", ok, "caCert", caCert)
	if ok {
		return false, errors.New("ca cert is alread exit")
	}

	cac := &CACert{}
	if len(ca.caCertMap[epoch].CACert) == 0 {
		cac.CACert = append(cac.CACert, caCert)
		cac.IsStore = append(cac.IsStore, true)
		ca.caCertMap[epoch] = cac
	} else {
		ca.caCertMap[epoch].CACert = append(ca.caCertMap[epoch].CACert, caCert)
		ca.caCertMap[epoch].IsStore = append(ca.caCertMap[epoch].IsStore, true)
	}

	return true, nil

}

func (ca *CACertList) delCertToList(caCert []byte, epoch uint64) (bool, error) {
	if len(caCert) == 0 {
		return false, errors.New("ca cert len is zeor")
	}

	if ca.caCertMap[epoch] == nil {
		return false, errors.New("ca cert list epoch is nil")
	}

	hash := types.RlpHash(caCert)
	cerList := ca.caCertMap[epoch].CACert
	for i, val := range cerList {
		if hash == types.RlpHash(val) {
			ca.caCertMap[epoch].CACert = append(ca.caCertMap[epoch].CACert[:i], ca.caCertMap[epoch].CACert[i+1:]...)
			ca.caCertMap[epoch].IsStore = append(ca.caCertMap[epoch].IsStore[:i], ca.caCertMap[epoch].IsStore[i+1:]...)
			return true, nil
		}
	}

	return false, errors.New("not find the ca cert")
}

func (ca *CACertList) copyCertToList(epoch uint64) {

	if ca.caCertMap[epoch+1] == nil {
		calist := &CACert{}
		for i, val := range ca.caCertMap[epoch].CACert {
			calist.CACert = append(calist.CACert, val)
			calist.IsStore = append(calist.IsStore, ca.caCertMap[epoch].IsStore[i])
		}
		ca.caCertMap[epoch+1] = calist
	}
}

func (ca *CACertList) ChangeElectionCaList(blockHight *big.Int) {
	epoch := blockHight.Uint64() / electionHgiht

	if blockHight.Int64() > int64((epoch*electionHgiht)+electionPerHgith) {
		if ca.caCertMap[epoch+1] == nil {
			ca.copyCertToList(epoch)
		}
	}
}

func (ca *CACertList) GetCaCertAmount(epoch uint64) uint64 {
	return uint64(len(ca.caCertMap[epoch].CACert))
}

func (ca *CACertList) checkProposal(pHash common.Hash, senderCert []byte, cACert []byte, evm *EVM, needDo uint8) (bool, error) {

	if ca.proposalMap[pHash] == nil {
		log.Info("--why is nil??", "senderCert", hex.EncodeToString(senderCert), "PHash", pHash)
		ca.proposalMap[pHash] = &ProposalState{PState: pStateNil}
		ca.proposalMap[pHash].SignMap = make(map[common.Hash]bool)
	}
	ppState := ca.proposalMap[pHash].PState

	if ppState != pStateNil && ppState != pStatePending {
		// need new one proposal
		log.Info("retrurn err?? checkProposal ")
		return false, errors.New("the proposal state not rgiht")
	}

	senderCertHash := types.RlpHash(senderCert)
	if !ca.proposalMap[pHash].SignMap[senderCertHash] {
		ca.proposalMap[pHash].SignList = append(ca.proposalMap[pHash].SignList, senderCertHash)
		ca.proposalMap[pHash].SignMap[senderCertHash] = true
	}

	epoch := evm.Context.BlockNumber.Uint64() / electionHgiht
	if ppState == pStateNil {
		log.Info("the new one")
		ca.proposalMap[pHash].PHash = pHash
		ca.proposalMap[pHash].CACert = cACert
		ca.proposalMap[pHash].StartHeight = evm.Context.BlockNumber
		ca.proposalMap[pHash].EndHeight = new(big.Int).Add(evm.Context.BlockNumber, big.NewInt(proposalTimeLine))
		ca.proposalMap[pHash].NeedPconfirmNumber = uint64((len(ca.caCertMap[epoch].CACert) / 3)) * 2
		ca.proposalMap[pHash].PNeedDo = needDo
		ca.proposalMap[pHash].PState = pStatePending
	} else {
		if ppState == pStatePending {
			//check time
			log.Info("have lote of pepole check")
			newHight := evm.Context.BlockNumber
			if newHight.Cmp(ca.proposalMap[pHash].EndHeight) > 0 {
				ca.proposalMap[pHash].PState = pStateFail
				return false, errors.New("proposal time is over 1000 block hight")
			}

			confirmLen := len(ca.proposalMap[pHash].SignList)
			if uint64(confirmLen) >= ca.proposalMap[pHash].NeedPconfirmNumber {
				// do proposal
				res, err := ca.exeProposal(pHash, evm.Context.BlockNumber)

				return res, err
			}
		}
	}
	return true, nil
}

func (ca *CACertList) exeProposal(pHash common.Hash, blockHight *big.Int) (bool, error) {
	ca.proposalMap[pHash].PState = pStateFail
	epoch := blockHight.Uint64() / electionHgiht
	var res bool
	var err error
	if ca.proposalMap[pHash].PNeedDo == proposalAddCert {
		ca.copyCertToList(epoch)
		res, err = ca.addCertToList(ca.proposalMap[pHash].CACert, epoch+1)
		if res && err == nil {
			ca.proposalMap[pHash].PState = pStateSuccless
			return true, nil
		}
	} else {
		if ca.proposalMap[pHash].PNeedDo == proposalDelCert {
			ca.copyCertToList(epoch)
			res, err = ca.delCertToList(ca.proposalMap[pHash].CACert, epoch+1)
			if res && err == nil {
				ca.proposalMap[pHash].PState = pStateSuccless
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

// RunStaking execute taiyuechain staking contract
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

	epoch := evm.Context.BlockNumber.Uint64() / electionHgiht

	amount := caCertList.GetCaCertAmount(epoch)
	log.Info("----amount", "is", amount)
	ret, err = method.Outputs.Pack(amount)

	return ret, err
}

func isApproveCaCert(evm *EVM, contract *Contract, input []byte) (ret []byte, err error) {

	var caCert []byte

	log.Info(" isApproveCaCert 1")
	method, _ := abiCaCertStore.Methods["isApproveCaCert"]
	err = method.Inputs.Unpack(&caCert, input)
	log.Info(" isApproveCaCert 2", "ca", hex.EncodeToString(caCert))
	caCertList := NewCACertList()
	err = caCertList.LoadCACertList(evm.StateDB, types.CACertListAddress)
	if err != nil {
		log.Error("Staking load error", "error", err)
		return nil, err
	}

	epoch := evm.Context.BlockNumber.Uint64() / electionHgiht

	//is in list
	var ok bool
	log.Info(" isApproveCaCert 3", "ca", hex.EncodeToString(caCert), "calist amount", len(caCertList.caCertMap[epoch].CACert))

	ok, _ = caCertList.IsInList(caCert, epoch)

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

	epoch := evm.Context.BlockNumber.Uint64() / electionHgiht
	pHash := types.RlpHash(args.CaCert)
	log.Info("multiProposal arg is ", "senderca", hex.EncodeToString(args.SenderCert), "ca", hex.EncodeToString(args.CaCert), "isAdd", args.IsAdd)
	//check cacert
	if !args.IsAdd {
		// del this cacert to this group
		res, err := caCertList.IsInList(args.CaCert, epoch)

		if !res {
			return nil, err
		}

		//check propsal
		res, err = caCertList.checkProposal(pHash, args.SenderCert, args.CaCert, evm, proposalDelCert)

	} else {
		//add
		caCertList.checkProposal(pHash, args.SenderCert, args.CaCert, evm, proposalAddCert)
	}

	//caCertList.proposalMap[PHash]
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
