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

	lru "github.com/hashicorp/golang-lru"
	"github.com/taiyuechain/taiyuechain/accounts/abi"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/log"
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
	epoch := types.GetEpochIDFromHeight(blockHight).Uint64()
	for i := 0; i < len; i++ {
		ca.addCertToList(caList[i], epoch, true)
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
			make([][]byte,len(val.CACert)),
			make([]bool,len(val.IsStore)),
		}

		for i:=0;i<len(val.CACert);i++{
			items.CACert[i] = append(items.CACert[i],val.CACert[i][:]...)
			items.IsStore[i] = val.IsStore[i]
		}

		tmp.caCertMap[k] = items
	}

	for key, value := range cachaList.proposalMap {
		//log.Info("---clone", "k", key, "value", value.CACert, "isstart", value.PHash)
		item := &ProposalState{
			value.PHash,
			value.CACert,
			big.NewInt(value.StartHeight.Int64()),
			big.NewInt(value.EndHeight.Int64()),
			value.PState,
			value.NeedPconfirmNumber,
			value.PNeedDo,
			value.SignList,
			make(map[common.Hash]bool),
		}

		for k,v := range value.SignMap{
			item.SignMap[k] = v
		}
		tmp.proposalMap[key] = item
	}
	return tmp
}

func (ca *CACertList) GetCACertMapByEpoch(epoch uint64) *CACert {
	return ca.caCertMap[epoch]
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

func (ca *CACertList) addCertToList(caCert []byte, epoch uint64, isInit bool) (bool, error) {
	if len(caCert) == 0 {
		return false, errors.New("ca cert len is zeor")
	}
	if !isInit {

		ok, _ := ca.IsInList(caCert, epoch)
		//log.Info("---addCertToList", "isInlist", ok, "caCert", caCert)
		if ok {
			return false, errors.New("ca cert is alread exit")
		}
	}

	cac := &CACert{}
	if ca.caCertMap[epoch] == nil {
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

func (ca *CACertList) ChangeElectionCaList(blockHight *big.Int, state StateDB) {
	epoch := types.GetEpochIDFromHeight(blockHight).Uint64()
	_, end := types.GetEpochHeigth(new(big.Int).SetUint64(epoch))

	if blockHight.Uint64() >= end.Uint64()-types.EpochElectionPoint {
		if ca.caCertMap[epoch+1] == nil {
			ca.copyCertToList(epoch)
			ca.SaveCACertList(state, types.CACertListAddress)
		}
	}
}

func (ca *CACertList) GetCaCertAmount(epoch uint64) uint64 {
	if ca.caCertMap[epoch] == nil {
		return uint64(0)
	}
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

	epoch := types.GetEpochIDFromHeight(evm.BlockNumber).Uint64()
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
	epoch := types.GetEpochIDFromHeight(blockHight).Uint64()
	var res bool
	var err error
	if ca.proposalMap[pHash].PNeedDo == proposalAddCert {
		ca.copyCertToList(epoch)
		res, err = ca.addCertToList(ca.proposalMap[pHash].CACert, epoch+1, false)
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
	log.Info("---------------------func RunCaCertStore neo2020310 ", "name", method.Name, "height", evm.BlockNumber.Uint64())
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

	epoch := types.GetEpochIDFromHeight(evm.Context.BlockNumber).Uint64()

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

	epoch := types.GetEpochIDFromHeight(evm.BlockNumber).Uint64()

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

	epoch := types.GetEpochIDFromHeight(evm.Context.BlockNumber).Uint64()
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
