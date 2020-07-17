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
	"github.com/taiyuechain/taiyuechain/accounts/abi"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/log"
	"math/big"
	"strings"
)

//*************************
//store logic
//*************************

// StakingGas defines all method gas
var PermissionGas = map[string]uint64{
	"grantPermission":       360000,
	"revokePermission":      360000,
	"createGroupPermission": 360000,
	"delGroupPermission":    360000,
}

// Staking contract ABI
var PermissionABI abi.ABI

//type CaRootContract struct{}
type PermissionContract struct{}

func init() {
	PermissionABI, _ = abi.JSON(strings.NewReader(PermissionABIJSON))
}

// RunStaking execute taiyuechain staking contract
func RunPermissionCtr(evm *EVM, contract *Contract, input []byte) (ret []byte, err error) {
	method, err := PermissionABI.MethodById(input)
	if err != nil {
		log.Error("No method found RunPermissionCtr","err",err)
		return nil, ErrPermissionInvalidInput
	}
	data := input[4:]

	switch method.Name {
	case "grantPermission":
		ret, err = grantPermission(evm, contract, data)
	case "revokePermission":
		ret, err = revokePermission(evm, contract, data)
	case "createGroupPermission":
		ret, err = createGroupPermission(evm, contract, data)
	case "delGroupPermission":
		ret, err = delGroupPermission(evm, contract, data)
	default:
		log.Warn("CA cert store call fallback function")
		err = ErrPermissionInvalidInput
	}

	return ret, err
}

func grantPermission(evm *EVM, contract *Contract, input []byte) (ret []byte, err error) {
	//GrantPermission(creator,from,member,gropAddr common.Address, mPermType ModifyPerminType,GroupName string ,whitelistisWork bool) (bool ,error)  {
	args := struct {
		ContractAddr    common.Address
		Member          common.Address
		GropAddr        common.Address
		MPermType       *big.Int
		WhitelistisWork bool
	}{}

	method, _ := PermissionABI.Methods["grantPermission"]
	err = method.Inputs.Unpack(&args, input)
	if err != nil {
		return nil, err
	}

	pTable := NewPerminTable()
	err = pTable.Load(evm.StateDB)
	if err != nil {
		log.Error("Staking load error", "error", err)
		return nil, err
	}

	from := pTable.ChangeRootTOImage(contract.caller.Address())
	creator := pTable.GetCreator(from)

	if creator == (common.Address{}) {
		return nil, ErrPermissionInvalidFrom
	}

 	group_Contract_Addr := args.ContractAddr

	if ModifyPerminType(args.MPermType.Int64()) == ModifyPerminType_AddGropManagerPerm ||
		ModifyPerminType(args.MPermType.Int64()) == ModifyPerminType_AddGropMemberPerm {
		group_Contract_Addr = args.GropAddr
	}
	if !pTable.CheckActionPerm(from, args.GropAddr, group_Contract_Addr, ModifyPerminType(args.MPermType.Int64())) {
		return nil, err
	}

	res, err := pTable.GrantPermission(creator, from, args.Member, group_Contract_Addr, ModifyPerminType(args.MPermType.Int64()), "", args.WhitelistisWork)
	if !res {
		return nil, err
	}

	pTable.Save(evm.StateDB)

	log.Info("grantPermission","number",evm.BlockNumber.Uint64(),"permission",args.MPermType)
	return []byte{}, nil
}
func revokePermission(evm *EVM, contract *Contract, input []byte) (ret []byte, err error) {
	//GrantPermission(creator,from,member,gropAddr common.Address, mPermType ModifyPerminType,GroupName string ,whitelistisWork bool) (bool ,error)  {
	args := struct {
		ContractAddr    common.Address
		Member          common.Address
		GropAddr        common.Address
		MPermType       *big.Int
		WhitelistisWork bool
	}{}

	method, _ := PermissionABI.Methods["revokePermission"]
	err = method.Inputs.Unpack(&args, input)
	if err != nil {
		return nil, err
	}

	/*if ModifyPerminType(args.MPermType) != ModifyPerminType_AddSendTxPerm || ModifyPerminType(args.MPermType) != ModifyPerminType_AddSendTxManagerPerm || ModifyPerminType(args.MPermType) != ModifyPerminType_AddCrtContractPerm || ModifyPerminType(args.MPermType) != ModifyPerminType_AddCrtContractManagerPerm || ModifyPerminType(args.MPermType) != ModifyPerminType_AddGropManagerPerm || ModifyPerminType(args.MPermType) != ModifyPerminType_AddGropMemberPerm || ModifyPerminType(args.MPermType) != ModifyPerminType_AddContractMemberPerm || ModifyPerminType(args.MPermType) != ModifyPerminType_AddContractManagerPerm || ModifyPerminType(args.MPermType) != ModifyPerminType_AddWhitListPerm {
		return nil, err
	}*/

	pTable := NewPerminTable()
	err = pTable.Load(evm.StateDB)
	if err != nil {
		log.Error("Staking load error", "error", err)
		return nil, err
	}
	from := pTable.ChangeRootTOImage(contract.caller.Address())
	creator := pTable.GetCreator(from)
	if len(creator) == 0 {
		return nil, ErrPermissionInvalidFrom
	}

	group_Contract_Addr := args.ContractAddr

	if ModifyPerminType(args.MPermType.Int64()) == ModifyPerminType_DelGropManagerPerm ||
		ModifyPerminType(args.MPermType.Int64()) == ModifyPerminType_DelGropMemberPerm ||
		ModifyPerminType(args.MPermType.Int64()) == ModifyPerminType_DelGrop {
		group_Contract_Addr = args.GropAddr
	}

	if !pTable.CheckActionPerm(from, args.GropAddr, group_Contract_Addr, ModifyPerminType(args.MPermType.Int64())) {
		return nil, err
	}

	res, err := pTable.GrantPermission(creator, from, args.Member, group_Contract_Addr, ModifyPerminType(args.MPermType.Int64()), "", args.WhitelistisWork)
	if !res {
		return nil, err
	}

	pTable.Save(evm.StateDB)

	log.Info("revokePermission","number",evm.BlockNumber.Uint64(),"permission",args.MPermType)
	return []byte{}, nil
}
func createGroupPermission(evm *EVM, contract *Contract, input []byte) (ret []byte, err error) {
	args := struct {
		GroupName string
	}{}

	method, _ := PermissionABI.Methods["createGroupPermission"]
	err = method.Inputs.Unpack(&args, input)
	if err != nil {
		return nil, err
	}
	pTable := NewPerminTable()
	err = pTable.Load(evm.StateDB)
	if err != nil {
		log.Error("Staking load error", "error", err)
		return nil, err
	}
	from := pTable.ChangeRootTOImage(contract.caller.Address())
	if !pTable.CheckActionPerm(from, common.Address{}, common.Address{}, ModifyPerminType_CrtGrop) {
		return nil, err
	}

	res, err := pTable.GrantPermission(from, from, common.Address{}, common.Address{}, ModifyPerminType_CrtGrop, args.GroupName, false)
	if !res {
		return nil, err
	}


	pTable.Save(evm.StateDB)

	groupAddr :=pTable.GetLastGroupAddr(from)

	event := PermissionABI.Events["createGroup"]
	logData, err := event.Inputs.PackNonIndexed(args.GroupName)
	if err != nil {
		log.Error("Pack permission log error", "error", err)
		return nil, err
	}
	topics := []common.Hash{
		event.ID,
		common.BytesToHash(groupAddr[:]),
	}
	logForReceipt(evm, contract, topics, logData)

	ret, err = method.Outputs.Pack(groupAddr)
	log.Info("createGroupPermission","number",evm.BlockNumber.Uint64(),"groupName",args.GroupName,"groupAddr",crypto.AddressToHex(groupAddr))
	return ret, err
}
func delGroupPermission(evm *EVM, contract *Contract, input []byte) (ret []byte, err error) {
	args := struct {
		GroupAddr common.Address
	}{}

	method, _ := PermissionABI.Methods["delGroupPermission"]
	err = method.Inputs.Unpack(&args, input)
	if err != nil {
		return nil, err
	}
	pTable := NewPerminTable()
	err = pTable.Load(evm.StateDB)
	if err != nil {
		log.Error("Staking load error", "error", err)
		return nil, err
	}
	from := pTable.ChangeRootTOImage(contract.caller.Address())
	if !pTable.CheckActionPerm(from, args.GroupAddr, common.Address{}, ModifyPerminType_DelGrop) {
		return nil, err
	}

	res, err := pTable.GrantPermission(from, from, common.Address{}, args.GroupAddr, ModifyPerminType_DelGrop, "", false)
	if !res {
		return nil, err
	}

	pTable.Save(evm.StateDB)
	log.Info("delGroupPermission","number",evm.BlockNumber.Uint64(),"GroupAddr",crypto.AddressToHex(args.GroupAddr))
	return []byte{}, nil
}

const PermissionABIJSON = `
[
	{
    	"name": "createGroup",
    	"inputs": [
	  		{
        	"type": "address",
        	"name": "GropAddr",
	        "indexed": true
      		},
	  		{
        	"type": "string",
        	"name": "GroupName",
	        "indexed": false
      		}
    	],
	    "anonymous": false,
    	"type": "event"
   	},
	{
    	"name": "grantPermission",
    	"outputs": [],
    	"inputs": [
		{
        	"type": "address",
        	"name": "ContractAddr"
      	},
		{
        	"type": "address",
        	"name": "Member"
      	},
		{
        	"type": "address",
        	"name": "GropAddr"
      	},
		{
        	"type": "uint256",
        	"name": "MPermType"
      	},
		{
        	"type": "bool",
        	"name": "WhitelistisWork"
      	}
    	],
    	"constant": false,
    	"payable": false,
    	"type": "function"
   	},
	{
    	"name": "revokePermission",
    	"outputs": [],
    	"inputs": [
		{
        	"type": "address",
        	"name": "ContractAddr"
      	},
		{
        	"type": "address",
        	"name": "Member"
      	},
		{
        	"type": "address",
        	"name": "GropAddr"
      	},
		{
        	"type": "uint256",
        	"name": "MPermType"
      	},
		{
        	"type": "bool",
        	"name": "WhitelistisWork"
      	}
    	],
    	"constant": false,
    	"payable": false,
    	"type": "function"
   	},
	{
    	"name": "createGroupPermission",
    	"outputs": [
			{
        	"type": "address",
        	"name": "GropAddr"
      		}
		],
    	"inputs": [
	  	{
        	"type": "string",
        	"name": "GroupName"
      	}
    	],
    	"constant": false,
    	"payable": false,
    	"type": "function"
   	},
	{
    	"name": "delGroupPermission",
    	"outputs": [],
    	"inputs": [
	  	{
        	"type": "address",
        	"name": "GroupAddr"
      	}
    	],
    	"constant": false,
    	"payable": false,
    	"type": "function"
   	}
]
`
