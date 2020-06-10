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
	"strings"
	"github.com/taiyuechain/taiyuechain/accounts/abi"
	"github.com/taiyuechain/taiyuechain/log"
	"github.com/taiyuechain/taiyuechain/common"
)

//*************************
//store logic
//*************************


// StakingGas defines all method gas
var PermissionGas = map[string]uint64{
	"grantPermission":     360000,
	"revokePermission":     360000,
	"createGropPermission":     360000,
	"delGropPermission":     360000,
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
		log.Error("No method found RunCaCertStore")
		return nil, ErrPermissionInvalidInput
	}
	log.Info("--------------------- RunPermissionCtr  ", "name", method.Name, "height", evm.BlockNumber.Uint64())
	data := input[4:]

	switch method.Name {
	case "grantPermission":
		ret, err = grantPermission(evm, contract, data)
	case "revokePermission":
		ret, err = revokePermission(evm, contract, data)
	case "createGropPermission":
		ret, err = createGropPermission(evm, contract, data)
	case "delGropPermission":
		ret, err = delGropPermission(evm, contract, data)
	default:
		log.Warn("CA cert store call fallback function")
		err = ErrPermissionInvalidInput
	}

	return ret, err
}

func grantPermission(evm *EVM, contract *Contract, input []byte) (ret []byte, err error) {
	//GrantPermission(creator,from,member,gropAddr common.Address, mPermType ModifyPerminType,gropName string ,whitelistisWork bool) (bool ,error)  {
	args := struct {
		Creator 		common.Address
		Member  		common.Address
		GropAddr		common.Address
		MPermType 		int
		WhitelistisWork bool
	}{}

	method, _ := PermissionABI.Methods["grantPermission"]
	err = method.Inputs.Unpack(&args, input)
	if err != nil {
		return nil, err
	}

	if ModifyPerminType(args.MPermType) != ModifyPerminType_AddSendTxPerm ||
		ModifyPerminType(args.MPermType) != ModifyPerminType_AddSendTxManagerPerm ||
		ModifyPerminType(args.MPermType) != ModifyPerminType_AddCrtContractPerm ||
		ModifyPerminType(args.MPermType) != ModifyPerminType_AddCrtContractManagerPerm ||
		ModifyPerminType(args.MPermType) != ModifyPerminType_AddGropManagerPerm ||
		ModifyPerminType(args.MPermType) != ModifyPerminType_AddGropMemberPerm ||
		ModifyPerminType(args.MPermType) != ModifyPerminType_AddContractMemberPerm ||
		ModifyPerminType(args.MPermType) != ModifyPerminType_AddContractManagerPerm ||
		ModifyPerminType(args.MPermType) != ModifyPerminType_AddWhitListPerm {
		return nil, err
	}

	pTable := NewPerminTable()
	err = pTable.Load(evm.StateDB)
	if err != nil {
		log.Error("Staking load error", "error", err)
		return nil, err
	}
	from := contract.caller.Address()

	res,err:=pTable.GrantPermission(args.Creator,from,args.Member,args.GropAddr,ModifyPerminType(args.MPermType),"",args.WhitelistisWork)
	if !res{
		return nil,err
	}

	pTable.Save(evm.StateDB)


	return []byte{},nil
}
func revokePermission(evm *EVM, contract *Contract, input []byte) (ret []byte, err error) {
	return []byte{},nil
}
func createGropPermission(evm *EVM, contract *Contract, input []byte) (ret []byte, err error) {
	return []byte{},nil
}
func delGropPermission(evm *EVM, contract *Contract, input []byte) (ret []byte, err error) {
	return []byte{},nil
}

const PermissionABIJSON = `
[
	{
    	"name": "grantPermission",
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
    	"name": "grantPermission",
    	"outputs": [],
    	"inputs": [
	  	{
        	"type": "bytes",
        	"name": "Creator"
      	},
		{
        	"type": "bytes",
        	"name": "Member"
      	},
		{
        	"type": "bytes",
        	"name": "GropAddr"
      	},
		{
        	"type": "int",
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
   	}
]
`