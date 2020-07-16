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
	"fmt"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/crypto"
	"runtime/debug"
	"testing"
)

func TestContractManagerPermissionTable(t *testing.T) {
	ptable := initPerminTable(true, true)
	res, err := ptable.GrantPermission(root1, root1, member1, common.Address{}, ModifyPerminType_AddCrtContractPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_AddCrtContractPerm")
	checkBaseCrtContractPermission(member1, t, true, ptable)

	res, err = ptable.GrantPermission(root1, root1, member1, common.Address{}, ModifyPerminType_DelCrtContractPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_DelCrtContractPerm")
	checkBaseCrtContractPermission(member1, t, false, ptable)

	res, err = ptable.GrantPermission(root1, root1, member1, common.Address{}, ModifyPerminType_AddCrtContractManagerPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_AddCrtContractManagerPerm")
	checkBaseCrtManagerContractPermission(member1, t, true, ptable)

	res, err = ptable.GrantPermission(root1, member1, member2, common.Address{}, ModifyPerminType_AddCrtContractPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_AddCrtContractPerm")
	checkBaseCrtContractPermission(member2, t, true, ptable)

	res, err = ptable.GrantPermission(root1, root1, member1, common.Address{}, ModifyPerminType_DelCrtContractManagerPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_DelCrtContractManagerPerm")
	checkBaseCrtContractPermission(member1, t, false, ptable) // true
	checkBaseCrtContractPermission(member2, t, true, ptable)

	res, err = ptable.GrantPermission(root1, root1, member2, common.Address{}, ModifyPerminType_DelCrtContractPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_DelCrtContractPerm")
	checkBaseCrtContractPermission(member2, t, false, ptable)
}

func TestCreateContractPermissionTable(t *testing.T) {
	ptable := initPerminTable(true, true)
	res, err := ptable.GrantPermission(root1, root1, member1, common.Address{}, ModifyPerminType_AddCrtContractPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_AddCrtContractPerm")

	checkBaseCrtContractPermission(member1, t, true, ptable)
	checkBaseSendTxPermission(member1, t, false, ptable)

	res, err = ptable.GrantPermission(root1, root1, member1, common.Address{}, ModifyPerminType_AddSendTxPerm, "a", true)
	printResError(res, err, t, "Grent err")
	checkBaseSendTxPermission(member1, t, true, ptable)
	checkBaseCrtContractPermission(member1, t, true, ptable)

	//ModifyPerminType_CrtContractPerm
	contractAddr := crypto.CreateAddress(member1, 2)
	ptable.CreateContractPem(contractAddr, member1, uint64(2), false)
	res, err = ptable.GrantPermission(member1, member1, member1, contractAddr, ModifyPerminType_CrtContractPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_CrtContractPerm")
	checkBaseManagerContractPermission(member1, contractAddr, t, true, ptable)

	res, err = ptable.GrantPermission(root1, member1, member2, contractAddr, ModifyPerminType_AddContractMemberPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_AddContractMemberPerm")
	// new 2

	res, err = ptable.GrantPermission(root1, root1, member2, common.Address{}, ModifyPerminType_AddSendTxPerm, "a", true)
	printResError(res, err, t, "Grent err")
	checkBaseSendTxPermission(member2, t, true, ptable)
	checkBaseContractPermission(member2, contractAddr, t, true, ptable)

	//ModifyPerminType_DelContractMemberPerm
	res, err = ptable.GrantPermission(member1, member1, member2, contractAddr, ModifyPerminType_DelContractMemberPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_DelContractMemberPerm")
	checkBaseContractPermission(member2, contractAddr, t, false, ptable)
}

// contract group ? delete contract group
func TestContractPermissionTable(t *testing.T) {
	ptable := initPerminTable(true, true)
	res, err := ptable.GrantPermission(root1, root1, member1, common.Address{}, ModifyPerminType_AddSendTxPerm, "a", true)
	printResError(res, err, t, "Grent err")
	checkBaseSendTxPermission(member1, t, true, ptable)
	res, err = ptable.GrantPermission(root1, root1, member2, common.Address{}, ModifyPerminType_AddSendTxPerm, "a", true)
	printResError(res, err, t, "Grent err")
	checkBaseSendTxPermission(member2, t, true, ptable)

	res, err = ptable.GrantPermission(root1, root1, member1, common.Address{}, ModifyPerminType_AddCrtContractPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_AddCrtContractPerm")
	checkBaseCrtContractPermission(member1, t, true, ptable)

	//checkSendTxPermission(member1,t,true)
	//ModifyPerminType_CrtContractPerm
	contractAddr := crypto.CreateAddress(member1, 2)
	ptable.CreateContractPem(contractAddr, member1, uint64(2), false)
	res, err = ptable.GrantPermission(member1, member1, member1, contractAddr, ModifyPerminType_CrtContractPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_CrtContractPerm")
	checkBaseManagerContractPermission(member1, contractAddr, t, true, ptable)

	res, err = ptable.GrantPermission(root1, member1, member2, contractAddr, ModifyPerminType_AddContractMemberPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_AddContractMemberPerm")
	// new 2
	checkBaseContractPermission(member2, contractAddr, t, true, ptable)

	//ModifyPerminType_DelContractMemberPerm
	res, err = ptable.GrantPermission(member1, member1, member2, contractAddr, ModifyPerminType_DelContractMemberPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_DelContractMemberPerm")
	checkBaseContractPermission(member2, contractAddr, t, false, ptable)

	//ModifyPerminType_AddContractMemberPerm
	res, err = ptable.GrantPermission(member1, member1, member2, contractAddr, ModifyPerminType_AddContractMemberPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_AddContractMemberPerm")
	checkBaseContractPermission(member2, contractAddr, t, true, ptable)

	//ModifyPerminType_AddContractManagerPerm
	res, err = ptable.GrantPermission(member1, member1, member2, contractAddr, ModifyPerminType_AddContractManagerPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_AddContractManagerPerm")
	checkBaseManagerContractPermission(member2, contractAddr, t, true, ptable)

	res, err = ptable.GrantPermission(member1, member2, member3, contractAddr, ModifyPerminType_AddContractMemberPerm, "a", true)
	checkBaseContractPermission(member3, contractAddr, t, false, ptable)

	res, err = ptable.GrantPermission(root1, root1, member3, common.Address{}, ModifyPerminType_AddSendTxPerm, "a", true)
	printResError(res, err, t, "Grent err")
	checkBaseContractPermission(member3, contractAddr, t, true, ptable)

	//ModifyPerminType_DelContractManagerPerm
	res, err = ptable.GrantPermission(member1, member1, member2, contractAddr, ModifyPerminType_DelContractManagerPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_DelContractManagerPerm")
	checkBaseContractPermission(member2, contractAddr, t, true, ptable)
	checkBaseContractPermission(member3, contractAddr, t, true, ptable)
}

func TestContractSimplePermissionTable(t *testing.T) {
	ptable := initPerminTable(true, true)
	res, err := ptable.GrantPermission(root1, root1, member1, common.Address{}, ModifyPerminType_AddSendTxPerm, "a", true)
	printResError(res, err, t, "Grent err")
	checkBaseSendTxPermission(member1, t, true, ptable)
	res, err = ptable.GrantPermission(root1, root1, member2, common.Address{}, ModifyPerminType_AddSendTxPerm, "a", true)
	printResError(res, err, t, "Grent err")
	checkBaseSendTxPermission(member2, t, true, ptable)

	res, err = ptable.GrantPermission(root1, root1, member1, common.Address{}, ModifyPerminType_AddCrtContractPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_AddCrtContractPerm")

	checkBaseCrtContractPermission(member1, t, true, ptable)

	//ModifyPerminType_CrtContractPerm
	contractAddr := crypto.CreateAddress(member1, 2)
	ptable.CreateContractPem(contractAddr, member1, uint64(2), false)
	res, err = ptable.GrantPermission(member1, member1, member1, contractAddr, ModifyPerminType_CrtContractPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_CrtContractPerm")
	checkBaseManagerContractPermission(member1, contractAddr, t, true, ptable)

	//ModifyPerminType_AddContractMemberPerm
	res, err = ptable.GrantPermission(root1, member1, member2, contractAddr, ModifyPerminType_AddContractMemberPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_AddContractMemberPerm")
	checkBaseContractPermission(member2, contractAddr, t, true, ptable)

	//ModifyPerminType_DelContractMemberPerm
	res, err = ptable.GrantPermission(root1, member1, member2, contractAddr, ModifyPerminType_DelContractMemberPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_DelContractMemberPerm")
	checkBaseContractPermission(member2, contractAddr, t, false, ptable)

	//ModifyPerminType_AddContractManagerPerm
	res, err = ptable.GrantPermission(root1, member1, member2, contractAddr, ModifyPerminType_AddContractManagerPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_AddContractManagerPerm")
	checkBaseManagerContractPermission(member2, contractAddr, t, true, ptable)

	//ModifyPerminType_DelContractManagerPerm
	res, err = ptable.GrantPermission(root1, member1, member2, contractAddr, ModifyPerminType_DelContractManagerPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_DelContractManagerPerm")
	checkBaseManagerContractPermission(member2, contractAddr, t, false, ptable)

	res, err = ptable.GrantPermission(root1, root1, member1, common.Address{}, ModifyPerminType_DelCrtContractPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_DelCrtContractPerm")
	checkBaseCrtContractPermission(member1, t, false, ptable)

	res, err = ptable.GrantPermission(root1, root1, member1, common.Address{}, ModifyPerminType_AddCrtContractManagerPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_AddCrtContractManagerPerm")
	checkBaseCrtManagerContractPermission(member1, t, true, ptable)

	res, err = ptable.GrantPermission(root1, root1, member1, common.Address{}, ModifyPerminType_DelCrtContractManagerPerm, "a", true)
	printResError(res, err, t, "Grent err,ModifyPerminType_DelCrtContractManagerPerm")

	checkBaseCrtManagerContractPermission(member1, t, false, ptable)
}

func TestContractNormalPermissionTable(t *testing.T) {
	ptable := initPerminTable(true, true)
	res, err := ptable.GrantPermission(root1, root1, member1, common.Address{}, ModifyPerminType_AddSendTxPerm, "a", true)
	printResError(res, err, t, "Grent err")
	checkBaseSendTxPermission(member1, t, true, ptable)
	res, err = ptable.GrantPermission(root1, root1, member2, common.Address{}, ModifyPerminType_AddSendTxPerm, "a", true)
	printResError(res, err, t, "Grent err")
	checkBaseSendTxPermission(member2, t, true, ptable)
	res, err = ptable.GrantPermission(root1, root1, member1, common.Address{}, ModifyPerminType_AddCrtContractPerm, "a", true)
	if !res {
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_AddSendTxManagerPerm")
	}
	if ptable.CheckActionPerm(member1, common.Address{}, common.Address{}, ModifyPerminType_AddCrtContractPerm) {

		t.Fatalf("CheckActionPerm err ModifyPerminType_AddCrtContractPerm")
	}
	if !ptable.CheckActionPerm(member1, common.Address{}, common.Address{}, PerminType_CreateContract) {

		t.Fatalf("CheckActionPerm err PerminType_SendTx")
	}

	//ModifyPerminType_CrtContractPerm
	contractAddr := crypto.CreateAddress(member1, 2)
	ptable.CreateContractPem(contractAddr, member1, uint64(2), false)
	res, err = ptable.GrantPermission(member1, member1, member1, contractAddr, ModifyPerminType_CrtContractPerm, "a", true)
	if !res {
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_CrtContractPerm")
	}
	//ModifyPerminType_AddContractMemberPerm
	if !ptable.CheckActionPerm(member1, common.Address{}, contractAddr, ModifyPerminType_AddContractMemberPerm) {

		t.Fatalf("CheckActionPerm err ModifyPerminType_AddContractMemberPerm")
	}
	res, err = ptable.GrantPermission(member1, member1, member2, contractAddr, ModifyPerminType_AddContractMemberPerm, "a", true)
	if !res {
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_CrtContractPerm")
	}
	//ModifyPerminType_DelContractMemberPerm
	res, err = ptable.GrantPermission(member1, member1, member2, contractAddr, ModifyPerminType_DelContractMemberPerm, "a", true)
	if !res {
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_DelContractMemberPerm")
	}
	//ModifyPerminType_AddContractManagerPerm
	res, err = ptable.GrantPermission(member1, member1, member2, contractAddr, ModifyPerminType_AddContractManagerPerm, "a", true)
	if !res {
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_CrtContractPerm")
	}
	checkBaseManagerContractPermission(member2, contractAddr, t, true, ptable)
	if !ptable.CheckActionPerm(member2, common.Address{}, contractAddr, ModifyPerminType_AddContractMemberPerm) {

		t.Fatalf("CheckActionPerm err ModifyPerminType_AddContractMemberPerm")
	}
	if !ptable.CheckActionPerm(member2, common.Address{}, contractAddr, ModifyPerminType_DelContractMemberPerm) {

		t.Fatalf("CheckActionPerm err ModifyPerminType_AddContractMemberPerm")
	}
	//ModifyPerminType_DelContractManagerPerm
	res, err = ptable.GrantPermission(member2, member1, member2, contractAddr, ModifyPerminType_DelContractManagerPerm, "a", true)
	if !res {
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_CrtContractPerm")
	}
	if ptable.CheckActionPerm(member2, common.Address{}, contractAddr, ModifyPerminType_DelContractMemberPerm) {

		t.Fatalf("CheckActionPerm err ModifyPerminType_AddContractMemberPerm")
	}
	if ptable.CheckActionPerm(member2, common.Address{}, contractAddr, ModifyPerminType_AddContractMemberPerm) {

		t.Fatalf("CheckActionPerm err ModifyPerminType_AddContractMemberPerm")
	}

	res, err = ptable.GrantPermission(root1, root1, member1, common.Address{}, ModifyPerminType_DelCrtContractPerm, "a", true)
	if !res {
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_AddSendTxManagerPerm")
	}
	if ptable.CheckActionPerm(member1, common.Address{}, common.Address{}, PerminType_CreateContract) {

		t.Fatalf("CheckActionPerm err PerminType_SendTx")
	}

	res, err = ptable.GrantPermission(root1, root1, member1, common.Address{}, ModifyPerminType_AddCrtContractManagerPerm, "a", true)
	if !res {
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_AddCrtContractManagerPerm")
	}
	if !ptable.CheckActionPerm(member1, common.Address{}, common.Address{}, ModifyPerminType_AddCrtContractManagerPerm) {

		t.Fatalf("CheckActionPerm err ModifyPerminType_AddCrtContractPerm")
	}
	if !ptable.CheckActionPerm(member1, common.Address{}, common.Address{}, PerminType_CreateContract) {

		t.Fatalf("CheckActionPerm err PerminType_SendTx")
	}

	res, err = ptable.GrantPermission(root1, root1, member1, common.Address{}, ModifyPerminType_DelCrtContractManagerPerm, "a", true)
	if !res {
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_AddCrtContractManagerPerm")
	}
	if ptable.CheckActionPerm(member1, common.Address{}, common.Address{}, ModifyPerminType_DelCrtContractManagerPerm) {

		t.Fatalf("CheckActionPerm err ModifyPerminType_AddCrtContractPerm")
	}
	if ptable.CheckActionPerm(member1, common.Address{}, common.Address{}, PerminType_CreateContract) {

		t.Fatalf("CheckActionPerm err PerminType_SendTx")
	}
}

func initPerminTable(sendTxFlag, crtContractFlag bool) *PerminTable {
	SetPermConfig(sendTxFlag, crtContractFlag)

	rootList = append(rootList, common.HexToAddress("0x21C16f03bbF085D6908569d159Ad40BcafdB80C5"))
	rootList = append(rootList, common.HexToAddress("0xa9A2CbA5d5d16DE370375B42662F3272279B2b89"))
	rootList = append(rootList, common.HexToAddress("0x6bE9780954580FCC268944e9D6271B3Dfc886997"))
	rootList = append(rootList, common.HexToAddress("0x03096816367827E9C5c1993AE18b237895717500"))

	ptable := NewPerminTable()
	ptable.InitPBFTRootGrop(rootList)

	root1 = rootList[1]
	member1 = common.HexToAddress("0xFE9cFAc0EDf17FB746069f1d12885217fF30234C")
	member2 = common.HexToAddress("0x1b3d007C0D5318D241F26374F379E882cDCbc371")
	member3 = common.HexToAddress("0x5A778953403352839Faf865C82309B63965f15F2")
	return ptable
}

func checkBaseCrtContractPermission(from common.Address, t *testing.T, has bool, ptable *PerminTable) {
	checkCreateContractTxPermission(ptable, from, t, has)

	checkAddContractPermission(ptable, from, t, false)
	checkDelContractPermission(ptable, from, t, false)
	checkAddCrtContractManagerPermission(ptable, from, t, false)
	checkDelCrtContractManagerPermission(from, t, false, ptable)
}

func checkBaseCrtManagerContractPermission(from common.Address, t *testing.T, has bool, ptable *PerminTable) {
	checkCreateContractTxPermission(ptable, from, t, has)
	checkAddContractPermission(ptable, from, t, has)
	checkDelContractPermission(ptable, from, t, has)
	checkAddCrtContractManagerPermission(ptable, from, t, has)
	checkDelCrtContractManagerPermission(from, t, has, ptable)
}

func checkBaseContractPermission(from, contract common.Address, t *testing.T, has bool, ptable *PerminTable) {
	checkAccessContractPermission(from, contract, t, has, ptable)

	checkAddContractMemberPermission(from, contract, t, false, ptable)
	checkDelContractMemberPermission(from, contract, t, false, ptable)
	checkAddContractManagerPermission(from, contract, t, false, ptable)
	checkDelContractManagerPermission(from, contract, t, false, ptable)
}

func checkBaseManagerContractPermission(from, contract common.Address, t *testing.T, has bool, ptable *PerminTable) {
	checkAccessContractPermission(from, contract, t, has, ptable)

	checkAddContractMemberPermission(from, contract, t, has, ptable)
	checkDelContractMemberPermission(from, contract, t, has, ptable)
	checkAddContractManagerPermission(from, contract, t, has, ptable)
	checkDelContractManagerPermission(from, contract, t, has, ptable)
}

func checkCreateContractTxPermission(ptable *PerminTable, from common.Address, t *testing.T, has bool) {
	//if has {
	//	checkSendTxPermission(from,t,true)
	//}

	if ptable.CheckActionPerm(from, common.Address{}, common.Address{}, PerminType_CreateContract) != has {
		printStack("CheckActionPerm err PerminType_CreateContract", t)
	}
}

func checkAddContractPermission(ptable *PerminTable, from common.Address, t *testing.T, has bool) {
	if ptable.CheckActionPerm(from, common.Address{}, common.Address{}, ModifyPerminType_AddCrtContractPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_AddCrtContractPerm", t)
	}
}

func checkDelContractPermission(ptable *PerminTable, from common.Address, t *testing.T, has bool) {
	if ptable.CheckActionPerm(from, common.Address{}, common.Address{}, ModifyPerminType_DelCrtContractPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_DelCrtContractPerm", t)
	}
}

func checkAddCrtContractManagerPermission(ptable *PerminTable, from common.Address, t *testing.T, has bool) {
	if ptable.CheckActionPerm(from, common.Address{}, common.Address{}, ModifyPerminType_AddCrtContractManagerPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_AddCrtContractManagerPerm", t)
	}
}

func checkDelCrtContractManagerPermission(from common.Address, t *testing.T, has bool, ptable *PerminTable) {
	if ptable.CheckActionPerm(from, common.Address{}, common.Address{}, ModifyPerminType_DelCrtContractManagerPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_DelCrtContractManagerPerm", t)
	}
}

func checkAddContractMemberPermission(from, contractAddr common.Address, t *testing.T, has bool, ptable *PerminTable) {
	if ptable.CheckActionPerm(from, common.Address{}, contractAddr, ModifyPerminType_AddContractMemberPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_AddContractMemberPerm", t)
	}
}

func checkDelContractMemberPermission(from, contractAddr common.Address, t *testing.T, has bool, ptable *PerminTable) {
	if ptable.CheckActionPerm(from, common.Address{}, contractAddr, ModifyPerminType_DelContractMemberPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_DelContractMemberPerm", t)
	}
}

func checkAddContractManagerPermission(from, contract common.Address, t *testing.T, has bool, ptable *PerminTable) {
	if ptable.CheckActionPerm(from, common.Address{}, contract, ModifyPerminType_AddContractManagerPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_AddCrtContractManagerPerm", t)
	}
}

func checkDelContractManagerPermission(from, contract common.Address, t *testing.T, has bool, ptable *PerminTable) {
	if ptable.CheckActionPerm(from, common.Address{}, contract, ModifyPerminType_DelContractManagerPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_DelCrtContractManagerPerm", t)
	}
}

func checkAccessContractPermission(from, contract common.Address, t *testing.T, has bool, ptable *PerminTable) {
	//if has {
	//	checkSendTxPermission(from,t,true)
	//}
	if ptable.CheckActionPerm(from, common.Address{}, contract, PerminType_AccessContract) != has {
		printStack("CheckActionPerm err ModifyPerminType_DelCrtContractManagerPerm", t)
	}
}

func printStack(err string, t *testing.T) {
	debug.PrintStack()
	t.FailNow()
}

func printResError(res bool, err error, t *testing.T, str string) {
	if !res {
		fmt.Println(err)
		printStack(str, t)
	}
}

func checkBothTxGroupPermission(from, gropAddr common.Address, t *testing.T, has bool, ptable *PerminTable) {
	checkBaseManagerSendTxPermission(from, t, true, ptable)
	checkBaseGroupManagerPermission(from, gropAddr, t, true, ptable)
}

func checkNoBothTxGroupPermission(from common.Address, t *testing.T, has bool, ptable *PerminTable) {
	checkBaseSendTxPermission(from, t, false, ptable)
	checkBaseGroupPermission(from, common.Address{}, t, false, ptable)

}

func checkNoBaseSendTxPermission(from common.Address, t *testing.T, has bool, ptable *PerminTable) {
	checkSendTxPermission(ptable, from, t, false)
	checkAddSendTxPermission(ptable, from, t, false)
	checkDelSendTxPermission(ptable, from, t, false)
	checkSendTxManagerPermission(ptable, from, t, false)
	checkDelSendTxManagerPermission(ptable, from, t, false)
}

func checkBaseSendTxPermission(from common.Address, t *testing.T, has bool, ptable *PerminTable) {
	checkSendTxPermission(ptable, from, t, has)
	checkAddSendTxPermission(ptable, from, t, false)
	checkDelSendTxPermission(ptable, from, t, false)
	checkSendTxManagerPermission(ptable, from, t, false)
	checkDelSendTxManagerPermission(ptable, from, t, false)
}

func checkBaseManagerSendTxPermission(from common.Address, t *testing.T, has bool, ptable *PerminTable, ) {
	checkSendTxPermission(ptable, from, t, true)
	checkAddSendTxPermission(ptable, from, t, true)
	checkDelSendTxPermission(ptable, from, t, true)
	checkSendTxManagerPermission(ptable, from, t, true)
	checkDelSendTxManagerPermission(ptable, from, t, true)
}

func checkSendTxPermission(ptable *PerminTable, from common.Address, t *testing.T, has bool) {
	if ptable.CheckActionPerm(from, common.Address{}, common.Address{}, PerminType_SendTx) != has {
		printStack("CheckActionPerm err PerminType_SendTx", t)
	}
}

func checkAddSendTxPermission(ptable *PerminTable, from common.Address, t *testing.T, has bool) {
	if ptable.CheckActionPerm(from, common.Address{}, common.Address{}, ModifyPerminType_AddSendTxPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_AddSendTxManagerPerm", t)
	}
}

func checkDelSendTxPermission(ptable *PerminTable, from common.Address, t *testing.T, has bool) {
	if ptable.CheckActionPerm(from, common.Address{}, common.Address{}, ModifyPerminType_DelSendTxPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_AddSendTxManagerPerm", t)
	}
}

func checkSendTxManagerPermission(ptable *PerminTable, from common.Address, t *testing.T, has bool) {
	if ptable.CheckActionPerm(from, common.Address{}, common.Address{}, ModifyPerminType_AddSendTxManagerPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_AddSendTxManagerPerm", t)
	}
}

func checkDelSendTxManagerPermission(ptable *PerminTable, from common.Address, t *testing.T, has bool) {
	if ptable.CheckActionPerm(from, common.Address{}, common.Address{}, ModifyPerminType_DelSendTxManagerPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_DelSendTxManagerPerm", t)
	}
}

func checkNoBaseGroupPermission(from, gropAddr common.Address, t *testing.T, has bool, ptable *PerminTable, ) {
	checkGroupSendTxPermission(ptable, from, gropAddr, t, false)
	checkAddGroupMemberPermission(ptable, from, gropAddr, t, false)
	checkDelGroupMemberPermission(ptable, from, gropAddr, t, false)
	checkAddGroupManagerPermission(ptable, from, gropAddr, t, false)
	checkDelGroupManagerPermission(ptable, from, gropAddr, t, false)
	checkDelGropPermission(ptable, from, gropAddr, t, false)
}

func checkBaseGroupPermission(from, gropAddr common.Address, t *testing.T, has bool, ptable *PerminTable, ) {
	checkGroupSendTxPermission(ptable, from, gropAddr, t, has)
	checkAddGroupMemberPermission(ptable, from, gropAddr, t, false)
	checkDelGroupMemberPermission(ptable, from, gropAddr, t, false)
	checkAddGroupManagerPermission(ptable, from, gropAddr, t, false)
	checkDelGroupManagerPermission(ptable, from, gropAddr, t, false)
	checkDelGropPermission(ptable, from, gropAddr, t, false)
}

func checkBaseGroupManagerPermission(from, gropAddr common.Address, t *testing.T, has bool, ptable *PerminTable, ) {
	checkGroupSendTxPermission(ptable, from, gropAddr, t, has)
	checkAddGroupMemberPermission(ptable, from, gropAddr, t, has)
	checkDelGroupMemberPermission(ptable, from, gropAddr, t, has)
	checkAddGroupManagerPermission(ptable, from, gropAddr, t, has)
	checkDelGroupManagerPermission(ptable, from, gropAddr, t, has)
	checkDelGropPermission(ptable, from, gropAddr, t, has)
}

func checkGroupSendTxPermission(ptable *PerminTable, from, group common.Address, t *testing.T, has bool) {
	group = common.Address{}
	if ptable.CheckActionPerm(from, group, common.Address{}, PerminType_SendTx) != has {
		printStack("CheckActionPerm err PerminType_SendTx", t)
	}
}

func checkAddGroupMemberPermission(ptable *PerminTable, member, gropAddr common.Address, t *testing.T, has bool) {
	if ptable.CheckActionPerm(member, gropAddr, common.Address{}, ModifyPerminType_AddGropMemberPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_AddGropManagerPerm", t)
	}
}

func checkDelGroupMemberPermission(ptable *PerminTable, member, gropAddr common.Address, t *testing.T, has bool) {
	if ptable.CheckActionPerm(member, gropAddr, common.Address{}, ModifyPerminType_DelGropMemberPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_AddGropManagerPerm", t)
	}
}

func checkAddGroupManagerPermission(ptable *PerminTable, member, gropAddr common.Address, t *testing.T, has bool) {
	if ptable.CheckActionPerm(member, gropAddr, common.Address{}, ModifyPerminType_AddGropManagerPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_AddGropManagerPerm", t)
	}
}

func checkDelGroupManagerPermission(ptable *PerminTable, member, gropAddr common.Address, t *testing.T, has bool) {
	if ptable.CheckActionPerm(member, gropAddr, common.Address{}, ModifyPerminType_DelGropManagerPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_AddGropManagerPerm", t)
	}
}

func checkDelGropPermission(ptable *PerminTable, member, gropAddr common.Address, t *testing.T, has bool) {
	if ptable.CheckActionPerm(member, gropAddr, common.Address{}, ModifyPerminType_DelGrop) != has {
		printStack("CheckActionPerm err ModifyPerminType_DelGrop", t)
	}
}
