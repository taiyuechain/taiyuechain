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
	res, err :=ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddCrtContractPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddCrtContractPerm")

	checkAddContractPermission(member1,t,false)
	checkCreateContractTxPermission(member1,t,true)

	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_DelCrtContractPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelCrtContractPerm")
	checkCreateContractTxPermission(member1,t,false)

	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddCrtContractManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddCrtContractManagerPerm")
	checkAddCrtContractManagerPermission(member1,t,true)
	checkDelCrtContractManagerPermission(member1,t,true)
	checkAddContractPermission(member1,t,true)
	checkCreateContractTxPermission(member1,t,true)

	res, err =ptable.GrantPermission(root1,member1,member2,common.Address{},ModifyPerminType_AddCrtContractPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddCrtContractPerm")
	checkAddContractPermission(member2,t,false)
	checkCreateContractTxPermission(member2,t,true)

	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_DelCrtContractManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelCrtContractManagerPerm")
	checkDelCrtContractManagerPermission(member1,t,false)
	checkCreateContractTxPermission(member1,t,true)
	checkCreateContractTxPermission(member2,t,true)

	res, err =ptable.GrantPermission(root1,root1,member2,common.Address{},ModifyPerminType_DelCrtContractPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelCrtContractPerm")
	checkCreateContractTxPermission(member2,t,false)
}

func TestCreateContractPermissionTable(t *testing.T) {
	res, err :=ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddCrtContractPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddCrtContractPerm")

	checkAddContractPermission(member1,t,false)
	checkSendTxPermission(member1,t,false)
	checkCreateContractTxPermission(member1,t,true)

	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddSendTxPerm,"a",true)
	printResError(res,err,t,"Grent err")
	checkSendTxPermission(member1,t,true)
	checkCreateContractTxPermission(member1,t,true)

	//ModifyPerminType_CrtContractPerm
	contractAddr := crypto.CreateAddress(member1,2)
	ptable.CreateContractPem(contractAddr ,member1, uint64(2),false)
	res, err =ptable.GrantPermission(member1,member1,member1,contractAddr,ModifyPerminType_CrtContractPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_CrtContractPerm")
	checkAddContractMemberPermission(member1,contractAddr,t,true)
	checkDelContractMemberPermission(member1,contractAddr,t,true)

	res, err =ptable.GrantPermission(root1,member1,member2,contractAddr,ModifyPerminType_AddContractMemberPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddContractMemberPerm")
	// new 2
	checkAccessContractPermission(member2,contractAddr,t,false)

	res, err =ptable.GrantPermission(root1,root1,member2,common.Address{},ModifyPerminType_AddSendTxPerm,"a",true)
	printResError(res,err,t,"Grent err")
	checkSendTxPermission(member2,t,true)
	checkAccessContractPermission(member2,contractAddr,t,true)


	//ModifyPerminType_DelContractMemberPerm
	res, err =ptable.GrantPermission(member1,member1,member2,contractAddr,ModifyPerminType_DelContractMemberPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelContractMemberPerm")
	checkAccessContractPermission(member2,contractAddr,t,false)
}

// contract group ? delete contract group
func TestContractPermissionTable(t *testing.T) {
	res, err :=ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddSendTxPerm,"a",true)
	printResError(res,err,t,"Grent err")
	checkSendTxPermission(member1,t,true)
	res, err =ptable.GrantPermission(root1,root1,member2,common.Address{},ModifyPerminType_AddSendTxPerm,"a",true)
	printResError(res,err,t,"Grent err")
	checkSendTxPermission(member2,t,true)

	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddCrtContractPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddCrtContractPerm")

	checkAddContractPermission(member1,t,false)
	checkCreateContractTxPermission(member1,t,true)

	//checkSendTxPermission(member1,t,true)
	//ModifyPerminType_CrtContractPerm
	contractAddr := crypto.CreateAddress(member1,2)
	ptable.CreateContractPem(contractAddr ,member1, uint64(2),false)
	res, err =ptable.GrantPermission(member1,member1,member1,contractAddr,ModifyPerminType_CrtContractPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_CrtContractPerm")
	checkAddContractMemberPermission(member1,contractAddr,t,true)
	checkDelContractMemberPermission(member1,contractAddr,t,true)

	res, err =ptable.GrantPermission(root1,member1,member2,contractAddr,ModifyPerminType_AddContractMemberPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddContractMemberPerm")
	// new 2
	checkAccessContractPermission(member2,contractAddr,t,true)

	//ModifyPerminType_DelContractMemberPerm
	res, err =ptable.GrantPermission(member1,member1,member2,contractAddr,ModifyPerminType_DelContractMemberPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelContractMemberPerm")
	checkAccessContractPermission(member2,contractAddr,t,false)

	//ModifyPerminType_AddContractMemberPerm
	res, err =ptable.GrantPermission(member1,member1,member2,contractAddr,ModifyPerminType_AddContractMemberPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddContractMemberPerm")
	checkAccessContractPermission(member2,contractAddr,t,true)

	//ModifyPerminType_AddContractManagerPerm
	res, err =ptable.GrantPermission(member1,member1,member2,contractAddr,ModifyPerminType_AddContractManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddContractManagerPerm")
	checkAddContractMemberPermission(member2,contractAddr,t,true)
	checkDelContractMemberPermission(member2,contractAddr,t,true)
	checkAddContractManagerPermission(member2,contractAddr,t,true)

	res, err =ptable.GrantPermission(member1,member2,member3,contractAddr,ModifyPerminType_AddContractMemberPerm,"a",true)
	checkAccessContractPermission(member3,contractAddr,t,false)

	res, err =ptable.GrantPermission(root1,root1,member3,common.Address{},ModifyPerminType_AddSendTxPerm,"a",true)
	printResError(res,err,t,"Grent err")
	checkAccessContractPermission(member3,contractAddr,t,true)

	//ModifyPerminType_DelContractManagerPerm
	res, err =ptable.GrantPermission(member1,member1,member2,contractAddr,ModifyPerminType_DelContractManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelContractManagerPerm")
	checkDelContractMemberPermission(member2,contractAddr,t,false)
	checkAddContractMemberPermission(member2,contractAddr,t,false)
	checkAccessContractPermission(member3,contractAddr,t,true)
}

func TestContractSimplePermissionTable(t *testing.T) {
	res, err :=ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddSendTxPerm,"a",true)
	printResError(res,err,t,"Grent err")
	checkSendTxPermission(member1,t,true)
	res, err =ptable.GrantPermission(root1,root1,member2,common.Address{},ModifyPerminType_AddSendTxPerm,"a",true)
	printResError(res,err,t,"Grent err")
	checkSendTxPermission(member2,t,true)

	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddCrtContractPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddCrtContractPerm")

	checkAddContractPermission(member1,t,false)
	checkCreateContractTxPermission(member1,t,true)

	//ModifyPerminType_CrtContractPerm
	//contractAddr := common.HexToAddress("0x0e09094f7BF1f268c45730aCB3ed48504A1FbbbB")
	contractAddr := crypto.CreateAddress(member1,2)
	ptable.CreateContractPem(contractAddr ,member1, uint64(2),false)
	res, err =ptable.GrantPermission(member1,root1,member1,contractAddr,ModifyPerminType_CrtContractPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_CrtContractPerm")

	checkAddContractMemberPermission(member1,contractAddr,t,true)
	checkAddContractManagerPermission(member1,contractAddr,t,true)
	checkCreateContractTxPermission(member1,t,true)

	//ModifyPerminType_AddContractMemberPerm
	res, err =ptable.GrantPermission(root1,member1,member2,contractAddr,ModifyPerminType_AddContractMemberPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddContractMemberPerm")
	checkAccessContractPermission(member2,contractAddr,t,true)

	//ModifyPerminType_DelContractMemberPerm
	res, err =ptable.GrantPermission(root1,member1,member2,contractAddr,ModifyPerminType_DelContractMemberPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelContractMemberPerm")
	checkAccessContractPermission(member2,contractAddr,t,false)

	//ModifyPerminType_AddContractManagerPerm
	res, err =ptable.GrantPermission(root1,member1,member2,contractAddr,ModifyPerminType_AddContractManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddContractManagerPerm")

	checkAddContractMemberPermission(member2,contractAddr,t,true)
	checkDelContractMemberPermission(member2,contractAddr,t,true)
	checkAddContractManagerPermission(member2,contractAddr,t,true)
	checkDelContractManagerPermission(member2,contractAddr,t,true)

	//ModifyPerminType_DelContractManagerPerm
	res, err =ptable.GrantPermission(root1,member1,member2,contractAddr,ModifyPerminType_DelContractManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelContractManagerPerm")
	checkAddContractMemberPermission(member2,contractAddr,t,false)
	checkDelContractMemberPermission(member2,contractAddr,t,false)
	checkAddContractManagerPermission(member2,contractAddr,t,false)
	checkDelContractManagerPermission(member2,contractAddr,t,false)
	checkAccessContractPermission(member2,contractAddr,t,false)

	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_DelCrtContractPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelCrtContractPerm")
	checkCreateContractTxPermission(member1,t,false)


	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddCrtContractManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddCrtContractManagerPerm")
	checkCreateContractTxPermission(member1,t,true)
	checkAddContractPermission(member1,t,true)
	checkDelContractPermission(member1,t,true)
	checkAddCrtContractManagerPermission(member1,t,true)
	checkDelCrtContractManagerPermission(member1,t,true)

	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_DelCrtContractManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelCrtContractManagerPerm")

	checkAddContractPermission(member1,t,false)
	checkDelContractPermission(member1,t,false)
	checkAddCrtContractManagerPermission(member1,t,false)
	checkDelCrtContractManagerPermission(member1,t,false)
	checkCreateContractTxPermission(member1,t,true)
}

func TestContractNormalPermissionTable(t *testing.T) {
	res, err :=ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddCrtContractPerm,"a",true)
	if !res{
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_AddSendTxManagerPerm")
	}
	if ptable.CheckActionPerm(member1,common.Address{},common.Address{},ModifyPerminType_AddCrtContractPerm){

		t.Fatalf("CheckActionPerm err ModifyPerminType_AddCrtContractPerm")
	}
	if !ptable.CheckActionPerm(member1,common.Address{},common.Address{},PerminType_CreateContract){

		t.Fatalf("CheckActionPerm err PerminType_SendTx")
	}


	//ModifyPerminType_CrtContractPerm
	//contractAddr := common.HexToAddress("0x0e09094f7BF1f268c45730aCB3ed48504A1FbbbB")
	contractAddr := crypto.CreateAddress(member1,2)
	ptable.CreateContractPem(contractAddr ,member1, uint64(2),false)
	res, err =ptable.GrantPermission(member1,root1,member1,contractAddr,ModifyPerminType_CrtContractPerm,"a",true)
	if !res{
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_CrtContractPerm")
	}
	//ModifyPerminType_AddContractMemberPerm
	if !ptable.CheckActionPerm(member1,common.Address{},contractAddr,ModifyPerminType_AddContractMemberPerm){

		t.Fatalf("CheckActionPerm err ModifyPerminType_AddContractMemberPerm")
	}
	res, err =ptable.GrantPermission(member1,member1,member2,contractAddr,ModifyPerminType_AddContractMemberPerm,"a",true)
	if !res{
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_CrtContractPerm")
	}
	//ModifyPerminType_DelContractMemberPerm
	res, err =ptable.GrantPermission(member1,member1,member2,contractAddr,ModifyPerminType_DelContractMemberPerm,"a",true)
	if !res{
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_DelContractMemberPerm")
	}
	//ModifyPerminType_AddContractManagerPerm
	res, err =ptable.GrantPermission(member1,member1,member2,contractAddr,ModifyPerminType_AddContractManagerPerm,"a",true)
	if !res{
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_CrtContractPerm")
	}
	if !ptable.CheckActionPerm(member2,common.Address{},contractAddr,ModifyPerminType_AddContractMemberPerm){

		t.Fatalf("CheckActionPerm err ModifyPerminType_AddContractMemberPerm")
	}
	if !ptable.CheckActionPerm(member2,common.Address{},contractAddr,ModifyPerminType_DelContractMemberPerm){

		t.Fatalf("CheckActionPerm err ModifyPerminType_AddContractMemberPerm")
	}
	//ModifyPerminType_DelContractManagerPerm
	res, err =ptable.GrantPermission(member2,member1,member2,contractAddr,ModifyPerminType_DelContractManagerPerm,"a",true)
	if !res{
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_CrtContractPerm")
	}
	if ptable.CheckActionPerm(member2,common.Address{},contractAddr,ModifyPerminType_DelContractMemberPerm){

		t.Fatalf("CheckActionPerm err ModifyPerminType_AddContractMemberPerm")
	}
	if ptable.CheckActionPerm(member2,common.Address{},contractAddr,ModifyPerminType_AddContractMemberPerm){

		t.Fatalf("CheckActionPerm err ModifyPerminType_AddContractMemberPerm")
	}


	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_DelCrtContractPerm,"a",true)
	if !res{
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_AddSendTxManagerPerm")
	}
	if ptable.CheckActionPerm(member1,common.Address{},common.Address{},PerminType_CreateContract){

		t.Fatalf("CheckActionPerm err PerminType_SendTx")
	}


	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddCrtContractManagerPerm,"a",true)
	if !res{
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_AddCrtContractManagerPerm")
	}
	if !ptable.CheckActionPerm(member1,common.Address{},common.Address{},ModifyPerminType_AddCrtContractManagerPerm){

		t.Fatalf("CheckActionPerm err ModifyPerminType_AddCrtContractPerm")
	}
	if !ptable.CheckActionPerm(member1,common.Address{},common.Address{},PerminType_CreateContract){

		t.Fatalf("CheckActionPerm err PerminType_SendTx")
	}

	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_DelCrtContractManagerPerm,"a",true)
	if !res{
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_AddCrtContractManagerPerm")
	}
	if ptable.CheckActionPerm(member1,common.Address{},common.Address{},ModifyPerminType_DelCrtContractManagerPerm){

		t.Fatalf("CheckActionPerm err ModifyPerminType_AddCrtContractPerm")
	}
	if !ptable.CheckActionPerm(member1,common.Address{},common.Address{},PerminType_CreateContract){

		t.Fatalf("CheckActionPerm err PerminType_SendTx")
	}
}

func checkAddContractPermission(from common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(from,common.Address{},common.Address{},ModifyPerminType_AddCrtContractPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_AddCrtContractPerm",t)
	}
}

func checkDelContractPermission(from common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(from,common.Address{},common.Address{},ModifyPerminType_DelCrtContractPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_DelCrtContractPerm",t)
	}
}

func checkCreateContractTxPermission(from common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(from,common.Address{},common.Address{},PerminType_CreateContract) != has {
		printStack("CheckActionPerm err PerminType_CreateContract",t)
	}
}

func checkAddCrtContractManagerPermission(from common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(from,common.Address{},common.Address{},ModifyPerminType_AddCrtContractManagerPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_AddCrtContractManagerPerm",t)
	}
}

func checkDelCrtContractManagerPermission(from common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(from,common.Address{},common.Address{},ModifyPerminType_DelCrtContractManagerPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_DelCrtContractManagerPerm",t)
	}
}

func checkAddContractMemberPermission(from, contractAddr common.Address, t *testing.T, has bool) {
	if ptable.CheckActionPerm(from, common.Address{}, contractAddr, ModifyPerminType_AddContractMemberPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_AddContractMemberPerm",t)
	}
}

func checkDelContractMemberPermission(from, contractAddr common.Address, t *testing.T, has bool) {
	if ptable.CheckActionPerm(from, common.Address{}, contractAddr, ModifyPerminType_DelContractMemberPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_DelContractMemberPerm",t)
	}
}

func checkAddContractManagerPermission(from,contract common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(from,common.Address{},contract,ModifyPerminType_AddContractManagerPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_AddCrtContractManagerPerm",t)
	}
}

func checkDelContractManagerPermission(from,contract common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(from,common.Address{},contract,ModifyPerminType_DelContractManagerPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_DelCrtContractManagerPerm",t)
	}
}

func checkAccessContractPermission(from,contract common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(from,common.Address{},contract,PerminType_AccessContract) != has {
		printStack("CheckActionPerm err ModifyPerminType_DelCrtContractManagerPerm",t)
	}
}

func printStack(err string,t *testing.T) {
	debug.PrintStack()
	t.FailNow()
}

func printResError(res bool,err error,t *testing.T,str string) {
	if !res{
		fmt.Println(err)
		printStack(str,t)
	}
}

func checkBothTxGroupPermission(from,gropAddr common.Address,t *testing.T,has bool) {
	checkBaseManagerSendTxPermission(from,t,true)
	checkBaseGroupManagerPermission(from,gropAddr,t,true)
}

func checkNoBothTxGroupPermission(from common.Address,t *testing.T,has bool) {
	checkNoBaseSendTxPermission(from,t,false)
	checkNoBaseGroupPermission(from,common.Address{},t,false)

}

func checkNoBaseSendTxPermission(from common.Address,t *testing.T,has bool) {
	checkSendTxPermission(from,t,false)
	checkAddSendTxPermission(from,t,false)
	checkDelSendTxPermission(from,t,false)
	checkSendTxManagerPermission(from,t,false)
	checkDelSendTxManagerPermission(from,t,false)
}

func checkBaseSendTxPermission(from common.Address,t *testing.T,has bool) {
	checkSendTxPermission(from,t,true)
	checkAddSendTxPermission(from,t,false)
	checkDelSendTxPermission(from,t,false)
	checkSendTxManagerPermission(from,t,false)
	checkDelSendTxManagerPermission(from,t,false)
}

func checkBaseManagerSendTxPermission(from common.Address,t *testing.T,has bool) {
	checkSendTxPermission(from,t,true)
	checkAddSendTxPermission(from,t,true)
	checkDelSendTxPermission(from,t,true)
	checkSendTxManagerPermission(from,t,true)
	checkDelSendTxManagerPermission(from,t,true)
}

func checkSendTxPermission(from common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(from,common.Address{},common.Address{},PerminType_SendTx) != has {
		printStack("CheckActionPerm err PerminType_SendTx",t)
	}
}

func checkAddSendTxPermission(from common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(from,common.Address{},common.Address{},ModifyPerminType_AddSendTxPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_AddSendTxManagerPerm",t)
	}
}

func checkDelSendTxPermission(from common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(from,common.Address{},common.Address{},ModifyPerminType_DelSendTxPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_AddSendTxManagerPerm",t)
	}
}

func checkSendTxManagerPermission(from common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(from,common.Address{},common.Address{},ModifyPerminType_AddSendTxManagerPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_AddSendTxManagerPerm",t)
	}
}

func checkDelSendTxManagerPermission(from common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(from,common.Address{},common.Address{},ModifyPerminType_DelSendTxManagerPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_DelSendTxManagerPerm",t)
	}
}

func checkNoBaseGroupPermission(from, gropAddr common.Address,t *testing.T,has bool) {
	checkGroupSendTxPermission(from,gropAddr,t,false)
	checkAddGroupMemberPermission(from,gropAddr,t,false)
	checkDelGroupMemberPermission(from,gropAddr,t,false)
	checkAddGroupManagerPermission(from,gropAddr,t,false)
	checkDelGroupManagerPermission(from,gropAddr,t,false)
	checkDelGropPermission(from,gropAddr,t,false)
}

func checkBaseGroupPermission(from, gropAddr common.Address,t *testing.T,has bool) {
	checkGroupSendTxPermission(from,gropAddr,t,true)
	checkAddGroupMemberPermission(from,gropAddr,t,false)
	checkDelGroupMemberPermission(from,gropAddr,t,false)
	checkAddGroupManagerPermission(from,gropAddr,t,false)
	checkDelGroupManagerPermission(from,gropAddr,t,false)
	checkDelGropPermission(from,gropAddr,t,false)
}

func checkBaseGroupManagerPermission(from, gropAddr common.Address,t *testing.T,has bool) {
	checkGroupSendTxPermission(from,gropAddr,t,true)
	checkAddGroupMemberPermission(from,gropAddr,t,true)
	checkDelGroupMemberPermission(from,gropAddr,t,true)
	checkAddGroupManagerPermission(from,gropAddr,t,true)
	checkDelGroupManagerPermission(from,gropAddr,t,true)
	checkDelGropPermission(from,gropAddr,t,true)
}

func checkGroupSendTxPermission(from,group common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(from,group,common.Address{},PerminType_SendTx) != has {
		printStack("CheckActionPerm err PerminType_SendTx",t)
	}
}

func checkAddGroupMemberPermission(member,gropAddr common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(member,gropAddr,common.Address{},ModifyPerminType_AddGropMemberPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_AddGropManagerPerm",t)
	}
}

func checkDelGroupMemberPermission(member,gropAddr common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(member,gropAddr,common.Address{},ModifyPerminType_DelGropMemberPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_AddGropManagerPerm",t)
	}
}

func checkAddGroupManagerPermission(member,gropAddr common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(member,gropAddr,common.Address{},ModifyPerminType_AddGropManagerPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_AddGropManagerPerm",t)
	}
}

func checkDelGroupManagerPermission(member,gropAddr common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(member,gropAddr,common.Address{},ModifyPerminType_DelGropManagerPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_AddGropManagerPerm",t)
	}
}

func checkDelGropPermission(member,gropAddr common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(member,gropAddr,common.Address{},ModifyPerminType_DelGrop) != has {
		printStack("CheckActionPerm err ModifyPerminType_DelGrop",t)
	}
}