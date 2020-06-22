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

func init() {
	/*SetConfig(true, true)

	rootList = append(rootList, common.HexToAddress("0x21C16f03bbF085D6908569d159Ad40BcafdB80C5"))
	rootList = append(rootList, common.HexToAddress("0xa9A2CbA5d5d16DE370375B42662F3272279B2b89"))
	rootList = append(rootList, common.HexToAddress("0x6bE9780954580FCC268944e9D6271B3Dfc886997"))
	rootList = append(rootList, common.HexToAddress("0x03096816367827E9C5c1993AE18b237895717500"))

	ptable = NewPerminTable()
	ptable.InitPBFTRootGrop(rootList)

	root1 = rootList[1]
	member1 = common.HexToAddress("0xf22142DbF24C324Eb021332c2D673d3B819B955a")
	member2 = common.HexToAddress("0x1b3d007C0D5318D241F26374F379E882cDCbc371")
	member3 = common.HexToAddress("0xFE9cFAc0EDf17FB746069f1d12885217fF30234C")*/
}

func TestContractManagerPermissionTable(t *testing.T) {
	res, err :=ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddCrtContractPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddCrtContractPerm")

	checkAddContractTxPermission(member1,t,false)
	checkCreateContractTxPermission(member1,t,true)

	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_DelCrtContractPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelCrtContractPerm")
	checkCreateContractTxPermission(member1,t,false)

	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddCrtContractManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddCrtContractManagerPerm")
	checkAddContractManagerPermission(member1,t,true)
	checkCreateContractTxPermission(member1,t,true)

	res, err =ptable.GrantPermission(root1,member1,member2,common.Address{},ModifyPerminType_AddCrtContractPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddCrtContractPerm")
	checkAddContractTxPermission(member2,t,false)
	checkCreateContractTxPermission(member2,t,true)

	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_DelCrtContractManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelCrtContractManagerPerm")
	checkDelContractManagerPermission(member1,t,false)
	checkCreateContractTxPermission(member1,t,true)
	checkCreateContractTxPermission(member2,t,true)

	res, err =ptable.GrantPermission(root1,root1,member2,common.Address{},ModifyPerminType_DelCrtContractPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelCrtContractPerm")
	checkCreateContractTxPermission(member2,t,false)
}

// contract group ? delete contract group
func TestContractPermissionTable(t *testing.T) {
	res, err :=ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddCrtContractPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddCrtContractPerm")

	checkAddContractTxPermission(member1,t,false)
	checkCreateContractTxPermission(member1,t,true)

	//ModifyPerminType_CrtContractPerm
	contractAddr := crypto.CreateAddress(member1,2)
	ptable.CreateContractPem(contractAddr ,member1, uint64(2),false)
	res, err =ptable.GrantPermission(member1,root1,member1,contractAddr,ModifyPerminType_CrtContractPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_CrtContractPerm")
	checkAddContractMemberPermission(member1,contractAddr,t,true)
	checkDelContractMemberPermission(member1,contractAddr,t,true)

	res, err =ptable.GrantPermission(root1,member1,member2,contractAddr,ModifyPerminType_AddContractMemberPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddContractMemberPerm")
	// new 2
	checkAddContractTxPermission(member2,t,false)
	checkCreateContractTxPermission(member2,t,false)

	/*res, err =ptable.GrantPermission(root1,member1,contractAddr,contractAddr,ModifyPerminType_AddCrtContractPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddContractMemberPerm")
	checkAddContractTxPermission(member2,t,false)
	checkCreateContractTxPermission(member2,t,true)*/

	//ModifyPerminType_DelContractMemberPerm
	res, err =ptable.GrantPermission(member1,member1,member2,contractAddr,ModifyPerminType_DelContractMemberPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelContractMemberPerm")
	checkCreateContractTxPermission(member2,t,false)

	//ModifyPerminType_AddContractManagerPerm
	res, err =ptable.GrantPermission(member1,member1,member2,contractAddr,ModifyPerminType_AddContractManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddContractManagerPerm")
	checkAddContractMemberPermission(member2,contractAddr,t,true)
	checkCreateContractTxPermission(member2,t,true)
	checkDelContractMemberPermission(member2,contractAddr,t,true)

	res, err =ptable.GrantPermission(member2,member2,member3,contractAddr,ModifyPerminType_AddContractMemberPerm,"a",true)
	checkAddContractTxPermission(member2,t,false)
	checkCreateContractTxPermission(member3,t,true)

	//ModifyPerminType_DelContractManagerPerm
	res, err =ptable.GrantPermission(member1,member1,member2,contractAddr,ModifyPerminType_DelContractManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelContractManagerPerm")
	checkDelContractMemberPermission(member2,contractAddr,t,false)
	checkAddContractMemberPermission(member2,contractAddr,t,false)
	checkCreateContractTxPermission(member3,t,true)

	//todo
	//delete contract group ??? PerminType_AccessContract
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
	if ptable.CheckActionPerm(member1,common.Address{},common.Address{},PerminType_CreateContract){

		t.Fatalf("CheckActionPerm err PerminType_SendTx")
	}
}

func checkAddContractTxPermission(from common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(from,common.Address{},common.Address{},ModifyPerminType_AddCrtContractPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_AddCrtContractPerm",t)
	}
}

func checkCreateContractTxPermission(from common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(from,common.Address{},common.Address{},PerminType_CreateContract) != has {
		printStack("CheckActionPerm err PerminType_CreateContract",t)
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

func checkAddContractManagerPermission(from common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(from,common.Address{},common.Address{},ModifyPerminType_AddCrtContractManagerPerm) != has {
		printStack("CheckActionPerm err ModifyPerminType_AddCrtContractManagerPerm",t)
	}
}

func checkDelContractManagerPermission(from common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(from,common.Address{},common.Address{},ModifyPerminType_DelCrtContractManagerPerm) != has {
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

func checkSendTxPermission(from common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(from,common.Address{},common.Address{},PerminType_SendTx) != has {
		printStack("CheckActionPerm err PerminType_SendTx",t)
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

func checkGroupSendTxPermission(from,group common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(from,group,common.Address{},PerminType_SendTx) != has {
		printStack("CheckActionPerm err PerminType_SendTx",t)
	}
}

func checkDelGropPermission(member,gropAddr common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(member,gropAddr,common.Address{},ModifyPerminType_DelGrop) != has {
		printStack("CheckActionPerm err ModifyPerminType_DelGrop",t)
	}
}