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
	"math/big"
	"runtime/debug"
	"testing"
)

var (
	pbft1PrivString = "7631a11e9d28563cdbcf96d581e4b9a19e53ad433a53c25a9f18c74ddf492f75"
	pbft2PrivString = "bab8dbdcb4d974eba380ff8b2e459efdb6f8240e5362e40378de3f9f5f1e67bb"
	pbft3PrivString = "122d186b77a030e04f5654e13d934b21af2aac03b942c3ecda4632364d81cbab"
	pbft4PrivString = "fe44cbc0e164092a6746bd57957422ab165c009d0299c7639a2f4d290317f20f"
	rootList        []common.Address
	root1           common.Address
	member1         common.Address
	member2         common.Address
	ptable          *PerminTable
)

func init() {
	SetConfig(true, true)

	rootList = append(rootList, common.HexToAddress("0x21C16f03bbF085D6908569d159Ad40BcafdB80C5"))
	rootList = append(rootList, common.HexToAddress("0xa9A2CbA5d5d16DE370375B42662F3272279B2b89"))
	rootList = append(rootList, common.HexToAddress("0x6bE9780954580FCC268944e9D6271B3Dfc886997"))
	rootList = append(rootList, common.HexToAddress("0x03096816367827E9C5c1993AE18b237895717500"))

	ptable = NewPerminTable()
	ptable.InitPBFTRootGrop(rootList)

	root1 = rootList[1]
	member1 = common.HexToAddress("0xf22142DbF24C324Eb021332c2D673d3B819B955a")
	member2 = common.HexToAddress("0xFE9cFAc0EDf17FB746069f1d12885217fF30234C")
}

func printResError(res bool,err error,t *testing.T,str string) {
	if !res{
		fmt.Println(err)
		t.Fatalf(str)
	}
}

func checkSendTxPermission(from common.Address,t *testing.T,has bool) {
	if ptable.CheckActionPerm(from,common.Address{},common.Address{},PerminType_SendTx) != has {
		debug.PrintStack()
		t.Fatalf("CheckActionPerm err PerminType_SendTx")
	}
}

func checkDelGropPermission(member,gropAddr common.Address,t *testing.T,has bool) {
		if ptable.CheckActionPerm(member,gropAddr,common.Address{},ModifyPerminType_DelGrop) != has {
		debug.PrintStack()
		t.Fatalf("CheckActionPerm err ModifyPerminType_DelGrop")
	}
}

func TestPerminTable_DeletePermission(t *testing.T) {
	// check no permission account
	checkSendTxPermission(common.BytesToAddress([]byte("1234")),t,false)

	res, err :=ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddSendTxPerm,"a",true)
	printResError(res,err,t,"Grent err")

	checkSendTxPermission(member1,t,true)

	res, err =ptable.GrantPermission(common.Address{},member1,common.Address{},common.Address{},ModifyPerminType_CrtGrop,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_CrtGrop")

	gropAddr := crypto.CreateGroupkey(member1,3)
	res, err =ptable.GrantPermission(member1,root1,member2,gropAddr,ModifyPerminType_AddGropMemberPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddGropMemberPerm")

	checkSendTxPermission(member2,t,false)

	res, err =ptable.GrantPermission(root1,root1,gropAddr,common.Address{},ModifyPerminType_AddSendTxPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddSendTxPerm")

	checkSendTxPermission(member2,t,true)

	//ModifyPerminType_AddGropManagerPerm
	res, err =ptable.GrantPermission(common.Address{},member1,member2,gropAddr,ModifyPerminType_AddGropManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddGropManagerPerm")

	checkDelGropPermission(member2,gropAddr,t,true)

	//ModifyPerminType_DelGropManagerPerm
	res, err =ptable.GrantPermission(member1,root1,member2,gropAddr,ModifyPerminType_DelGropManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelGropManagerPerm")

	checkDelGropPermission(member2,gropAddr,t,true)

	res, err = ptable.GrantPermission(member1, root1, member2, gropAddr, ModifyPerminType_DelGrop, "a", true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelGrop")

	checkSendTxPermission(member2,t,false)
}

func TestPerminTable_GrantPermission(t *testing.T) {
	res, err :=ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddSendTxPerm,"a",true)
	if !res{
		fmt.Println(err)
		t.Fatalf("Grent err")
	}
	res, err =ptable.GrantPermission(root1,root1,member2,common.Address{},ModifyPerminType_AddSendTxPerm,"a",true)
	if !res{
		fmt.Println(err)
		t.Fatalf("Grent err")
	}
	if !ptable.CheckActionPerm(member1,common.Address{},common.Address{},PerminType_SendTx){
		t.Fatalf("CheckActionPerm err PerminType_SendTx")
	}

	res, err =ptable.GrantPermission(common.Address{},member1,member1,common.Address{},ModifyPerminType_CrtGrop,"a",true)
	if !res {
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_CrtGrop")
	}

	gropAddr := crypto.CreateGroupkey(member1,3)

	//ModifyPerminType_AddGropManagerPerm
	res, err =ptable.GrantPermission(common.Address{},member1,member2,gropAddr,ModifyPerminType_AddGropManagerPerm,"a",true)
	if !res {
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_AddCrtContractManagerPerm")
	}
	if !ptable.CheckActionPerm(member2,gropAddr,common.Address{},ModifyPerminType_DelGrop){

		t.Fatalf("CheckActionPerm err ModifyPerminType_DelGrop")
	}

	//ModifyPerminType_DelGropManagerPerm
	res, err =ptable.GrantPermission(member1,root1,member2,gropAddr,ModifyPerminType_DelGropManagerPerm,"a",true)
	if !res {
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_AddCrtContractManagerPerm")
	}
	if ptable.CheckActionPerm(member2,gropAddr,common.Address{},ModifyPerminType_DelGrop){

		t.Fatalf("CheckActionPerm err ModifyPerminType_DelGrop")
	}
	//ModifyPerminType_AddGropMemberPerm
	res, err =ptable.GrantPermission(member1,root1,member2,gropAddr,ModifyPerminType_AddGropMemberPerm,"a",true)
	if !res {
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_AddCrtContractManagerPerm")
	}
	if !ptable.CheckActionPerm(member2,gropAddr,common.Address{},PerminType_SendTx){
		t.Fatalf("CheckActionPerm err PerminType_SendTx")
	}
	//ModifyPerminType_DelGropMemberPerm
	res, err =ptable.GrantPermission(member1,root1,member2,gropAddr,ModifyPerminType_DelGropMemberPerm,"a",true)
	if !res {
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_AddCrtContractManagerPerm")
	}
	if !ptable.CheckActionPerm(member2,gropAddr,common.Address{},PerminType_SendTx){
		t.Fatalf("CheckActionPerm err PerminType_SendTx")
	}


	if !ptable.CheckActionPerm(member1,gropAddr,common.Address{},ModifyPerminType_DelGrop){
		t.Fatalf("CheckActionPerm err ModifyPerminType_DelGrop")
	}
	res, err =ptable.GrantPermission(common.Address{},member1,member1,gropAddr,ModifyPerminType_DelGrop,"a",true)
	if !res{
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_AddCrtContractManagerPerm")
	}
	if ptable.CheckActionPerm(member1,gropAddr,common.Address{},ModifyPerminType_DelGrop){

		t.Fatalf("CheckActionPerm err ModifyPerminType_DelGrop")
	}

	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_DelSendTxPerm,"a",true)
	if !res{
		fmt.Println(err)
		t.Fatalf("Grent err ")
	}

	if ptable.CheckActionPerm(member1,common.Address{},common.Address{},PerminType_SendTx){

		t.Fatalf("CheckActionPerm err PerminType_SendTx")
	}

	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddSendTxManagerPerm,"a",true)
	if !res{
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_AddSendTxManagerPerm")
	}

	if !ptable.CheckActionPerm(member1,common.Address{},common.Address{},PerminType_SendTx){

		t.Fatalf("CheckActionPerm err PerminType_SendTx")
	}

	if !ptable.CheckActionPerm(member1,common.Address{},common.Address{},ModifyPerminType_AddSendTxManagerPerm){

		t.Fatalf("CheckActionPerm err ModifyPerminType_AddSendTxManagerPerm")
	}


	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_DelSendTxManagerPerm,"a",true)
	if !res{
		fmt.Println(err)
		t.Fatalf("Grent err,ModifyPerminType_AddSendTxManagerPerm")
	}
	if ptable.CheckActionPerm(member1,common.Address{},common.Address{},ModifyPerminType_DelSendTxManagerPerm){

		t.Fatalf("CheckActionPerm err ModifyPerminType_AddSendTxManagerPerm")
	}

	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddCrtContractPerm,"a",true)
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

func Test1(t *testing.T) {
	i := int(1)
	if ModifyPerminType(i) == ModifyPerminType_AddSendTxPerm || ModifyPerminType(i) == PerminType_CreateContract{
		fmt.Println("1111")
	}else{
		t.Fatalf("transfer error")
	}


}

func TestSortRlp(t *testing.T) {
	lenSum := 100
	userAddress := make(map[common.Address]int, lenSum)
	for i := 0; i < lenSum; i++ {
		prv, _ := crypto.GenerateKey()
		address := crypto.PubkeyToAddress(prv.PublicKey)
		userAddress[address] = i + 10
	}
	ctpOrders := sortArr(userAddress)
	ctpOrders2 := sortBinary(userAddress)
	for i, v := range ctpOrders {
		if ctpOrders2[i] != v {
			fmt.Println("i ", i, " v ", v)
		}
	}

	var ctps []int
	for _, index := range ctpOrders {
		ctps = append(ctps, userAddress[index])
	}
}

func sortArr(userAddress map[common.Address]int) []common.Address {
	var ctpOrders []common.Address
	count := 0
	for i, _ := range userAddress {
		ctpOrders = append(ctpOrders, i)
		count++
	}
	for m := 0; m < len(ctpOrders)-1; m++ {
		for n := 0; n < len(ctpOrders)-1-m; n++ {
			if ctpOrders[n].Big().Cmp(ctpOrders[n+1].Big()) > 0 {
				ctpOrders[n], ctpOrders[n+1] = ctpOrders[n+1], ctpOrders[n]
			}
			count++
		}
	}
	fmt.Println("sortArr ", count)
	return ctpOrders
}

var countBinary = 0

func sortBinary(userAddress map[common.Address]int) []common.Address {
	var bpOrders []common.Address
	for i, _ := range userAddress {
		countBinary++
		if bpOrders == nil {
			bpOrders = append(bpOrders, i)
		} else {
			pos := find1(i.Big(), bpOrders)
			rear := append([]common.Address{}, bpOrders[pos:]...)
			bpOrders = append(append(bpOrders[:pos], i), rear...)
		}
	}
	fmt.Println("sortBinary ", countBinary)
	return bpOrders
}

func find1(h *big.Int, vs []common.Address) int {
	low, height := 0, len(vs)-1
	mid := 0
	for low <= height {
		countBinary++
		mid = (height + low) / 2
		if h.Cmp(vs[mid].Big()) > 0 {
			low = mid + 1
			if low > height {
				return low
			}
		} else {
			height = mid - 1
		}
	}
	return mid
}