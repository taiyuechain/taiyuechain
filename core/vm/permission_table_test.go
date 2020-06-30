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
	"testing"
)

var (
	rootList        []common.Address
	root1           common.Address
	member1         common.Address
	member2         common.Address
	member3         common.Address
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
	member1 = common.HexToAddress("0xFE9cFAc0EDf17FB746069f1d12885217fF30234C")
	member2 = common.HexToAddress("0x1b3d007C0D5318D241F26374F379E882cDCbc371")
	member3 = common.HexToAddress("0x5A778953403352839Faf865C82309B63965f15F2")
}

//
func TestSendTxManagerPermissionTable(t *testing.T) {
	// check no permission account
	errAddr := common.BytesToAddress([]byte("1234"))
	checkNoBothTxGroupPermission(errAddr,t,false)

	res, err :=ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddSendTxPerm,"a",true)
	printResError(res,err,t,"Grent err")
	checkBaseSendTxPermission(member1,t,true)

	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_DelSendTxPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelSendTxPerm")
	checkNoBaseSendTxPermission(member1,t,false)

	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddSendTxManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddSendTxManagerPerm")
	checkBaseManagerSendTxPermission(member1,t,true)

	res, err =ptable.GrantPermission(root1,member1,member2,common.Address{},ModifyPerminType_AddSendTxPerm,"a",true)
	printResError(res,err,t,"Grent err")
	checkBaseSendTxPermission(member2,t,true)


	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_DelSendTxManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelSendTxManagerPerm")
	checkNoBaseSendTxPermission(member1,t,false)

	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddSendTxPerm,"a",true)
	printResError(res,err,t,"Grent err")
	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddSendTxManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddSendTxManagerPerm")
	checkBaseManagerSendTxPermission(member1,t,true)
	res, err =ptable.GrantPermission(root1,member1,member2,common.Address{},ModifyPerminType_AddSendTxManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddSendTxManagerPerm")
	checkBaseManagerSendTxPermission(member2,t,true)

	res, err =ptable.GrantPermission(root1,member2,member1,common.Address{},ModifyPerminType_DelSendTxManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelSendTxManagerPerm")
	checkBaseSendTxPermission(member1,t,true)
	res, err =ptable.GrantPermission(root1,root1,member2,common.Address{},ModifyPerminType_DelSendTxManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelSendTxManagerPerm")
	checkBaseSendTxPermission(member2,t,true)

	checkBaseSendTxPermission(member2,t,true)
	res, err =ptable.GrantPermission(root1,root1,member2,common.Address{},ModifyPerminType_DelSendTxPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelSendTxPerm")
	checkNoBaseSendTxPermission(member2,t,false)
}

// 
func TestGroupPermission(t *testing.T) {
	res, err :=ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddSendTxPerm,"a",true)
	printResError(res,err,t,"Grent err")
	checkBaseSendTxPermission(member1,t,true)

	res, err =ptable.GrantPermission(common.Address{},member1,common.Address{},common.Address{},ModifyPerminType_CrtGrop,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_CrtGrop")
	checkBaseSendTxPermission(member2,t,false)
	gropAddr := crypto.CreateGroupkey(member1,3)
	checkBaseGroupManagerPermission(member1,gropAddr,t,true)

	res, err =ptable.GrantPermission(member1,member1,member2,gropAddr,ModifyPerminType_AddGropMemberPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddGropMemberPerm")
	checkBaseSendTxPermission(member2,t,false)

	res, err =ptable.GrantPermission(root1,root1,gropAddr,common.Address{},ModifyPerminType_AddSendTxPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddSendTxPerm")
	checkBaseGroupPermission(member2,gropAddr,t,true)

	//ModifyPerminType_AddGropManagerPerm
	res, err =ptable.GrantPermission(common.Address{},member1,member2,gropAddr,ModifyPerminType_AddGropManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddGropManagerPerm")
	checkBaseGroupManagerPermission(member2,gropAddr,t,true)

	res, err =ptable.GrantPermission(common.Address{},member2,member3,gropAddr,ModifyPerminType_AddGropMemberPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddGropMemberPerm")
	checkBaseGroupPermission(member3,gropAddr,t,true)

	//ModifyPerminType_DelGropManagerPerm
	res, err =ptable.GrantPermission(member1,member1,member2,gropAddr,ModifyPerminType_DelGropManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelGropManagerPerm")
	checkBaseGroupPermission(member2,gropAddr,t,true)
	checkBaseGroupPermission(member3,gropAddr,t,true)

	res, err = ptable.GrantPermission(member1, member1, member2, gropAddr, ModifyPerminType_DelGrop, "a", true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelGrop")
	checkBaseGroupPermission(member1,gropAddr,t,true)
	checkBaseSendTxPermission(member1,t,true)
	checkNoBaseGroupPermission(member2,gropAddr,t,false)
	checkNoBaseGroupPermission(member3,gropAddr,t,false)
}

func TestTxGroupMemberPermissionTable(t *testing.T) {
	res, err :=ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddSendTxPerm,"a",true)
	printResError(res,err,t,"Grent err")
	checkBaseSendTxPermission(member1,t,true)

	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddSendTxManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddSendTxManagerPerm")
	checkBaseManagerSendTxPermission(member1,t,true)

	res, err =ptable.GrantPermission(root1,member1,member2,common.Address{},ModifyPerminType_AddSendTxPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddSendTxPerm")
	checkBaseSendTxPermission(member2,t,true)

	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_DelSendTxManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelSendTxManagerPerm")
	checkBaseSendTxPermission(member1,t,true)

	res, err =ptable.GrantPermission(root1,root1,member2,common.Address{},ModifyPerminType_AddSendTxManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddSendTxManagerPerm")
	checkBaseManagerSendTxPermission(member2,t,true)

	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_DelSendTxPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelSendTxPerm")
	res, err =ptable.GrantPermission(root1,root1,member2,common.Address{},ModifyPerminType_DelSendTxPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelSendTxPerm")
	checkNoBaseSendTxPermission(member1,t,false)
	checkBaseManagerSendTxPermission(member2,t,true)

	res, err =ptable.GrantPermission(root1,root1,member2,common.Address{},ModifyPerminType_DelSendTxManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelSendTxManagerPerm")
	checkNoBaseSendTxPermission(member2,t,false)
}

func TestTxGroupNormalPermissionTable(t *testing.T) {
	res, err :=ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddSendTxPerm,"a",true)
	printResError(res,err,t,"Grent err")

	res, err =ptable.GrantPermission(root1,root1,member2,common.Address{},ModifyPerminType_AddSendTxPerm,"a",true)
	printResError(res,err,t,"Grent err")
	checkSendTxPermission(member1,t,true)

	res, err =ptable.GrantPermission(common.Address{},member1,member1,common.Address{},ModifyPerminType_CrtGrop,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_CrtGrop")

	gropAddr := crypto.CreateGroupkey(member1,3)
	//ModifyPerminType_AddGropManagerPerm
	res, err =ptable.GrantPermission(common.Address{},member1,member2,gropAddr,ModifyPerminType_AddGropManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddGropManagerPerm")
	checkDelGropPermission(member2,gropAddr,t,true)

	//ModifyPerminType_DelGropManagerPerm
	res, err =ptable.GrantPermission(root1,member1,member2,gropAddr,ModifyPerminType_DelGropManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelGropManagerPerm")
	checkDelGropPermission(member2,gropAddr,t,false)

	//ModifyPerminType_AddGropMemberPerm
	res, err =ptable.GrantPermission(root1,member1,member2,gropAddr,ModifyPerminType_AddGropMemberPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddGropMemberPerm")

	checkGroupSendTxPermission(member2,gropAddr,t,true)
	//ModifyPerminType_DelGropMemberPerm
	res, err =ptable.GrantPermission(member1,root1,member2,gropAddr,ModifyPerminType_DelGropMemberPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelGropMemberPerm")
	checkGroupSendTxPermission(member2,gropAddr,t,true)

	checkDelGropPermission(member1,gropAddr,t,true)
	res, err =ptable.GrantPermission(common.Address{},member1,member1,gropAddr,ModifyPerminType_DelGrop,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelGrop")
	checkDelGropPermission(member1,gropAddr,t,false)

	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_DelSendTxPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelSendTxPerm")
	checkSendTxPermission(member1,t,false)

	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddSendTxManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_AddSendTxManagerPerm")
	checkSendTxPermission(member1,t,true)
	checkSendTxManagerPermission(member1,t,true)

	res, err =ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_DelSendTxManagerPerm,"a",true)
	printResError(res,err,t,"Grent err,ModifyPerminType_DelSendTxManagerPerm")
	checkNoBaseSendTxPermission(member1,t,false)
	checkDelSendTxManagerPermission(member1,t,false)
}

func TestTxGroupPermissionTable(t *testing.T) {
	res, err :=ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddSendTxPerm,"a",true)
	printResError(res,err,t,"Grent err")
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