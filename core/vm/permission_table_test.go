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
	"testing"
	"github.com/taiyuechain/taiyuechain/common"
	"fmt"
)

var(
	pbft1PrivString ="7631a11e9d28563cdbcf96d581e4b9a19e53ad433a53c25a9f18c74ddf492f75"
	pbft2PrivString ="bab8dbdcb4d974eba380ff8b2e459efdb6f8240e5362e40378de3f9f5f1e67bb"
	pbft3PrivString ="122d186b77a030e04f5654e13d934b21af2aac03b942c3ecda4632364d81cbab"
	pbft4PrivString ="fe44cbc0e164092a6746bd57957422ab165c009d0299c7639a2f4d290317f20f"
	rootList  []common.Address
	)
func init(){
	SetConfig(true,true)

	rootList = append(rootList, common.HexToAddress("0x21C16f03bbF085D6908569d159Ad40BcafdB80C5"))
	rootList = append(rootList, common.HexToAddress("0xa9A2CbA5d5d16DE370375B42662F3272279B2b89"))
	rootList = append(rootList, common.HexToAddress("0x6bE9780954580FCC268944e9D6271B3Dfc886997"))
	rootList = append(rootList, common.HexToAddress("0x03096816367827E9C5c1993AE18b237895717500"))
}

func TestPerminTable_GrantPermission(t *testing.T) {

	//add send tx
	ptable := NewPerminTable()




	ptable.InitPBFTRootGrop(rootList)

	root1 := rootList[1]
	member1 :=common.HexToAddress("0xf22142DbF24C324Eb021332c2D673d3B819B955a")

	res, err :=ptable.GrantPermission(root1,root1,member1,common.Address{},ModifyPerminType_AddSendTxPerm,"a",true)
	if !res{
		fmt.Println(err)
		t.Fatalf("Grent err")
	}



}

