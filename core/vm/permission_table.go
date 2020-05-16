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
	"errors"
	"fmt"

	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/core/types"
	lru "github.com/hashicorp/golang-lru"
	"github.com/taiyuechain/taiyuechain/rlp"
	"github.com/taiyuechain/taiyuechain/log"

)
////cache

type PerminType int

const (
	PermintionNil PerminType = iota
	PerminType_Supervision
	PerminType_NodeIn
	PerminType_PbftIn
	PerminType_SendTx
	PerminType_AddSendTxPerm
	PerminType_DelSendTxPerm
	PerminType_CreateContract
	PerminType_AddCrtCtractPrem
	PerminType_DelCrtCtractPrem
	PerminType_CreateGroup
	PerminType_AddGroupManager
	PerminType_DelGropManager
	PerminType_AddGroupMember
	PerminType_DelGropMember
	PerminType_AddCtractManager
	PerminType_DelCtractManager
	PerminType_AddCtractAccess
	PerminType_DelCtractAccess
	PerminType_AddWhiteListMember
	PerminType_DelWhiteListMember
	PerminType_AddBlackListMember
	PerminType_DelBlockListMember
	PerminType_AddCrtGroupPrem
	PerminType_DelCrtGroupPrem
	PerminType_AddSendTxManager
	PerminType_DelSendTxManager
	PerminType_AddCrtCtractManager
	PerminType_DelCrtCtractManager
	PerminType_delGroup
)

type ModifyPerminType int

const (
	ModifyPerminType_Nil ModifyPerminType = iota
	ModifyPerminType_AddSendTxPerm //add send tx permission
	ModifyPerminType_DelSendTxPerm //del send tx permission
	ModifyPerminType_AddSendTxManagerPerm
	ModifyPerminType_DelSendTxManagerPerm
	ModifyPerminType_AddCrtContractPerm
	ModifyPerminType_DelCrtContractPerm
	ModifyPerminType_AddCrtContractManagerPerm
	ModifyPerminType_DelCrtContractManagerPerm
	ModifyPerminType_AddGropManagerPerm
	ModifyPerminType_DelGropManagerPerm
	ModifyPerminType_AddGropMamberPerm
	ModifyPerminType_DelGropMamberPerm
	ModifyPerminType_AddWhitListPerm
	ModifyPerminType_DelWhitListPerm
	ModifyPerminType_AddBlockListPerm
	ModifyPerminType_DelBlockListPerm
)


var (
	ErrorMemberAlreadIn = errors.New("Mamber alread have this perminssion")
)

var PerminCache *PerminssionCache

func init() {
	PerminCache = newImpawnCache()
}

type PerminssionCache struct {
	Cache 		*lru.Cache
	size 		int
}

func newImpawnCache() *PerminssionCache {
	cc := &PerminssionCache{
		size:	20,
	}
	cc.Cache,_ = lru.New(cc.size)
	return cc
}
/////cache



type PerminTable struct {
	WhiteList  []common.Address
	BlackList  []common.Address
	ContractPermi map[common.Address]*MemberListTable  //contract Addr=> Memberlist
	GropPermi	map[common.Address]*MemberListTable //group addr => MemberList
	SendTranPermi map[common.Address]*MemberListTable //Group Addr=> MemberList
	CrtContracetPermi map[common.Address]*MemberListTable //Group Addr => MemberList
	UserBasisPermi  map[common.Address]*BasisPermin   // persion addr => basisperim
}

type MemberListTable struct {
	GroupID      common.Address
	Creater      common.Address
	IsWhitListWork  bool
	WhiteMembers *MemberTable
	BlackMembers *MemberTable

}

type MemberTable struct {
	Manager  []*MemberInfo
	Member  []*MemberInfo
}

type  MemberInfo struct {
	MemberID common.Address
	JoinTime       int
}

type BasisPermin struct {
	MemberID common.Address
	SendTran    bool
	CrtContract bool
}

func NewPerminTable() *PerminTable  {
	return &PerminTable{
		WhiteList:[]common.Address{},
		BlackList:[]common.Address{},
		ContractPermi:make(map[common.Address]*MemberListTable),
		GropPermi:make(map[common.Address]*MemberListTable),
		SendTranPermi:make(map[common.Address]*MemberListTable),
		CrtContracetPermi:make(map[common.Address]*MemberListTable),
		UserBasisPermi:make(map[common.Address]*BasisPermin),
	}
}

func ClonePerminCaCache(pt *PerminTable) *PerminTable  {
	if pt == nil{
		return nil
	}

	tempPT :=  &PerminTable{
		WhiteList:make([]common.Address, len(pt.WhiteList)),
		BlackList:make([]common.Address, len(pt.BlackList)),
		ContractPermi:make(map[common.Address]*MemberListTable),
		GropPermi:make(map[common.Address]*MemberListTable),
		SendTranPermi:make(map[common.Address]*MemberListTable),
		CrtContracetPermi:make(map[common.Address]*MemberListTable),
		UserBasisPermi:make(map[common.Address]*BasisPermin),
	}
	copy(tempPT.WhiteList, pt.WhiteList)
	copy(tempPT.BlackList, pt.BlackList)

	for k,v := range pt.ContractPermi{
		tempPT.ContractPermi[k] = v
	}
	for k,v := range pt.GropPermi{
		tempPT.GropPermi[k] = v
	}
	for k,v := range pt.SendTranPermi{
		tempPT.SendTranPermi[k] = v
	}
	for k,v := range pt.CrtContracetPermi{
		tempPT.CrtContracetPermi[k] = v
	}
	for k,v := range pt.UserBasisPermi{
		tempPT.UserBasisPermi[k] = v
	}

	return tempPT
}

func (pt *PerminTable)Load(state StateDB) error {
	preAddr := types.PermiTableAddress
	key := common.BytesToHash(preAddr[:])
	data := state.GetCAState(preAddr, key)

	if len(data) == 0{
		return errors.New("Load PerminTable len is 0")
	}

	hash :=types.RlpHash(data)

	var temp PerminTable
	if cache,ok := PerminCache.Cache.Get(hash); ok{
		pTable := cache.(* PerminTable)
		temp = *ClonePerminCaCache(pTable)
	}else{
		if err := rlp.DecodeBytes(data, &temp); err != nil {
			log.Error("Invalid Permission entry RLP", "err", err)
			return errors.New(fmt.Sprintf("Invalid Permission entry RLP %s", err.Error()))
		}
		tmp := ClonePerminCaCache(&temp)
		if tmp != nil {
			PerminCache.Cache.Add(hash, tmp)
		}
	}

	pt.WhiteList = temp.WhiteList
	pt.BlackList = temp.BlackList
	pt.ContractPermi = temp.ContractPermi
	pt.GropPermi = temp.GropPermi
	pt.SendTranPermi = temp.SendTranPermi
	pt.CrtContracetPermi = temp.CrtContracetPermi
	pt.UserBasisPermi = temp.UserBasisPermi

	return nil
}

func (pt *PerminTable)Save(state StateDB) error{
	preAddr := types.PermiTableAddress
	key := common.BytesToHash(preAddr[:])
	data, err := rlp.EncodeToBytes(pt)

	if err != nil {
		log.Crit("Failed to RLP encode ImpawnImpl", "err", err)
	}
	hash := types.RlpHash(data)
	state.SetCAState(preAddr, key, data)
	tmp := ClonePerminCaCache(pt)
	if tmp != nil {
		PerminCache.Cache.Add(hash, tmp)
	}
	return err
}

//Grant Perminission
func (pt *PerminTable)Grantpermission(from,to,member common.Address, mPermType ModifyPerminType) error  {
	switch mPermType {
	case ModifyPerminType_AddSendTxPerm:
	case ModifyPerminType_DelSendTxPerm:
	case ModifyPerminType_AddSendTxManagerPerm:
	case ModifyPerminType_DelSendTxManagerPerm:
	case ModifyPerminType_AddCrtContractPerm:
	case ModifyPerminType_DelCrtContractPerm:
	case ModifyPerminType_AddCrtContractManagerPerm:
	case ModifyPerminType_DelCrtContractManagerPerm:
	case ModifyPerminType_AddGropManagerPerm:
	case ModifyPerminType_DelGropManagerPerm:
	case ModifyPerminType_AddGropMamberPerm:
	case ModifyPerminType_DelGropMamberPerm:
	case ModifyPerminType_AddWhitListPerm:
	case ModifyPerminType_DelWhitListPerm:
	case ModifyPerminType_AddBlockListPerm:
	case ModifyPerminType_DelBlockListPerm:
	}
	return nil
}

/*func (pt *PerminTable)setSendTxPerm(from ,member common.Address, isAdd bool) error  {
	//check member
	if pt.UserBasisPermi[member].SendTran == true{
		return
	}
	return nil
}*/

func (pt *PerminTable)CheckPerim()  {

}

func (mt *MemberTable)clone() *MemberTable  {
	temp := &MemberTable{
		Manager:[]*MemberInfo{},
		Member:[]*MemberInfo{},
	}
	for _,manval :=range mt.Manager{
		temp.Manager = append(temp.Manager, manval)
	}

	for _,memval :=range mt.Member{
		temp.Member = append(temp.Manager, memval)
	}

	return temp

}


