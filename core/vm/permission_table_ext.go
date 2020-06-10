package vm

import (
	"errors"
	"fmt"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/log"
	"github.com/taiyuechain/taiyuechain/rlp"
	"io"
)

func (pt *PerminTable) Load(state StateDB) error {
	preAddr := types.PermiTableAddress
	key := common.BytesToHash(preAddr[:])
	data := state.GetCAState(preAddr, key)

	if len(data) == 0 {
		return errors.New("Load PerminTable len is 0")
	}

	hash := types.RlpHash(data)
	var temp PerminTable
	if cache, ok := PerminCache.Cache.Get(hash); ok {
		pTable := cache.(*PerminTable)
		temp = *ClonePerminCaCache(pTable)
	} else {
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

func (pt *PerminTable) Save(state StateDB) error {
	preAddr := types.PermiTableAddress
	key := common.BytesToHash(preAddr[:])
	data, err := rlp.EncodeToBytes(pt)

	if err != nil {
		log.Crit("Failed to RLP encode ImpawnImpl", "err", err)
	}
	state.SetCAState(preAddr, key, data)

	tmp := ClonePerminCaCache(pt)
	if tmp != nil {
		hash := types.RlpHash(data)
		PerminCache.Cache.Add(hash, tmp)
	}
	return err
}

// "external" PerminTable encoding. used for pos staking.
type extPerminTable struct {
	WhiteList         []common.Address
	BlackList         []common.Address
	ContractPermi     []*ContractListTable //contract Addr=> Memberlist
	CPArray           []common.Address
	GropPermi         []*GropListTable //group addr => GropListTable
	GPArray           []common.Address
	SendTranPermi     []*MemberListTable //Group Addr=> MemberList
	SPArray           []common.Address
	CrtContracetPermi []*MemberListTable //Group Addr => MemberList
	CCPArray          []common.Address
	UserBasisPermi    []*BasisPermin // persion addr => basisperim
	UBPArray          []common.Address
}

func (p *PerminTable) DecodeRLP(s *rlp.Stream) error {
	var ei extPerminTable
	if err := s.Decode(&ei); err != nil {
		return err
	}
	clts := make(map[common.Address]*ContractListTable)
	for i, cert := range ei.ContractPermi {
		clts[ei.CPArray[i]] = cert
	}
	gps := make(map[common.Address]*GropListTable)
	for i, proposal := range ei.GropPermi {
		gps[ei.GPArray[i]] = proposal
	}
	mlts := make(map[common.Address]*MemberListTable)
	for i, cert := range ei.SendTranPermi {
		mlts[ei.SPArray[i]] = cert
	}
	ctps := make(map[common.Address]*MemberListTable)
	for i, proposal := range ei.CrtContracetPermi {
		ctps[ei.CCPArray[i]] = proposal
	}
	bps := make(map[common.Address]*BasisPermin)
	for i, proposal := range ei.UserBasisPermi {
		bps[ei.UBPArray[i]] = proposal
	}

	p.WhiteList, p.BlackList, p.ContractPermi = ei.WhiteList, ei.BlackList, clts
	p.GropPermi, p.SendTranPermi, p.ContractPermi, p.UserBasisPermi = gps, mlts, clts, bps
	return nil
}

// EncodeRLP serializes b into the truechain RLP ImpawnImpl format.
func (i *PerminTable) EncodeRLP(w io.Writer) error {
	var clts []*ContractListTable
	var order []common.Address
	for i, _ := range i.ContractPermi {
		order = append(order, i)
	}
	for m := 0; m < len(order)-1; m++ {
		for n := 0; n < len(order)-1-m; n++ {
			if order[n].Big().Cmp(order[n+1].Big()) > 0 {
				order[n], order[n+1] = order[n+1], order[n]
			}
		}
	}
	for _, index := range order {
		clts = append(clts, i.ContractPermi[index])
	}

	var glts []*GropListTable
	var gltOrders []common.Address
	for i, _ := range i.GropPermi {
		gltOrders = append(gltOrders, i)
	}
	for m := 0; m < len(gltOrders)-1; m++ {
		for n := 0; n < len(gltOrders)-1-m; n++ {
			if gltOrders[n].Big().Cmp(gltOrders[n+1].Big()) > 0 {
				gltOrders[n], gltOrders[n+1] = gltOrders[n+1], gltOrders[n]
			}
		}
	}
	for _, index := range gltOrders {
		glts = append(glts, i.GropPermi[index])
	}

	var mlts []*MemberListTable
	var mltOrders []common.Address
	for i, _ := range i.SendTranPermi {
		mltOrders = append(mltOrders, i)
	}
	for m := 0; m < len(mltOrders)-1; m++ {
		for n := 0; n < len(mltOrders)-1-m; n++ {
			if mltOrders[n].Big().Cmp(mltOrders[n+1].Big()) > 0 {
				mltOrders[n], mltOrders[n+1] = mltOrders[n+1], mltOrders[n]
			}
		}
	}
	for _, index := range mltOrders {
		mlts = append(mlts, i.SendTranPermi[index])
	}

	var ctps []*MemberListTable
	var ctpOrders []common.Address
	for i, _ := range i.CrtContracetPermi {
		ctpOrders = append(ctpOrders, i)
	}
	for m := 0; m < len(ctpOrders)-1; m++ {
		for n := 0; n < len(ctpOrders)-1-m; n++ {
			if ctpOrders[n].Big().Cmp(ctpOrders[n+1].Big()) > 0 {
				ctpOrders[n], ctpOrders[n+1] = ctpOrders[n+1], ctpOrders[n]
			}
		}
	}
	for _, index := range ctpOrders {
		ctps = append(ctps, i.CrtContracetPermi[index])
	}

	var bps []*BasisPermin
	var bpOrders []common.Address
	for i, _ := range i.UserBasisPermi {
		bpOrders = append(bpOrders, i)
	}
	for m := 0; m < len(bpOrders)-1; m++ {
		for n := 0; n < len(bpOrders)-1-m; n++ {
			if bpOrders[n].Big().Cmp(bpOrders[n+1].Big()) > 0 {
				bpOrders[n], bpOrders[n+1] = bpOrders[n+1], bpOrders[n]
			}
		}
	}
	for _, index := range bpOrders {
		bps = append(bps, i.UserBasisPermi[index])
	}

	return rlp.Encode(w, extPerminTable{
		WhiteList:         i.WhiteList,
		BlackList:         i.BlackList,
		ContractPermi:     clts,
		CPArray:           order,
		GropPermi:         glts,
		GPArray:           gltOrders,
		SendTranPermi:     mlts,
		SPArray:           mltOrders,
		CrtContracetPermi: ctps,
		CCPArray:          ctpOrders,
		UserBasisPermi:    bps,
		UBPArray:          bpOrders,
	})
}
