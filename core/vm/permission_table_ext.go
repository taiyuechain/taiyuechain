package vm

import (
	"errors"
	"fmt"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/log"
	"github.com/taiyuechain/taiyuechain/rlp"
	"io"
	"math/big"
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
		if order == nil {
			order = append(order, i)
		} else {
			pos := find(i.Big(), order)
			rear := append([]common.Address{}, order[pos:]...)
			order = append(append(order[:pos], i), rear...)
		}
	}
	for _, index := range order {
		clts = append(clts, i.ContractPermi[index])
	}

	var glts []*GropListTable
	var gltOrders []common.Address
	for i, _ := range i.GropPermi {
		if gltOrders == nil {
			gltOrders = append(gltOrders, i)
		} else {
			pos := find(i.Big(), gltOrders)
			rear := append([]common.Address{}, gltOrders[pos:]...)
			gltOrders = append(append(gltOrders[:pos], i), rear...)
		}
	}
	for _, index := range gltOrders {
		glts = append(glts, i.GropPermi[index])
	}

	var mlts []*MemberListTable
	var mltOrders []common.Address
	for i, _ := range i.SendTranPermi {
		if mltOrders == nil {
			mltOrders = append(mltOrders, i)
		} else {
			pos := find(i.Big(), mltOrders)
			rear := append([]common.Address{}, mltOrders[pos:]...)
			mltOrders = append(append(mltOrders[:pos], i), rear...)
		}
	}
	for _, index := range mltOrders {
		mlts = append(mlts, i.SendTranPermi[index])
	}

	var ctps []*MemberListTable
	var ctpOrders []common.Address
	for i, _ := range i.CrtContracetPermi {
		if ctpOrders == nil {
			ctpOrders = append(ctpOrders, i)
		} else {
			pos := find(i.Big(), ctpOrders)
			rear := append([]common.Address{}, ctpOrders[pos:]...)
			ctpOrders = append(append(ctpOrders[:pos], i), rear...)
		}
	}
	for _, index := range ctpOrders {
		ctps = append(ctps, i.CrtContracetPermi[index])
	}

	var bps []*BasisPermin
	var bpOrders []common.Address
	for i, _ := range i.UserBasisPermi {
		if bpOrders == nil {
			bpOrders = append(bpOrders, i)
		} else {
			pos := find(i.Big(), bpOrders)
			rear := append([]common.Address{}, bpOrders[pos:]...)
			bpOrders = append(append(bpOrders[:pos], i), rear...)
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

func find(h *big.Int, vs []common.Address) int {
	low, height := 0, len(vs)-1
	mid := 0
	for low <= height {
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

type extMemberInfo struct {
	MemberID common.Address
	JoinTime uint64
}

func (m *MemberInfo) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, extMemberInfo{
		MemberID: m.MemberID,
		JoinTime: uint64(m.JoinTime),
	})
}

func (m *MemberInfo) DecodeRLP(s *rlp.Stream) error {
	var ei extMemberInfo
	if err := s.Decode(&ei); err != nil {
		return err
	}
	m.JoinTime, m.MemberID = int64(ei.JoinTime), ei.MemberID
	return nil
}
