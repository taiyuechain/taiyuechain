package vm

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/log"
	"github.com/taiyuechain/taiyuechain/rlp"
	"io"
	"math/big"
	"strconv"
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
		//tmp := ClonePerminCaCache(&temp)
		//if tmp != nil {
		//	PerminCache.Cache.Add(hash, tmp)
		//}
	}

	pt.LastRootID = temp.LastRootID
	pt.RootList = temp.RootList
	pt.PBFT2Root = temp.PBFT2Root
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

	//tmp := ClonePerminCaCache(pt)
	//if tmp != nil {
	//	hash := types.RlpHash(data)
	//	PerminCache.Cache.Add(hash, tmp)
	//}
	return err
}

func (h *MemberTable) String() string {
	s := "Manager "
	for _, v := range h.Manager {
		s += crypto.AddressToHex(v.MemberID) + " "
		s += strconv.FormatUint(uint64(v.JoinTime), 10) + " "
	}
	s = "\n Member "
	for _, v := range h.Member {
		s += crypto.AddressToHex(v.MemberID) + " "
		s += strconv.FormatUint(uint64(v.JoinTime), 10) + " "
	}
	return s
}

func (h *extPerminTable) String() string {
	s := "BlackList"
	for _, v := range h.BlackList {
		s += crypto.AddressToHex(v)
	}
	s += "WhiteList\n"
	for _, v := range h.WhiteList {
		s += crypto.AddressToHex(v)
	}
	s += "ContractPermi\n"
	for k, v := range h.ContractPermi {
		s += "key " + crypto.AddressToHex(h.CPArray[k]) + " "
		s += crypto.AddressToHex(v.GroupKey) + " "
		s += crypto.AddressToHex(v.Creator) + " "
		s += strconv.FormatUint(uint64(v.CreateFlag), 10) + " "
		s += strconv.FormatBool(v.IsWhitListWork) + " "
		s += v.WhiteMembers.String() + " WhiteMembers "
		s += v.BlackMembers.String() + " BlackMembers "
	}
	s += "GropPermi\n"
	for k, v := range h.GropPermi {
		s += "key " + crypto.AddressToHex(h.GPArray[k]) + " "
		s += crypto.AddressToHex(v.GroupKey) + " "
		s += strconv.FormatUint(uint64(v.Id), 10) + " "
		s += crypto.AddressToHex(v.Creator) + " "
		s += v.Name + " "
		s += v.WhiteMembers.String() + " WhiteMembers "
		s += v.BlackMembers.String() + " BlackMembers "
	}
	s += "SendTranPermi\n"
	for k, v := range h.SendTranPermi {
		s += "key " + crypto.AddressToHex(h.SPArray[k]) + " "
		s += crypto.AddressToHex(v.GroupKey) + " "
		s += strconv.FormatUint(uint64(v.Id), 10) + " "
		s += crypto.AddressToHex(v.Creator) + " "
		s += strconv.FormatBool(v.IsWhitListWork) + " "
		s += v.WhiteMembers.String() + " WhiteMembers "
		s += v.BlackMembers.String() + " BlackMembers "
	}
	s += "CrtContracetPermi\n"
	for k, v := range h.CrtContracetPermi {
		s += "key " + crypto.AddressToHex(h.CCPArray[k]) + " "
		s += crypto.AddressToHex(v.GroupKey) + " "
		s += strconv.FormatUint(uint64(v.Id), 10) + " "
		s += crypto.AddressToHex(v.Creator) + " "
		s += strconv.FormatBool(v.IsWhitListWork) + " "
		s += v.WhiteMembers.String() + " WhiteMembers "
		s += v.BlackMembers.String() + " BlackMembers "
	}
	s += "UserBasisPermi\n"
	for k, v := range h.UserBasisPermi {
		s += "key " + crypto.AddressToHex(h.UBPArray[k]) + " "
		s += crypto.AddressToHex(v.MemberID) + " "
		s += crypto.AddressToHex(v.CreatorRoot) + " "
		s += strconv.FormatBool(v.SendTran) + " "
		s += strconv.FormatBool(v.CrtContract) + " "
		s += strconv.FormatUint(uint64(v.GropId), 10) + " "
		for _, vv := range v.GropList {
			s += crypto.AddressToHex(vv) + " "
		}
	}
	return s
}

// "external" PerminTable encoding. used for pos staking.
type extPerminTable struct {
	LastRootID        uint64
	WhiteList         []common.Address
	BlackList         []common.Address
	RootList          []common.Address
	PBFT2Root         []common.Address
	PRArray           []common.Address
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
	//fmt.Println("ei load ",ei.String())

	prs := make(map[common.Address]common.Address)
	for i, cert := range ei.PBFT2Root {
		prs[ei.PRArray[i]] = cert
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

	p.LastRootID, p.WhiteList, p.BlackList, p.RootList, p.ContractPermi, p.PBFT2Root = ei.LastRootID, ei.WhiteList, ei.BlackList, ei.RootList, clts, prs
	p.GropPermi, p.SendTranPermi, p.CrtContracetPermi, p.UserBasisPermi = gps, mlts, ctps, bps
	return nil
}

// EncodeRLP serializes b into the truechain RLP ImpawnImpl format.
func (i *PerminTable) EncodeRLP(w io.Writer) error {
	var prs []common.Address
	var prsOrder []common.Address
	for i, _ := range i.PBFT2Root {
		if prsOrder == nil {
			prsOrder = append(prsOrder, i)
		} else {
			pos := find(i.Big(), prsOrder)
			rear := append([]common.Address{}, prsOrder[pos:]...)
			prsOrder = append(append(prsOrder[:pos], i), rear...)
		}
	}
	for _, index := range prsOrder {
		prs = append(prs, i.PBFT2Root[index])
	}

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
	ei := extPerminTable{
		LastRootID:        i.LastRootID,
		WhiteList:         i.WhiteList,
		BlackList:         i.BlackList,
		RootList:          i.RootList,
		PBFT2Root:         prs,
		PRArray:           prsOrder,
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
	}
	//fmt.Println("ei save ",ei.String())
	return rlp.Encode(w, ei)
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

func (l PerminTable) MarshalJSON() ([]byte, error) {
	type CACertList struct {
		LastRootID        uint64                                 `json:"last_root_id"`
		WhiteList         []common.Address                      `json:"white_list"`
		BlackList         []common.Address                      `json:"black_list"`
		RootList          []common.Address                      `json:"root_list"`
		PBFT2Root         map[common.Address]common.Address     `json:"pbft_root"`
		ContractPermi     map[common.Address]*ContractListTable `json:"contract_perm"`
		GropPermi         map[common.Address]*GropListTable     `json:"group_perm"`
		SendTranPermi     map[common.Address]*MemberListTable   `json:"send_tran_perm"`
		CrtContracetPermi map[common.Address]*MemberListTable   `json:"crt_contract_perm"`
		UserBasisPermi    map[common.Address]*BasisPermin       `json:"user_basis_perm"`
	}
	var enc CACertList
	enc.LastRootID = l.LastRootID
	enc.WhiteList = l.WhiteList
	enc.BlackList = l.BlackList
	enc.RootList = l.RootList
	enc.PBFT2Root = l.PBFT2Root
	enc.ContractPermi = l.ContractPermi
	enc.GropPermi = l.GropPermi
	enc.SendTranPermi = l.SendTranPermi
	enc.CrtContracetPermi = l.CrtContracetPermi
	enc.UserBasisPermi = l.UserBasisPermi
	return json.Marshal(&enc)
}

// UnmarshalJSON unmarshals from JSON.
func (l *PerminTable) UnmarshalJSON(input []byte) error {
	type CACertList struct {
		LastRootID        *uint64                                `json:"last_root_id"`
		WhiteList         []common.Address                      `json:"white_list"`
		BlackList         []common.Address                      `json:"black_list"`
		RootList          []common.Address                      `json:"root_list"`
		PBFT2Root         map[common.Address]common.Address     `json:"pbft_root"`
		ContractPermi     map[common.Address]*ContractListTable `json:"contract_perm"`
		GropPermi         map[common.Address]*GropListTable     `json:"group_perm"`
		SendTranPermi     map[common.Address]*MemberListTable   `json:"send_tran_perm"`
		CrtContracetPermi map[common.Address]*MemberListTable   `json:"crt_contract_perm"`
		UserBasisPermi    map[common.Address]*BasisPermin       `json:"user_basis_perm"`
	}
	var dec CACertList
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.LastRootID == nil {
		return errors.New("missing required field 'last_root_id' for CACertList")
	}
	l.LastRootID = *dec.LastRootID

	if dec.WhiteList != nil {
		l.WhiteList = dec.WhiteList
	}
	if dec.BlackList != nil {
		l.BlackList = dec.BlackList
	}
	if dec.RootList != nil {
		l.RootList = dec.RootList
	}
	if dec.PBFT2Root != nil {
		l.PBFT2Root = dec.PBFT2Root
	}
	if dec.ContractPermi != nil {
		l.ContractPermi = dec.ContractPermi
	}
	if dec.GropPermi != nil {
		l.GropPermi = dec.GropPermi
	}
	if dec.SendTranPermi != nil {
		l.SendTranPermi = dec.SendTranPermi
	}
	if dec.CrtContracetPermi != nil {
		l.CrtContracetPermi = dec.CrtContracetPermi
	}
	if dec.UserBasisPermi != nil {
		l.UserBasisPermi = dec.UserBasisPermi
	}
	return nil
}
