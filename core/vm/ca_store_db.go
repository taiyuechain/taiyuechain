package vm

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/common/hexutil"
	"github.com/taiyuechain/taiyuechain/consensus/tbft/help"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/log"
	"github.com/taiyuechain/taiyuechain/rlp"
	"io"
	"math/big"
	"reflect"
)

func (ca *CACertList) LoadCACertList(state StateDB, preAddress common.Address) error {
	key := common.BytesToHash(preAddress[:])
	data := state.GetCAState(preAddress, key)
	lenght := len(data)
	if lenght == 0 {
		return errors.New("Load data = 0")
	}
	hash := types.RlpHash(data)
	var temp CACertList
	watch1 := help.NewTWatch(0.005, "Load impawn")
	if cc, ok := CASC.Cache.Get(hash); ok {
		caList := cc.(*CACertList)
		temp = *(CloneCaCache(caList))
	} else {
		if err := rlp.DecodeBytes(data, &temp); err != nil {
			watch1.EndWatch()
			watch1.Finish("DecodeBytes")
			log.Error(" Invalid CACertList entry RLP", "err", err)
			return errors.New(fmt.Sprintf("Invalid CACertList entry RLP %s", err.Error()))
		}
		tmp := CloneCaCache(&temp)

		if tmp != nil {
			CASC.Cache.Add(hash, tmp)
		}
	}

	ca.caCertMap, ca.proposalMap = temp.caCertMap, temp.proposalMap
	watch1.EndWatch()
	watch1.Finish("DecodeBytes")
	return nil
}

func (ca *CACertList) SaveCACertList(state StateDB, preAddress common.Address) error {
	key := common.BytesToHash(preAddress[:])
	watch1 := help.NewTWatch(0.005, "Save impawn")
	data, err := rlp.EncodeToBytes(ca)
	watch1.EndWatch()
	watch1.Finish("EncodeToBytes")

	if err != nil {
		log.Crit("Failed to RLP encode CACertList", "err", err)
	}
	for _, val := range ca.proposalMap {
		log.Info("save CA info", "Ce name", hex.EncodeToString(val.CACert), "is store", val.PHash, "caCertMap", len(ca.caCertMap), "ca", ca.caCertMap)
	}
	state.SetCAState(preAddress, key, data)

	tmp := CloneCaCache(ca)
	if tmp != nil {
		hash := types.RlpHash(data)
		CASC.Cache.Add(hash, tmp)
	}
	return err
}

// "external" CACertList encoding. used for pos staking.
type extCACertList struct {
	CACerts       []*CACert
	CAArray       []uint64
	Proposals     []*ProposalState
	ProposalArray []common.Hash
}

func (i *CACertList) DecodeRLP(s *rlp.Stream) error {
	var ei extCACertList
	if err := s.Decode(&ei); err != nil {
		return err
	}
	certs := make(map[uint64]*CACert)
	for i, cert := range ei.CACerts {
		certs[ei.CAArray[i]] = cert
	}
	proposals := make(map[common.Hash]*ProposalState)
	for i, proposal := range ei.Proposals {
		proposals[ei.ProposalArray[i]] = proposal
	}

	i.caCertMap, i.proposalMap = certs, proposals
	return nil
}

// EncodeRLP serializes b into the truechain RLP ImpawnImpl format.
func (i *CACertList) EncodeRLP(w io.Writer) error {
	var certs []*CACert
	var order []uint64
	for i, _ := range i.caCertMap {
		order = append(order, i)
	}
	for m := 0; m < len(order)-1; m++ {
		for n := 0; n < len(order)-1-m; n++ {
			if order[n] > order[n+1] {
				order[n], order[n+1] = order[n+1], order[n]
			}
		}
	}
	for _, index := range order {
		certs = append(certs, i.caCertMap[index])
	}

	var proposals []*ProposalState
	var proposalOrders []common.Hash
	for i, _ := range i.proposalMap {
		proposalOrders = append(proposalOrders, i)
	}
	for m := 0; m < len(proposalOrders)-1; m++ {
		for n := 0; n < len(proposalOrders)-1-m; n++ {
			if proposalOrders[n].Big().Cmp(proposalOrders[n+1].Big()) > 0 {
				proposalOrders[n], proposalOrders[n+1] = proposalOrders[n+1], proposalOrders[n]
			}
		}
	}
	for _, index := range proposalOrders {
		proposals = append(proposals, i.proposalMap[index])
	}
	return rlp.Encode(w, extCACertList{
		CACerts:       certs,
		CAArray:       order,
		Proposals:     proposals,
		ProposalArray: proposalOrders,
	})
}

// "external" ProposalState encoding. used for pos staking.
type extProposalState struct {
	PHash              common.Hash
	CACert             []byte
	StartHight         *big.Int
	EndHight           *big.Int
	PState             uint8
	NeedPconfirmNumber uint64 // muti need confir len
	PNeedDo            uint8  // only supprot add and del
	SignList           []common.Hash
	SignMap            []bool
	SignArray          []common.Hash
}

func (i *ProposalState) DecodeRLP(s *rlp.Stream) error {
	var ei extProposalState
	if err := s.Decode(&ei); err != nil {
		return err
	}
	proposals := make(map[common.Hash]bool)
	for i, proposal := range ei.SignMap {
		proposals[ei.SignArray[i]] = proposal
	}

	i.SignMap, i.PHash, i.CACert, i.StartHeight, i.EndHeight, i.PState, i.NeedPconfirmNumber, i.PNeedDo, i.SignList =
		proposals, ei.PHash, ei.CACert, ei.StartHight, ei.EndHight, ei.PState, ei.NeedPconfirmNumber, ei.PNeedDo, ei.SignList
	return nil
}

// EncodeRLP serializes b into the truechain RLP ImpawnImpl format.
func (i *ProposalState) EncodeRLP(w io.Writer) error {
	var proposals []bool
	var proposalOrders []common.Hash
	for i, _ := range i.SignMap {
		proposalOrders = append(proposalOrders, i)
	}
	for m := 0; m < len(proposalOrders)-1; m++ {
		for n := 0; n < len(proposalOrders)-1-m; n++ {
			if proposalOrders[n].Big().Cmp(proposalOrders[n+1].Big()) > 0 {
				proposalOrders[n], proposalOrders[n+1] = proposalOrders[n+1], proposalOrders[n]
			}
		}
	}
	for _, index := range proposalOrders {
		proposals = append(proposals, i.SignMap[index])
	}
	return rlp.Encode(w, extProposalState{
		PHash:              i.PHash,
		CACert:             i.CACert,
		StartHight:         i.StartHeight,
		EndHight:           i.EndHeight,
		PState:             i.PState,
		NeedPconfirmNumber: i.NeedPconfirmNumber,
		PNeedDo:            i.PNeedDo,
		SignList:           i.SignList,
		SignMap:            proposals,
		SignArray:          proposalOrders,
	})
}

type extCACert struct {
	CACert      []Cert   `json:"cacert"`
	Pubky       [][]byte // cacert hash=> publick key
	PbArr       []common.Hash
	CoinAddress []common.Address
	IsStore     []bool `json:"isstore"`
}

func (i *CACert) DecodeRLP(s *rlp.Stream) error {
	var ei extCACert
	if err := s.Decode(&ei); err != nil {
		return err
	}
	proposals := make(map[common.Hash][]byte)
	for i, proposal := range ei.Pubky {
		proposals[ei.PbArr[i]] = proposal
	}

	i.CACert, i.Pubky, i.CoinAddress, i.IsStore = ei.CACert, proposals, ei.CoinAddress, ei.IsStore
	return nil
}

// EncodeRLP serializes b into the truechain RLP ImpawnImpl format.
func (i *CACert) EncodeRLP(w io.Writer) error {
	var proposals [][]byte
	var proposalOrders []common.Hash
	for i, _ := range i.Pubky {
		proposalOrders = append(proposalOrders, i)
	}
	for m := 0; m < len(proposalOrders)-1; m++ {
		for n := 0; n < len(proposalOrders)-1-m; n++ {
			if proposalOrders[n].Big().Cmp(proposalOrders[n+1].Big()) > 0 {
				proposalOrders[n], proposalOrders[n+1] = proposalOrders[n+1], proposalOrders[n]
			}
		}
	}
	for _, index := range proposalOrders {
		proposals = append(proposals, i.Pubky[index])
	}

	return rlp.Encode(w, extCACert{
		CACert:      i.CACert,
		Pubky:       proposals,
		PbArr:       proposalOrders,
		CoinAddress: i.CoinAddress,
		IsStore:     i.IsStore,
	})
}

func (c *CACertList) GetCACertList() *CACertList {
	return c
}

// MarshalJSON marshals as JSON.
func (l CACertList) MarshalJSON() ([]byte, error) {
	type CACertList struct {
		CaCertMap   map[uint64]*CACert             `json:"cacertmap"`
		ProposalMap map[common.Hash]*ProposalState `json:"proposalmap"`
	}
	var enc CACertList
	enc.CaCertMap = l.caCertMap
	enc.ProposalMap = l.proposalMap
	return json.Marshal(&enc)
}

// UnmarshalJSON unmarshals from JSON.
func (l *CACertList) UnmarshalJSON(input []byte) error {
	type CACertList struct {
		CaCertMap   map[uint64]*CACert             `json:"cacertmap"`
		ProposalMap map[common.Hash]*ProposalState `json:"proposalmap"`
	}
	var dec CACertList
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.CaCertMap == nil {
		return errors.New("missing required field 'cacertmap' for CACertList")
	}
	l.caCertMap = dec.CaCertMap
	if dec.ProposalMap != nil {
		l.proposalMap = dec.ProposalMap
	}
	return nil
}

// MarshalJSON marshals as JSON.
func (l ProposalState) MarshalJSON() ([]byte, error) {
	type ProposalState struct {
		PHash              common.Hash          `json:"phash"`
		CACert             hexutil.Bytes        `json:"cacert"`
		StartHeight        *hexutil.Big         `json:"startheight"`
		EndHeight          *hexutil.Big         `json:"endheight"`
		PState             hexutil.Uint         `json:"pstate"`
		NeedPconfirmNumber hexutil.Uint64       `json:"needconfirmnumber"`
		PNeedDo            hexutil.Uint         `json:"pneeddo"`
		SignList           []common.Hash        `json:"signlist"`
		SignMap            map[common.Hash]bool `json:"signmap"`
	}
	var enc ProposalState
	enc.PHash = l.PHash
	enc.CACert = l.CACert
	enc.StartHeight = (*hexutil.Big)(l.StartHeight)
	enc.EndHeight = (*hexutil.Big)(l.EndHeight)
	enc.PState = hexutil.Uint(l.PState)
	enc.NeedPconfirmNumber = hexutil.Uint64(l.NeedPconfirmNumber)
	enc.PNeedDo = hexutil.Uint(l.PNeedDo)
	enc.SignList = l.SignList
	enc.SignMap = l.SignMap
	return json.Marshal(&enc)
}

// UnmarshalJSON unmarshals from JSON.
func (l *ProposalState) UnmarshalJSON(input []byte) error {
	type ProposalState struct {
		PHash              *common.Hash         `json:"phash"`
		CACert             *hexutil.Bytes       `json:"cacert"`
		StartHeight        *hexutil.Big         `json:"startheight"`
		EndHeight          *hexutil.Big         `json:"endheight"`
		PState             *hexutil.Uint        `json:"pstate"`
		NeedPconfirmNumber *hexutil.Uint64      `json:"needconfirmnumber"`
		PNeedDo            *hexutil.Uint        `json:"pneeddo"`
		SignList           []common.Hash        `json:"signlist"`
		SignMap            map[common.Hash]bool `json:"signmap"`
	}
	var dec ProposalState
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.PHash != nil {
		l.PHash = *dec.PHash
	}
	if dec.CACert != nil {
		l.CACert = *dec.CACert
	}
	if dec.StartHeight != nil {
		l.StartHeight = (*big.Int)(dec.StartHeight)
	}
	if dec.EndHeight != nil {
		l.EndHeight = (*big.Int)(dec.EndHeight)
	}
	if dec.PState != nil {
		l.PState = uint8(*dec.PState)
	}
	if dec.NeedPconfirmNumber != nil {
		l.NeedPconfirmNumber = uint64(*dec.NeedPconfirmNumber)
	}
	if dec.PNeedDo != nil {
		l.PNeedDo = uint8(*dec.PNeedDo)
	}
	if dec.SignList != nil {
		l.SignList = dec.SignList
	}
	if dec.SignMap != nil {
		l.SignMap = dec.SignMap
	}
	return nil
}

type Cert []byte

// UnmarshalText parses a hash in hex syntax.
func (h *Cert) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedText("Cert", input, *h)
}

// UnmarshalJSON parses a hash in hex syntax.
func (h *Cert) UnmarshalJSON(input []byte) error {
	return hexutil.UnmarshalFixedJSON(certT, input, *h)
}

// MarshalText returns the hex representation of h.
func (h Cert) MarshalText() ([]byte, error) {
	return hexutil.Bytes(h[:]).MarshalText()
}

var (
	certT = reflect.TypeOf(Cert{})
)

// TerminalString implements log.TerminalStringer, formatting a string for console
// output during logging.
func (h Cert) TerminalString() string {
	len := len(h)
	return fmt.Sprintf("%x…%x", h[:6], h[len-7:])
}
