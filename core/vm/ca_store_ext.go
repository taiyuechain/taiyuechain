package vm

import (
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/rlp"
	"io"
)

// "external" ImpawnImpl encoding. used for pos staking.
type extCACertList struct {
	CACerts       []*CACert
	CAArray       []uint64
	Proposals     []*ProposalState
	ProposalArray []common.Hash
	CAAmount      uint64
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

	i.caCertMap, i.proposalMap, i.cAAmount = certs, proposals, ei.CAAmount
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
	for m := 0; m < len(order)-1; m++ {
		for n := 0; n < len(order)-1-m; n++ {
			if order[n] > order[n+1] {
				order[n], order[n+1] = order[n+1], order[n]
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
		CAAmount:      i.cAAmount,
	})
}
