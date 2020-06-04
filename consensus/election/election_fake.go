package election

import (
	"crypto/ecdsa"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/log"
	"github.com/taiyuechain/taiyuechain/params"
	"math/big"
)

// NewFakeElection create fake mode election only for testing
func NewFakeElection() *Election {
	var priKeys []*ecdsa.PrivateKey
	var members []*types.CommitteeMember

	for i := 0; i < params.MinimumCommitteeNumber; i++ {
		priKey, err := crypto.GenerateKey()
		priKeys = append(priKeys, priKey)
		if err != nil {
			log.Error("initMembers", "error", err)
		}
		coinbase := crypto.PubkeyToAddress(priKey.PublicKey)

		m := &types.CommitteeMember{Coinbase: coinbase, CommitteeBase: coinbase, Publickey: crypto.FromECDSAPub(&priKey.PublicKey), Flag: types.StateUsedFlag, MType: types.TypeFixed}
		members = append(members, m)
	}

	// Backup members are empty in FakeMode Election
	elected := &committee{
		id:              new(big.Int).Set(common.Big0),
		beginFastNumber: new(big.Int).Set(common.Big1),
		endFastNumber:   new(big.Int).Set(common.Big0),
		members:         members,
	}

	election := &Election{
		fastchain:       nil,
		singleNode:      false,
		committee:       elected,
		testPrivateKeys: priKeys,
	}
	return election
}

func (e *Election) GenerateFakeSigns(fb *types.Block) ([]*types.PbftSign, error) {
	var signs []*types.PbftSign

	for _, privateKey := range e.testPrivateKeys {
		voteSign := &types.PbftSign{
			Result:     types.VoteAgree,
			FastHeight: fb.Header().Number,
			FastHash:   fb.Hash(),
		}
		var err error
		signHash := voteSign.HashWithNoSign().Bytes()
		voteSign.Sign, err = crypto.Sign(signHash, privateKey)

		if err != nil {
			log.Error("fb GenerateSign error ", "err", err)
		}
		signs = append(signs, voteSign)
	}
	return signs, nil
}
