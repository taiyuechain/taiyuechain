// Copyright 2018 The TaiyueChain Authors
// This file is part of the taiyuechain library.
//
// The taiyuechain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The taiyuechain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the taiyuechain library. If not, see <http://www.gnu.org/licenses/>.

package election

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/consensus"
	"github.com/taiyuechain/taiyuechain/core"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/params"
	"github.com/taiyuechain/taiyuechain/yuedb"
)

var (
	canonicalSeed = 1
)

func makeTestBlock() *types.Block {
	db := yuedb.NewMemDatabase()
	BaseGenesis := new(core.Genesis)
	genesis := BaseGenesis.MustCommit(db)
	header := &types.Header{
		ParentHash: genesis.Hash(),
		Number:     common.Big1,
		GasLimit:   0, //core.FastCalcGasLimit(genesis),
	}
	fb := types.NewBlock(header, nil, nil, nil, nil)
	return fb
}

type nodeType struct{}

func (nodeType) GetNodeType() bool { return false }

func TestElectionTestMode(t *testing.T) {
	// TestMode election return a local static committee, whose members are generated barely
	// by local node
	election := NewFakeElection()
	members := election.GetCommittee(common.Big1)
	if len(members) != params.MinimumCommitteeNumber {
		t.Errorf("Commit members count error %d", len(members))
	}
}

func TestVerifySigns(t *testing.T) {
	// TestMode election return a local static committee, whose members are generated barely
	// by local node
	election := NewFakeElection()
	pbftSigns, err := election.GenerateFakeSigns(makeTestBlock())
	if err != nil {
		t.Errorf("Generate fake sign failed")
	}
	members, errs := election.VerifySigns(pbftSigns)

	for _, m := range members {
		if m == nil {
			t.Errorf("Pbft fake signs get invalid member")
		}
	}
	for _, err := range errs {
		if err != nil {
			t.Errorf("Pbft fake signs failed, error=%v", err)
		}
	}
}

func committeeEqual(left, right []*types.CommitteeMember) bool {
	members := make(map[common.Address]*types.CommitteeMember)
	for _, l := range left {
		members[l.Coinbase] = l
	}
	for _, r := range right {
		if m, ok := members[r.Coinbase]; ok {
			if !bytes.Equal(m.Publickey, r.Publickey) {
				return false
			}
		} else {
			return false
		}
	}
	return true
}

// makeBlockChain creates a deterministic chain of blocks rooted at parent.
func makeFast(parent *types.Block, n int, engine consensus.Engine, db yuedb.Database, seed int) []*types.Block {
	blocks, _ := core.GenerateChain(params.TestChainConfig, parent, engine, db, n, func(i int, b *core.BlockGen) {
		b.SetCoinbase(common.Address{0: byte(seed), 19: byte(i)})
	})

	return blocks
}

func TestEpoch(t *testing.T) {
	epoch := types.GetEpochIDFromHeight(new(big.Int).SetUint64(5999))
	fmt.Println("epoch",epoch)
	epoch = types.GetEpochIDFromHeight(new(big.Int).SetUint64(6000))
	fmt.Println("epoch",epoch)
}