// Copyright 2017 The go-ethereum Authors
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

// Package consensus implements different Ethereum consensus engines.
package consensus

import (
	"math/big"

	"github.com/taiyuechain/taiyuechain/cim"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/core/state"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/core/vm"
	"github.com/taiyuechain/taiyuechain/params"
	"github.com/taiyuechain/taiyuechain/rpc"
)

// ChainReader defines a small collection of methods needed to access the local
// blockchain during header and/or signs verification.
type ChainReader interface {
	// Config retrieves the blockchain's chain configuration.
	Config() *params.ChainConfig

	// CurrentHeader retrieves the current header from the local chain.
	CurrentHeader() *types.Header

	// GetHeader retrieves a block header from the database by hash and number.
	GetHeader(hash common.Hash, number uint64) *types.Header

	// GetHeaderByNumber retrieves a block header from the database by number.
	GetHeaderByNumber(number uint64) *types.Header

	// GetHeaderByHash retrieves a block header from the database by its hash.
	GetHeaderByHash(hash common.Hash) *types.Header

	// GetBlock retrieves a block from the database by hash and number.
	GetBlock(hash common.Hash, number uint64) *types.Block
}

// Engine is an algorithm agnostic consensus engine.
type Engine interface {
	SetElection(e CommitteeElection)

	SetCimList(clist *cim.CimList)

	GetElection() CommitteeElection

	// Author retrieves the Ethereum address of the account that minted the given
	// block, which may be different from the header's coinbase if a consensus
	// engine is based on signatures.
	Author(header *types.Header) (common.Address, error)

	// VerifyHeader checks whether a header conforms to the consensus rules of a
	// given engine. Verifying the seal may be done optionally here, or explicitly
	// via the VerifySeal method.
	VerifyHeader(chain ChainReader, header *types.Header) error

	// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
	// concurrently. The method returns a quit channel to abort the operations and
	// a results channel to retrieve the async verifications (the order is that of
	// the input slice).
	VerifyHeaders(chain ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error)

	VerifySigns(fastnumber *big.Int, fastHash common.Hash, signs []*types.PbftSign) error

	VerifySwitchInfo(fastnumber *big.Int, info []*types.CommitteeMember) error

	// Prepare initializes the consensus fields of a block header according to the
	// rules of a particular engine. The changes are executed inline.
	Prepare(chain ChainReader, header *types.Header) error
	// Finalize runs any post-transaction state modifications (e.g. block rewards)
	// and assembles the final block.
	// Note: The block header and state database might be updated to reflect any
	// consensus rules that happen at finalization (e.g. block rewards).
	Finalize(chain ChainReader, header *types.Header, state *state.StateDB,
		txs []*types.Transaction, receipts []*types.Receipt, feeAmount *big.Int) (*types.Block, error)
	APIs(chain ChainReader) []rpc.API
}

//Election module implementation committee interface
type CommitteeElection interface {
	// VerifySigns verify the fast chain committee signatures in batches
	VerifySigns(pvs []*types.PbftSign) ([]*types.CommitteeMember, []error)

	// VerifySwitchInfo verify committee members and it's state
	VerifySwitchInfo(fastnumber *big.Int, info []*types.CommitteeMember) error

	//Get a list of committee members
	//GetCommittee(FastNumber *big.Int, FastHash common.Hash) (*big.Int, []*types.CommitteeMember)
	GetCommittee(fastNumber *big.Int) []*types.CommitteeMember

	GenerateFakeSigns(fb *types.Block) ([]*types.PbftSign, error)
}

// PoW is a consensus engine based on proof-of-work.
type PoW interface {
	Engine

	// Hashrate returns the current mining hashrate of a PoW consensus engine.
	Hashrate() float64
}

func makeCAContractInitState(state *state.StateDB, certList [][]byte, fastNumber *big.Int,pubk [][]byte,coinAddr []common.Address) bool {

	CaCertAddress := types.CACertListAddress
	key := common.BytesToHash(CaCertAddress[:])
	obj := state.GetCAState(CaCertAddress, key)
	if len(obj) == 0 {
		i := vm.NewCACertList()
		i.InitCACertList(certList, fastNumber,pubk,coinAddr)
		i.SaveCACertList(state, CaCertAddress)
		state.SetNonce(CaCertAddress, 1)
		state.SetCode(CaCertAddress, CaCertAddress[:])
	}

	pTAddress := types.PermiTableAddress
	ptKey := common.BytesToHash(pTAddress[:])
	objpt := state.GetCAState(pTAddress, ptKey)
	if len(objpt) == 0 {
		i := vm.NewPerminTable()

		i.InitPBFTRootGrop(coinAddr)
		i.Save(state)
		state.SetNonce(pTAddress, 1)
		state.SetCode(pTAddress, pTAddress[:])
	}
	return false
}
func OnceInitCAState(state *state.StateDB, fastNumber *big.Int, certList [][]byte,pubk [][]byte,coinAddr []common.Address) bool {
	return makeCAContractInitState(state, certList, fastNumber,pubk,coinAddr)
}

func CheckCAElection(state *state.StateDB, fastNumber *big.Int, rootCimList *cim.CimList) {
	CaCertAddress := types.CACertListAddress
	epoch := types.GetEpochIDFromHeight(fastNumber)
	_, end := types.GetEpochHeigth(epoch)

	if new(big.Int).Sub(end, fastNumber).Uint64() == types.EpochElectionPoint {
		i := vm.NewCACertList()
		i.LoadCACertList(state, CaCertAddress)
		i.ChangeElectionCaList(fastNumber, state)

	}

	//updata cim
	if end.Cmp(fastNumber) == 0 {
		i := vm.NewCACertList()
		i.LoadCACertList(state, CaCertAddress)
		nextEpoch := epoch.Uint64()+1
		rootCimList.UpdataCert(i.GetCertList(nextEpoch))

		//updata permisson
		curRootListCert :=i.GetCACertMapByEpoch(epoch.Uint64())
		oldRootListCert :=i.GetCACertMapByEpoch(epoch.Uint64()-1)

		var  curRootAddr []common.Address
		var  oldRootAddr []common.Address

		for _,pk:=range curRootListCert.CoinAddress{
			//pkecsda,_ := crypto.UnmarshalPubkey(pk)
			curRootAddr = append(curRootAddr, pk)
		}
		if oldRootListCert != nil {
			for _,pk:=range oldRootListCert.CoinAddress{
				//pkecsda,_ := crypto.UnmarshalPubkey(pk)
				oldRootAddr = append(oldRootAddr, pk)
			}
		}



		permTable := vm.NewPerminTable()
		permTable.Load(state)
		permTable.UpdataRootInElection(oldRootAddr,curRootAddr)
		permTable.Save(state)
	}

	if state.PermissionChange() {
		rootCimList.UpdataPermission(state)
	}
}
