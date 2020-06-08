// Copyright 2015 The go-ethereum Authors
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

package tai

import (
	"context"
	"math/big"

	"github.com/taiyuechain/taiyuechain/accounts"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/common/math"
	"github.com/taiyuechain/taiyuechain/core"
	"github.com/taiyuechain/taiyuechain/core/bloombits"
	"github.com/taiyuechain/taiyuechain/core/rawdb"
	"github.com/taiyuechain/taiyuechain/core/state"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/core/vm"
	"github.com/taiyuechain/taiyuechain/event"
	"github.com/taiyuechain/taiyuechain/params"
	"github.com/taiyuechain/taiyuechain/rpc"
	"github.com/taiyuechain/taiyuechain/tai/downloader"
	"github.com/taiyuechain/taiyuechain/tai/gasprice"
	"github.com/taiyuechain/taiyuechain/taidb"
)

// TRUEAPIBackend implements ethapi.Backend for full nodes
type TrueAPIBackend struct {
	tai *Taiyuechain
	gpo *gasprice.Oracle
}

// ChainConfig returns the active chain configuration.
func (b *TrueAPIBackend) ChainConfig() *params.ChainConfig {
	return b.tai.chainConfig
}

func (b *TrueAPIBackend) CurrentBlock() *types.Block {
	return b.tai.blockchain.CurrentBlock()
}

func (b *TrueAPIBackend) SetHead(number uint64) {
	b.tai.protocolManager.downloader.Cancel()
	b.tai.blockchain.SetHead(number)
}

func (b *TrueAPIBackend) SetSnailHead(number uint64) {
	b.tai.protocolManager.downloader.Cancel()
}

func (b *TrueAPIBackend) HeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Header, error) {
	// Pending block is only known by the miner
	/*if blockNr == rpc.PendingBlockNumber {
		block := b.tai.miner.PendingBlock()
		return block.Header(), nil
	}*/
	// Otherwise resolve and return the block
	if blockNr == rpc.LatestBlockNumber {
		return b.tai.blockchain.CurrentBlock().Header(), nil
	}
	return b.tai.blockchain.GetHeaderByNumber(uint64(blockNr)), nil
}
func (b *TrueAPIBackend) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	return b.tai.blockchain.GetHeaderByHash(hash), nil
}

func (b *TrueAPIBackend) BlockByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Block, error) {
	// Only snailchain has miner, also return current block here for fastchain
	if blockNr == rpc.PendingBlockNumber {
		block := b.tai.blockchain.CurrentBlock()
		return block, nil
	}
	// Otherwise resolve and return the block
	if blockNr == rpc.LatestBlockNumber {
		return b.tai.blockchain.CurrentBlock(), nil
	}
	return b.tai.blockchain.GetBlockByNumber(uint64(blockNr)), nil
}
func (b *TrueAPIBackend) GetCa(ctx context.Context, dir string) (interface{}, error) {
	// Only snailchain has miner, also return current block here for fastchain
	/*cimConfigDir, _ := config.GetDevCIMDir()
	singcertPath := cimConfigDir + dir
	id, err := cim.GetLocalIdentityDataFromConfig(singcertPath)
	if err != nil {
		return nil, err
	}*/
	return nil, nil
}

func (b *TrueAPIBackend) StateAndHeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	// Pending state is only known by the miner
	if blockNr == rpc.PendingBlockNumber {
		state, _ := b.tai.blockchain.State()
		block := b.tai.blockchain.CurrentBlock()
		return state, block.Header(), nil
	}
	// Otherwise resolve the block number and return its state
	header, err := b.HeaderByNumber(ctx, blockNr)
	if header == nil || err != nil {
		return nil, nil, err
	}
	stateDb, err := b.tai.BlockChain().StateAt(header.Root)
	return stateDb, header, err
}

func (b *TrueAPIBackend) GetBlock(ctx context.Context, hash common.Hash) (*types.Block, error) {
	return b.tai.blockchain.GetBlockByHash(hash), nil
}

func (b *TrueAPIBackend) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	if number := rawdb.ReadHeaderNumber(b.tai.chainDb, hash); number != nil {
		return rawdb.ReadReceipts(b.tai.chainDb, hash, *number), nil
	}
	return nil, nil
}

func (b *TrueAPIBackend) GetLogs(ctx context.Context, hash common.Hash) ([][]*types.Log, error) {
	number := rawdb.ReadHeaderNumber(b.tai.chainDb, hash)
	if number == nil {
		return nil, nil
	}
	receipts := rawdb.ReadReceipts(b.tai.chainDb, hash, *number)
	if receipts == nil {
		return nil, nil
	}
	logs := make([][]*types.Log, len(receipts))
	for i, receipt := range receipts {
		logs[i] = receipt.Logs
	}
	return logs, nil
}

func (b *TrueAPIBackend) GetTd(blockHash common.Hash) *big.Int {
	//return b.tai.snailblockchain.GetTdByHash(blockHash)
	return nil
}

func (b *TrueAPIBackend) GetEVM(ctx context.Context, msg core.Message, state *state.StateDB, header *types.Header, vmCfg vm.Config) (*vm.EVM, func() error, error) {
	state.SetBalance(msg.From(), math.MaxBig256)
	vmError := func() error { return nil }

	context := core.NewEVMContext(msg, header, b.tai.BlockChain(), nil, nil)
	return vm.NewEVM(context, state, b.tai.chainConfig, vmCfg), vmError, nil
}

func (b *TrueAPIBackend) SubscribeRemovedLogsEvent(ch chan<- types.RemovedLogsEvent) event.Subscription {
	return b.tai.BlockChain().SubscribeRemovedLogsEvent(ch)
}

func (b *TrueAPIBackend) SubscribeChainEvent(ch chan<- types.FastChainEvent) event.Subscription {
	return b.tai.BlockChain().SubscribeChainEvent(ch)
}

func (b *TrueAPIBackend) SubscribeChainHeadEvent(ch chan<- types.FastChainHeadEvent) event.Subscription {
	return b.tai.BlockChain().SubscribeChainHeadEvent(ch)
}

func (b *TrueAPIBackend) SubscribeChainSideEvent(ch chan<- types.FastChainSideEvent) event.Subscription {
	return b.tai.BlockChain().SubscribeChainSideEvent(ch)
}

func (b *TrueAPIBackend) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return b.tai.BlockChain().SubscribeLogsEvent(ch)
}

func (b *TrueAPIBackend) GetReward(number int64) *types.BlockReward {
	if number < 0 {
		return b.tai.blockchain.CurrentReward()
	}
	return b.tai.blockchain.GetBlockReward(uint64(number))
}

/*func (b *TrueAPIBackend) GetSnailRewardContent(snailNumber rpc.BlockNumber) *types.SnailRewardContenet {
	return b.tai.agent.GetSnailRewardContent(uint64(snailNumber))
}*/

func (b *TrueAPIBackend) GetCommittee(number rpc.BlockNumber) (map[string]interface{}, error) {
	return b.tai.election.GetCommitteeById(big.NewInt(number.Int64())), nil
}

func (b *TrueAPIBackend) SendTx(ctx context.Context, signedTx *types.Transaction) error {
	return b.tai.txPool.AddLocal(signedTx)
}

func (b *TrueAPIBackend) GetPoolTransactions() (types.Transactions, error) {
	pending, err := b.tai.txPool.Pending()
	if err != nil {
		return nil, err
	}
	var txs types.Transactions
	for _, batch := range pending {
		txs = append(txs, batch...)
	}
	return txs, nil
}

func (b *TrueAPIBackend) GetPoolTransaction(hash common.Hash) *types.Transaction {
	return b.tai.txPool.Get(hash)
}

func (b *TrueAPIBackend) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
	return b.tai.txPool.State().GetNonce(addr), nil
}

func (b *TrueAPIBackend) Stats() (pending int, queued int) {
	return b.tai.txPool.Stats()
}

func (b *TrueAPIBackend) IsNoGasUsageModel() bool {
	return b.tai.txPool.IsNoGasUsageModel()
}

func (b *TrueAPIBackend) TxPoolContent() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	return b.tai.TxPool().Content()
}

func (b *TrueAPIBackend) SubscribeNewTxsEvent(ch chan<- types.NewTxsEvent) event.Subscription {
	return b.tai.TxPool().SubscribeNewTxsEvent(ch)
}

func (b *TrueAPIBackend) Downloader() *downloader.Downloader {
	return b.tai.Downloader()
}

func (b *TrueAPIBackend) ProtocolVersion() int {
	return b.tai.EthVersion()
}

func (b *TrueAPIBackend) SuggestPrice(ctx context.Context) (*big.Int, error) {
	return b.gpo.SuggestPrice(ctx)
}

func (b *TrueAPIBackend) ChainDb() taidb.Database {
	return b.tai.ChainDb()
}

func (b *TrueAPIBackend) EventMux() *event.TypeMux {
	return b.tai.EventMux()
}

func (b *TrueAPIBackend) AccountManager() *accounts.Manager {
	return b.tai.AccountManager()
}

func (b *TrueAPIBackend) BloomStatus() (uint64, uint64) {
	sections, _, _ := b.tai.bloomIndexer.Sections()
	return params.BloomBitsBlocks, sections
}

func (b *TrueAPIBackend) ServiceFilter(ctx context.Context, session *bloombits.MatcherSession) {
	for i := 0; i < bloomFilterThreads; i++ {
		go session.Multiplex(bloomRetrievalBatch, bloomRetrievalWait, b.tai.bloomRequests)
	}
}
