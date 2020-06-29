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

package yue

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
	"github.com/taiyuechain/taiyuechain/yue/downloader"
	"github.com/taiyuechain/taiyuechain/yue/gasprice"
	"github.com/taiyuechain/taiyuechain/yuedb"
)

// TRUEAPIBackend implements ethapi.Backend for full nodes
type TrueAPIBackend struct {
	yue *Taiyuechain
	gpo *gasprice.Oracle
}

// ChainConfig returns the active chain configuration.
func (b *TrueAPIBackend) ChainConfig() *params.ChainConfig {
	return b.yue.chainConfig
}

func (b *TrueAPIBackend) CurrentBlock() *types.Block {
	return b.yue.blockchain.CurrentBlock()
}

func (b *TrueAPIBackend) SetHead(number uint64) {
	b.yue.protocolManager.downloader.Cancel()
	b.yue.blockchain.SetHead(number)
}

func (b *TrueAPIBackend) SetSnailHead(number uint64) {
	b.yue.protocolManager.downloader.Cancel()
}

func (b *TrueAPIBackend) HeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Header, error) {
	// Pending block is only known by the miner
	/*if blockNr == rpc.PendingBlockNumber {
		block := b.yue.miner.PendingBlock()
		return block.Header(), nil
	}*/
	// Otherwise resolve and return the block
	if blockNr == rpc.LatestBlockNumber {
		return b.yue.blockchain.CurrentBlock().Header(), nil
	}
	return b.yue.blockchain.GetHeaderByNumber(uint64(blockNr)), nil
}
func (b *TrueAPIBackend) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	return b.yue.blockchain.GetHeaderByHash(hash), nil
}
func (b *TrueAPIBackend) GetChainBaseParams() []byte {	
	return b.yue.blockchain.GetChainBaseParams()
}
func (b *TrueAPIBackend) BlockByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Block, error) {
	// Only snailchain has miner, also return current block here for fastchain
	if blockNr == rpc.PendingBlockNumber {
		block := b.yue.blockchain.CurrentBlock()
		return block, nil
	}
	// Otherwise resolve and return the block
	if blockNr == rpc.LatestBlockNumber {
		return b.yue.blockchain.CurrentBlock(), nil
	}
	return b.yue.blockchain.GetBlockByNumber(uint64(blockNr)), nil
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
		state, _ := b.yue.blockchain.State()
		block := b.yue.blockchain.CurrentBlock()
		return state, block.Header(), nil
	}
	// Otherwise resolve the block number and return its state
	header, err := b.HeaderByNumber(ctx, blockNr)
	if header == nil || err != nil {
		return nil, nil, err
	}
	stateDb, err := b.yue.BlockChain().StateAt(header.Root)
	return stateDb, header, err
}

func (b *TrueAPIBackend) GetBlock(ctx context.Context, hash common.Hash) (*types.Block, error) {
	return b.yue.blockchain.GetBlockByHash(hash), nil
}

func (b *TrueAPIBackend) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	if number := rawdb.ReadHeaderNumber(b.yue.chainDb, hash); number != nil {
		return rawdb.ReadReceipts(b.yue.chainDb, hash, *number), nil
	}
	return nil, nil
}

func (b *TrueAPIBackend) GetLogs(ctx context.Context, hash common.Hash) ([][]*types.Log, error) {
	number := rawdb.ReadHeaderNumber(b.yue.chainDb, hash)
	if number == nil {
		return nil, nil
	}
	receipts := rawdb.ReadReceipts(b.yue.chainDb, hash, *number)
	if receipts == nil {
		return nil, nil
	}
	logs := make([][]*types.Log, len(receipts))
	for i, receipt := range receipts {
		logs[i] = receipt.Logs
	}
	return logs, nil
}

func (b *TrueAPIBackend) GetEVM(ctx context.Context, msg core.Message, state *state.StateDB, header *types.Header, vmCfg vm.Config) (*vm.EVM, func() error, error) {
	state.SetBalance(msg.From(), math.MaxBig256)
	vmError := func() error { return nil }

	context := core.NewEVMContext(msg, header, b.yue.BlockChain(), nil, nil)
	return vm.NewEVM(context, state, b.yue.chainConfig, vmCfg), vmError, nil
}

func (b *TrueAPIBackend) SubscribeRemovedLogsEvent(ch chan<- types.RemovedLogsEvent) event.Subscription {
	return b.yue.BlockChain().SubscribeRemovedLogsEvent(ch)
}

func (b *TrueAPIBackend) SubscribeChainEvent(ch chan<- types.FastChainEvent) event.Subscription {
	return b.yue.BlockChain().SubscribeChainEvent(ch)
}

func (b *TrueAPIBackend) SubscribeChainHeadEvent(ch chan<- types.FastChainHeadEvent) event.Subscription {
	return b.yue.BlockChain().SubscribeChainHeadEvent(ch)
}

func (b *TrueAPIBackend) SubscribeChainSideEvent(ch chan<- types.FastChainSideEvent) event.Subscription {
	return b.yue.BlockChain().SubscribeChainSideEvent(ch)
}

func (b *TrueAPIBackend) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return b.yue.BlockChain().SubscribeLogsEvent(ch)
}

func (b *TrueAPIBackend) GetCommittee(number rpc.BlockNumber) (map[string]interface{}, error) {
	return b.yue.election.GetCommitteeById(big.NewInt(number.Int64())), nil
}

func (b *TrueAPIBackend) SendTx(ctx context.Context, signedTx *types.Transaction) error {
	return b.yue.txPool.AddLocal(signedTx)
}

func (b *TrueAPIBackend) GetPoolTransactions() (types.Transactions, error) {
	pending, err := b.yue.txPool.Pending()
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
	return b.yue.txPool.Get(hash)
}

func (b *TrueAPIBackend) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
	return b.yue.txPool.State().GetNonce(addr), nil
}

func (b *TrueAPIBackend) Stats() (pending int, queued int) {
	return b.yue.txPool.Stats()
}

func (b *TrueAPIBackend) IsNoGasUsageModel() bool {
	return b.yue.txPool.IsNoGasUsageModel()
}

func (b *TrueAPIBackend) TxPoolContent() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	return b.yue.TxPool().Content()
}

func (b *TrueAPIBackend) SubscribeNewTxsEvent(ch chan<- types.NewTxsEvent) event.Subscription {
	return b.yue.TxPool().SubscribeNewTxsEvent(ch)
}

func (b *TrueAPIBackend) Downloader() *downloader.Downloader {
	return b.yue.Downloader()
}

func (b *TrueAPIBackend) ProtocolVersion() int {
	return b.yue.EthVersion()
}

func (b *TrueAPIBackend) SuggestPrice(ctx context.Context) (*big.Int, error) {
	return b.gpo.SuggestPrice(ctx)
}

func (b *TrueAPIBackend) ChainDb() yuedb.Database {
	return b.yue.ChainDb()
}

func (b *TrueAPIBackend) EventMux() *event.TypeMux {
	return b.yue.EventMux()
}

func (b *TrueAPIBackend) AccountManager() *accounts.Manager {
	return b.yue.AccountManager()
}

func (b *TrueAPIBackend) BloomStatus() (uint64, uint64) {
	sections, _, _ := b.yue.bloomIndexer.Sections()
	return params.BloomBitsBlocks, sections
}

func (b *TrueAPIBackend) ServiceFilter(ctx context.Context, session *bloombits.MatcherSession) {
	for i := 0; i < bloomFilterThreads; i++ {
		go session.Multiplex(bloomRetrievalBatch, bloomRetrievalWait, b.yue.bloomRequests)
	}
}
