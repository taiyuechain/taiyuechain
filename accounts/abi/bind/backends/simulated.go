package backends

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	taiyue "github.com/taiyuechain/taiyuechain"
	"github.com/taiyuechain/taiyuechain/cim"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/common/math"
	"github.com/taiyuechain/taiyuechain/consensus"
	"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/taidb"
	"io/ioutil"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/taiyuechain/taiyuechain/accounts/abi/bind"
	ethash "github.com/taiyuechain/taiyuechain/consensus/minerva"
	"github.com/taiyuechain/taiyuechain/core"
	"github.com/taiyuechain/taiyuechain/core/bloombits"
	"github.com/taiyuechain/taiyuechain/core/rawdb"
	"github.com/taiyuechain/taiyuechain/core/state"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/core/vm"
	"github.com/taiyuechain/taiyuechain/event"
	"github.com/taiyuechain/taiyuechain/params"
	"github.com/taiyuechain/taiyuechain/rpc"
	"github.com/taiyuechain/taiyuechain/tai/filters"
)

// This nil assignment ensures compile time that SimulatedBackend implements bind.ContractBackend.
var _ bind.ContractBackend = (*SimulatedBackend)(nil)

var errGasEstimationFailed = errors.New("gas required exceeds allowance or always failing transaction")

var (
	errBlockNumberUnsupported  = errors.New("simulatedBackend cannot access blocks other than the latest block")
	errBlockDoesNotExist       = errors.New("block does not exist in blockchain")
	errTransactionDoesNotExist = errors.New("transaction does not exist")
)

// SimulatedBackend implements bind.ContractBackend, simulating a blockchain in
// the background. Its main purpose is to allow easily testing contract bindings.
// Simulated backend implements the following interfaces:
// ChainReader, ChainStateReader, ContractBackend, ContractCaller, ContractFilterer, ContractTransactor,
// DeployBackend, GasEstimator, GasPricer, LogFilterer, PendingContractCaller, TransactionReader, and TransactionSender
type SimulatedBackend struct {
	database   taidb.Database   // In memory database to store our testing data
	blockchain *core.BlockChain // Ethereum blockchain to handle the consensus

	mu           sync.Mutex
	pendingBlock *types.Block   // Currently pending block that will be imported on request
	pendingState *state.StateDB // Currently pending state that will be the active on on request

	events *filters.EventSystem // Event system for filtering log events live

	config *params.ChainConfig
	engine consensus.Engine
}

// NewSimulatedBackendWithDatabase creates a new binding backend based on the given database
// and uses a simulated blockchain for testing purposes.
func NewSimulatedBackendWithDatabase(database taidb.Database, alloc *core.Genesis, gasLimit uint64) *SimulatedBackend {
	genesis := alloc
	genesis.MustCommit(database)
	cimList := cim.NewCIMList(uint8(crypto.CryptoType))
	engine := ethash.NewFaker()

	blockchain, _ := core.NewBlockChain(database, nil, genesis.Config, engine, vm.Config{}, cimList)

	//init cert list to
	// need init cert list to statedb
	stateDB, err := blockchain.State()
	if err != nil {
		panic(err)
	}
	caCertList := vm.NewCACertList()
	err = caCertList.LoadCACertList(stateDB, types.CACertListAddress)
	epoch := blockchain.GetBlockNumber()
	for _, caCert := range caCertList.GetCACertMapByEpoch(epoch).CACert {
		cimCa, err := cim.NewCIM()
		if err != nil {
			panic(err)
		}

		cimCa.SetUpFromCA(caCert)
		cimList.AddCim(cimCa)
	}

	backend := &SimulatedBackend{
		database:   database,
		blockchain: blockchain,
		config:     genesis.Config,
		events:     filters.NewEventSystem(new(event.TypeMux), &filterBackend{database, blockchain}, false),
		engine:     engine,
	}
	backend.rollback()
	return backend
}

// NewSimulatedBackend creates a new binding backend using a simulated blockchain
// for testing purposes.
func NewSimulatedBackend(alloc *core.Genesis, gasLimit uint64) *SimulatedBackend {
	return NewSimulatedBackendWithDatabase(taidb.NewMemDatabase(), alloc, gasLimit)
}

// Close terminates the underlying blockchain's update loop.
func (b *SimulatedBackend) Close() error {
	b.blockchain.Stop()
	return nil
}

// Commit imports all the pending transactions as a single block and starts a
// fresh new state.
func (b *SimulatedBackend) Commit() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, err := b.blockchain.InsertChain([]*types.Block{b.pendingBlock}); err != nil {
		panic(err) // This cannot happen unless the simulator is wrong, fail in that case
	}
	b.rollback()
}

// Rollback aborts all pending transactions, reverting to the last committed state.
func (b *SimulatedBackend) Rollback() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.rollback()
}

func (b *SimulatedBackend) rollback() {
	blocks, _ := core.GenerateChain(b.config, b.blockchain.CurrentBlock(), b.engine, b.database, 1, func(int, *core.BlockGen) {})
	statedb, _ := b.blockchain.State()

	b.pendingBlock = blocks[0]
	b.pendingState, _ = state.New(b.pendingBlock.Root(), statedb.Database())
}

// stateByBlockNumber retrieves a state by a given blocknumber.
func (b *SimulatedBackend) stateByBlockNumber(ctx context.Context, blockNumber *big.Int) (*state.StateDB, error) {
	if blockNumber == nil || blockNumber.Cmp(b.blockchain.CurrentBlock().Number()) == 0 {
		return b.blockchain.State()
	}
	block, err := b.BlockByNumber(ctx, blockNumber)
	if err != nil {
		return nil, err
	}
	return b.blockchain.StateAt(block.Hash())
}

// CodeAt returns the code associated with a certain account in the blockchain.
func (b *SimulatedBackend) CodeAt(ctx context.Context, contract common.Address, blockNumber *big.Int) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	statedb, err := b.stateByBlockNumber(ctx, blockNumber)
	if err != nil {
		return nil, err
	}

	return statedb.GetCode(contract), nil
}

// BalanceAt returns the wei balance of a certain account in the blockchain.
func (b *SimulatedBackend) BalanceAt(ctx context.Context, contract common.Address, blockNumber *big.Int) (*big.Int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	statedb, err := b.stateByBlockNumber(ctx, blockNumber)
	if err != nil {
		return nil, err
	}

	return statedb.GetBalance(contract), nil
}

// NonceAt returns the nonce of a certain account in the blockchain.
func (b *SimulatedBackend) NonceAt(ctx context.Context, contract common.Address, blockNumber *big.Int) (uint64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	statedb, err := b.stateByBlockNumber(ctx, blockNumber)
	if err != nil {
		return 0, err
	}

	return statedb.GetNonce(contract), nil
}

// StorageAt returns the value of key in the storage of an account in the blockchain.
func (b *SimulatedBackend) StorageAt(ctx context.Context, contract common.Address, key common.Hash, blockNumber *big.Int) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	statedb, err := b.stateByBlockNumber(ctx, blockNumber)
	if err != nil {
		return nil, err
	}

	val := statedb.GetState(contract, key)
	return val[:], nil
}

// TransactionReceipt returns the receipt of a transaction.
func (b *SimulatedBackend) TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	receipt, _, _, _ := rawdb.ReadReceipt(b.database, txHash)
	return receipt, nil
}

// TransactionByHash checks the pool of pending transactions in addition to the
// blockchain. The isPending return value indicates whether the transaction has been
// mined yet. Note that the transaction may not be part of the canonical chain even if
// it's not pending.
func (b *SimulatedBackend) TransactionByHash(ctx context.Context, txHash common.Hash) (*types.Transaction, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	tx := b.pendingBlock.Transaction(txHash)
	if tx != nil {
		return tx, true, nil
	}
	tx, _, _, _ = rawdb.ReadTransaction(b.database, txHash)
	if tx != nil {
		return tx, false, nil
	}
	return nil, false, taiyue.NotFound
}

// BlockByHash retrieves a block based on the block hash
func (b *SimulatedBackend) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if hash == b.pendingBlock.Hash() {
		return b.pendingBlock, nil
	}

	block := b.blockchain.GetBlockByHash(hash)
	if block != nil {
		return block, nil
	}

	return nil, errBlockDoesNotExist
}

// BlockByNumber retrieves a block from the database by number, caching it
// (associated with its hash) if found.
func (b *SimulatedBackend) BlockByNumber(ctx context.Context, number *big.Int) (*types.Block, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if number == nil || number.Cmp(b.pendingBlock.Number()) == 0 {
		return b.blockchain.CurrentBlock(), nil
	}

	block := b.blockchain.GetBlockByNumber(uint64(number.Int64()))
	if block == nil {
		return nil, errBlockDoesNotExist
	}

	return block, nil
}

// HeaderByHash returns a block header from the current canonical chain.
func (b *SimulatedBackend) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if hash == b.pendingBlock.Hash() {
		return b.pendingBlock.Header(), nil
	}

	header := b.blockchain.GetHeaderByHash(hash)
	if header == nil {
		return nil, errBlockDoesNotExist
	}

	return header, nil
}

// HeaderByNumber returns a block header from the current canonical chain. If number is
// nil, the latest known header is returned.
func (b *SimulatedBackend) HeaderByNumber(ctx context.Context, block *big.Int) (*types.Header, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if block == nil || block.Cmp(b.pendingBlock.Number()) == 0 {
		return b.blockchain.CurrentHeader(), nil
	}

	return b.blockchain.GetHeaderByNumber(uint64(block.Int64())), nil
}

// TransactionCount returns the number of transactions in a given block
func (b *SimulatedBackend) TransactionCount(ctx context.Context, blockHash common.Hash) (uint, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if blockHash == b.pendingBlock.Hash() {
		return uint(b.pendingBlock.Transactions().Len()), nil
	}

	block := b.blockchain.GetBlockByHash(blockHash)
	if block == nil {
		return uint(0), errBlockDoesNotExist
	}

	return uint(block.Transactions().Len()), nil
}

// TransactionInBlock returns the transaction for a specific block at a specific index
func (b *SimulatedBackend) TransactionInBlock(ctx context.Context, blockHash common.Hash, index uint) (*types.Transaction, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if blockHash == b.pendingBlock.Hash() {
		transactions := b.pendingBlock.Transactions()
		if uint(len(transactions)) < index+1 {
			return nil, errTransactionDoesNotExist
		}

		return transactions[index], nil
	}

	block := b.blockchain.GetBlockByHash(blockHash)
	if block == nil {
		return nil, errBlockDoesNotExist
	}

	transactions := block.Transactions()
	if uint(len(transactions)) < index+1 {
		return nil, errTransactionDoesNotExist
	}

	return transactions[index], nil
}

// PendingCodeAt returns the code associated with an account in the pending state.
func (b *SimulatedBackend) PendingCodeAt(ctx context.Context, contract common.Address) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.pendingState.GetCode(contract), nil
}

// CallContract executes a contract call.
func (b *SimulatedBackend) CallContract(ctx context.Context, call taiyue.CallMsg, blockNumber *big.Int) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if blockNumber != nil && blockNumber.Cmp(b.blockchain.CurrentBlock().Number()) != 0 {
		return nil, errBlockNumberUnsupported
	}
	state, err := b.blockchain.State()
	if err != nil {
		return nil, err
	}
	rval, _, _, err := b.callContract(ctx, call, b.blockchain.CurrentBlock(), state)
	return rval, err
}

// PendingCallContract executes a contract call on the pending state.
func (b *SimulatedBackend) PendingCallContract(ctx context.Context, call taiyue.CallMsg) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	defer b.pendingState.RevertToSnapshot(b.pendingState.Snapshot())

	rval, _, _, err := b.callContract(ctx, call, b.pendingBlock, b.pendingState)
	return rval, err
}

// PendingNonceAt implements PendingStateReader.PendingNonceAt, retrieving
// the nonce currently pending for the account.
func (b *SimulatedBackend) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.pendingState.GetOrNewStateObject(account).Nonce(), nil
}

// SuggestGasPrice implements ContractTransactor.SuggestGasPrice. Since the simulated
// chain doesn't have miners, we just return a gas price of 1 for any call.
func (b *SimulatedBackend) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	return big.NewInt(1), nil
}

// EstimateGas executes the requested code against the currently pending block/state and
// returns the used amount of gas.
func (b *SimulatedBackend) EstimateGas(ctx context.Context, call taiyue.CallMsg) (uint64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Determine the lowest and highest possible gas limits to binary search in between
	var (
		lo  uint64 = params.TxGas - 1
		hi  uint64
		cap uint64
	)
	if call.Gas >= params.TxGas {
		hi = call.Gas
	} else {
		hi = b.pendingBlock.GasLimit()
	}
	cap = hi

	// Create a helper to check if a gas allowance results in an executable transaction
	executable := func(gas uint64) bool {
		call.Gas = gas

		snapshot := b.pendingState.Snapshot()
		_, _, failed, err := b.callContract(ctx, call, b.pendingBlock, b.pendingState)
		b.pendingState.RevertToSnapshot(snapshot)

		if err != nil || failed {
			return false
		}
		return true
	}
	// Execute the binary search and hone in on an executable gas limit
	for lo+1 < hi {
		mid := (hi + lo) / 2
		if !executable(mid) {
			lo = mid
		} else {
			hi = mid
		}
	}
	// Reject the transaction as invalid if it still fails at the highest allowance
	// Reject the transaction as invalid if it still fails at the highest allowance
	if hi == cap {
		if !executable(hi) {
			return 0, errGasEstimationFailed
		}
	}
	return hi, nil
}

// callContract implements common code between normal and pending contract calls.
// state is modified during execution, make sure to copy it if necessary.
func (b *SimulatedBackend) callContract(ctx context.Context, call taiyue.CallMsg, block *types.Block, statedb *state.StateDB) ([]byte, uint64, bool, error) {
	// Ensure message is initialized properly.
	if call.GasPrice == nil {
		call.GasPrice = big.NewInt(1)
	}
	if call.Gas == 0 {
		call.Gas = 50000000
	}
	if call.Value == nil {
		call.Value = new(big.Int)
	}
	// Set infinite balance to the fake caller account.
	from := statedb.GetOrNewStateObject(call.From)
	fmt.Println("callContract", crypto.AddressToHex(from.Address()), " from ", crypto.AddressToHex(call.From))
	from.SetBalance(math.MaxBig256)
	// Execute the call.
	msg := callmsg{call}

	evmContext := core.NewEVMContext(msg, block.Header(), b.blockchain, nil, nil)
	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	debug := false
	var (
		vmConf    vm.Config
		dump      *os.File
		writer    *bufio.Writer
		logConfig vm.LogConfig
	)

	logConfig.Debug = debug
	// Generate a unique temporary file to dump it into
	if debug {
		prefix := fmt.Sprintf("block_%d-%d-%#x-", block.NumberU64(), 0, call.From.Hash().Bytes()[:4])
		dump, _ = ioutil.TempFile(os.TempDir(), prefix)
		// Swap out the noop logger to the standard tracer
		writer = bufio.NewWriter(dump)
		vmConf = vm.Config{
			Debug:                   true,
			Tracer:                  vm.NewJSONLogger(&logConfig, writer),
			EnablePreimageRecording: true,
		}
	}
	vmenv := vm.NewEVM(evmContext, statedb, b.config, vmConf)

	gaspool := new(core.GasPool).AddGas(math.MaxUint64)
	v1, v2, v3, v4 := core.NewStateTransition(vmenv, msg, gaspool).TransitionDb()

	if debug {
		if writer != nil {
			writer.Flush()
		}
		if dump != nil {
			dump.Close()
			fmt.Println("Wrote SimulatedBackend standard trace", "file", dump.Name())
		}
	}

	return v1, v2, v3, v4
}

// SendTransaction updates the pending block to include the given transaction.
// It panics if the transaction is invalid.
func (b *SimulatedBackend) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	sender, err := types.Sender(types.NewSigner(tx.ChainId()), tx)
	if err != nil {
		panic(fmt.Errorf("invalid transaction: %v", err))
	}
	nonce := b.pendingState.GetNonce(sender)
	if tx.Nonce() != nonce {
		panic(fmt.Errorf("invalid transaction nonce: got %d, want %d", tx.Nonce(), nonce))
	}

	blocks, _ := core.GenerateChain(b.config, b.blockchain.CurrentBlock(), b.engine, b.database, 1, func(number int, block *core.BlockGen) {
		for _, tx := range b.pendingBlock.Transactions() {
			block.AddTxWithChain(b.blockchain, tx)
		}
		block.AddTxWithChain(b.blockchain, tx)
	})
	statedb, _ := b.blockchain.State()

	b.pendingBlock = blocks[0]
	b.pendingState, _ = state.New(b.pendingBlock.Root(), statedb.Database())
	return nil
}

// FilterLogs executes a log filter operation, blocking during execution and
// returning all the results in one batch.
//
// TODO(karalabe): Deprecate when the subscription one can return past data too.
func (b *SimulatedBackend) FilterLogs(ctx context.Context, query taiyue.FilterQuery) ([]types.Log, error) {
	var filter *filters.Filter
	if query.BlockHash != nil {
		// Block filter requested, construct a single-shot filter
		filter = filters.NewBlockFilter(&filterBackend{b.database, b.blockchain}, *query.BlockHash, query.Addresses, query.Topics)
	} else {
		// Initialize unset filter boundaried to run from genesis to chain head
		from := int64(0)
		if query.FromBlock != nil {
			from = query.FromBlock.Int64()
		}
		to := int64(-1)
		if query.ToBlock != nil {
			to = query.ToBlock.Int64()
		}
		// Construct the range filter
		filter = filters.NewRangeFilter(&filterBackend{b.database, b.blockchain}, from, to, query.Addresses, query.Topics)
	}
	// Run the filter and return all the logs
	logs, err := filter.Logs(ctx)
	if err != nil {
		return nil, err
	}
	res := make([]types.Log, len(logs))
	for i, log := range logs {
		res[i] = *log
	}
	return res, nil
}

// SubscribeFilterLogs creates a background log filtering operation, returning a
// subscription immediately, which can be used to stream the found events.
func (b *SimulatedBackend) SubscribeFilterLogs(ctx context.Context, query taiyue.FilterQuery, ch chan<- types.Log) (taiyue.Subscription, error) {
	// Subscribe to contract events
	sink := make(chan []*types.Log)

	sub, err := b.events.SubscribeLogs(query, sink)
	if err != nil {
		return nil, err
	}
	// Since we're getting logs in batches, we need to flatten them into a plain stream
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case logs := <-sink:
				for _, log := range logs {
					select {
					case ch <- *log:
					case err := <-sub.Err():
						return err
					case <-quit:
						return nil
					}
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// SubscribeNewHead returns an event subscription for a new header
func (b *SimulatedBackend) SubscribeNewHead(ctx context.Context, ch chan<- *types.Header) (taiyue.Subscription, error) {
	// subscribe to a new head
	sink := make(chan *types.Header)
	sub := b.events.SubscribeNewHeads(sink)

	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case head := <-sink:
				select {
				case ch <- head:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// AdjustTime adds a time shift to the simulated clock.
func (b *SimulatedBackend) AdjustTime(adjustment time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	blocks, _ := core.GenerateChain(b.config, b.blockchain.CurrentBlock(), b.engine, b.database, 1, func(number int, block *core.BlockGen) {
		for _, tx := range b.pendingBlock.Transactions() {
			block.AddTx(tx)
		}
		block.OffsetTime(int64(adjustment.Seconds()))
	})
	statedb, _ := b.blockchain.State()

	b.pendingBlock = blocks[0]
	b.pendingState, _ = state.New(b.pendingBlock.Root(), statedb.Database())

	return nil
}

// Blockchain returns the underlying blockchain.
func (b *SimulatedBackend) Blockchain() *core.BlockChain {
	return b.blockchain
}

// callmsg implements core.Message to allow passing it as a transaction simulator.
type callmsg struct {
	taiyue.CallMsg
}

func (m callmsg) From() common.Address    { return m.CallMsg.From }
func (m callmsg) Payment() common.Address { return m.CallMsg.Payment }
func (m callmsg) Nonce() uint64           { return 0 }
func (m callmsg) CheckNonce() bool        { return false }
func (m callmsg) To() *common.Address     { return m.CallMsg.To }
func (m callmsg) GasPrice() *big.Int      { return m.CallMsg.GasPrice }
func (m callmsg) Gas() uint64             { return m.CallMsg.Gas }
func (m callmsg) Value() *big.Int         { return m.CallMsg.Value }
func (m callmsg) Data() []byte            { return m.CallMsg.Data }
func (m callmsg) Fee() *big.Int           { return m.CallMsg.Fee }

// filterBackend implements filters.Backend to support filtering for logs without
// taking bloom-bits acceleration structures into account.
type filterBackend struct {
	db taidb.Database
	bc *core.BlockChain
}

func (fb *filterBackend) ChainDb() taidb.Database  { return fb.db }
func (fb *filterBackend) EventMux() *event.TypeMux { panic("not supported") }

func (fb *filterBackend) HeaderByNumber(ctx context.Context, block rpc.BlockNumber) (*types.Header, error) {
	if block == rpc.LatestBlockNumber {
		return fb.bc.CurrentHeader(), nil
	}
	return fb.bc.GetHeaderByNumber(uint64(block.Int64())), nil
}

func (fb *filterBackend) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	return fb.bc.GetHeaderByHash(hash), nil
}

func (fb *filterBackend) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	number := rawdb.ReadHeaderNumber(fb.db, hash)
	if number == nil {
		return nil, nil
	}
	return rawdb.ReadReceipts(fb.db, hash, *number), nil
}

func (fb *filterBackend) GetLogs(ctx context.Context, hash common.Hash) ([][]*types.Log, error) {
	number := rawdb.ReadHeaderNumber(fb.db, hash)
	if number == nil {
		return nil, nil
	}
	receipts := rawdb.ReadReceipts(fb.db, hash, *number)
	if receipts == nil {
		return nil, nil
	}
	logs := make([][]*types.Log, len(receipts))
	for i, receipt := range receipts {
		logs[i] = receipt.Logs
	}
	return logs, nil
}

func (fb *filterBackend) SubscribeNewTxsEvent(ch chan<- types.NewTxsEvent) event.Subscription {
	return nullSubscription()
}

func (fb *filterBackend) SubscribeChainEvent(ch chan<- types.FastChainEvent) event.Subscription {
	return fb.bc.SubscribeChainEvent(ch)
}

func (fb *filterBackend) SubscribeRemovedLogsEvent(ch chan<- types.RemovedLogsEvent) event.Subscription {
	return fb.bc.SubscribeRemovedLogsEvent(ch)
}

func (fb *filterBackend) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return fb.bc.SubscribeLogsEvent(ch)
}

func (fb *filterBackend) SubscribePendingLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return nullSubscription()
}

func (fb *filterBackend) BloomStatus() (uint64, uint64) { return 4096, 0 }

func (fb *filterBackend) ServiceFilter(ctx context.Context, ms *bloombits.MatcherSession) {
	panic("not supported")
}

func nullSubscription() event.Subscription {
	return event.NewSubscription(func(quit <-chan struct{}) error {
		<-quit
		return nil
	})
}
