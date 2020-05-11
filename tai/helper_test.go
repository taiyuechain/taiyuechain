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

// This file contains some shares testing functionality, common to  multiple
// different files and modules being tested.

package tai

import (
	"crypto/ecdsa"
	"crypto/rand"
	ethash "github.com/taiyuechain/taiyuechain/consensus/minerva"
	"github.com/taiyuechain/taiyuechain/core/forkid"

	"github.com/taiyuechain/taiyuechain/p2p/enode"
	"math/big"
	"sort"
	"sync"
	"testing"

	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/core"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/core/vm"
	"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/tai/downloader"
	"github.com/taiyuechain/taiyuechain/taidb"
	"github.com/taiyuechain/taiyuechain/event"
	"github.com/taiyuechain/taiyuechain/p2p"
	"github.com/taiyuechain/taiyuechain/params"
)

var (
	testBankKey, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	testBank       = crypto.PubkeyToAddress(testBankKey.PublicKey)
	engine         = ethash.NewFaker()
)

// newTestProtocolManager creates a new protocol manager for testing purposes,
// with the given number of blocks already known, and potential notification
// channels for different events.
func newTestProtocolManager(mode downloader.SyncMode, blocks int, sBlocks int, generator func(int, *core.BlockGen)) (*ProtocolManager, *taidb.MemDatabase, error) {
	var (
		evmux = new(event.TypeMux)
		db    = taidb.NewMemDatabase()
		gspec = &core.Genesis{
			Config:     params.TestChainConfig,
			Alloc:      types.GenesisAlloc{testBank: {Balance: big.NewInt(1000000000)}},
			Difficulty: big.NewInt(20000),
		}
		genesis       = gspec.MustFastCommit(db)
		blockchain, _ = core.NewBlockChain(db, nil, gspec.Config, engine, vm.Config{})

		priKey, _     = crypto.GenerateKey()
		coinbase      = crypto.PubkeyToAddress(priKey.PublicKey) //coinbase
		committeeNode = &types.CommitteeNode{
			IP:        "127.0.0.1",
			Port:      8080,
			Port2:     8090,
			Coinbase:  coinbase,
			Publickey: crypto.FromECDSAPub(&priKey.PublicKey),
		}
		pbftAgent = &PbftAgent{
			privateKey:    priKey,
			committeeNode: committeeNode,
		}
	)
	params.MinimumFruits = 60
	params.MinTimeGap = big.NewInt(0)
	chain, _ := core.GenerateChain(gspec.Config, genesis, engine, db, blocks, generator)
	if _, err := blockchain.InsertChain(chain); err != nil {
		panic(err)
	}

	//snailPool	etrue.snailblockchain
	pm, err := NewProtocolManager(gspec.Config, nil, mode, DefaultConfig.NetworkId, evmux, new(testTxPool), engine, blockchain, db, pbftAgent, 1, nil, nil)
	if err != nil {
		return nil, nil, err
	}
	pm.Start(1000)
	return pm, db, nil
}

// newTestProtocolManagerMust creates a new protocol manager for testing purposes,
// with the given number of blocks already known, and potential notification
// channels for different events. In case of an error, the constructor force-
// fails the test.
func newTestProtocolManagerMust(t *testing.T, mode downloader.SyncMode, blocks int, sBlocks int, generator func(int, *core.BlockGen), newtx chan<- []*types.Transaction) (*ProtocolManager, *taidb.MemDatabase) {
	pm, db, err := newTestProtocolManager(mode, blocks, sBlocks, generator)
	if err != nil {
		t.Fatalf("Failed to create protocol manager: %v", err)
	}
	return pm, db
}

// testTxPool is a fake, helper transaction pool for testing purposes
type testTxPool struct {
	txFeed event.Feed
	pool   []*types.Transaction        // Collection of all transactions
	added  chan<- []*types.Transaction // Notification channel for new transactions

	lock sync.RWMutex // Protects the transaction pool
}

func (p *testTxPool) Has(hash common.Hash) bool {
	panic("implement me")
}

func (p *testTxPool) Get(hash common.Hash) *types.Transaction {
	panic("implement me")
}

// AddRemotes appends a batch of transactions to the pool, and notifies any
// listeners if the addition channel is non nil
func (p *testTxPool) AddRemotes(txs []*types.Transaction) []error {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.pool = append(p.pool, txs...)
	//go p.txFeed.Send(types.NewTxsEvent{txs})
	if p.added != nil {
		p.added <- txs
	}
	return make([]error, len(txs))
}

// Pending returns all the transactions known to the pool
func (p *testTxPool) Pending() (map[common.Address]types.Transactions, error) {
	p.lock.RLock()
	defer p.lock.RUnlock()

	batches := make(map[common.Address]types.Transactions)
	for _, tx := range p.pool {
		from, _ := types.Sender(types.NewCommonSigner(new(big.Int).Set(common.Big1)), tx)
		batches[from] = append(batches[from], tx)
	}
	for _, batch := range batches {
		sort.Sort(types.TxByNonce(batch))
	}
	return batches, nil
}

func (p *testTxPool) SubscribeNewTxsEvent(ch chan<- types.NewTxsEvent) event.Subscription {
	return p.txFeed.Subscribe(ch)
}

// testSnailPool is a fake, helper fruit pool for testing purposes
type testSnailPool struct {
	fruitFeed event.Feed
	pool      []*types.SnailBlock        // Collection of all fruits
	added     chan<- []*types.SnailBlock // Notification channel for new fruits

	lock sync.RWMutex // Protects the transaction pool
}

// AddRemoteFruits appends a batch of fruits to the pool, and notifies any
// listeners if the addition channel is non nil
func (p *testSnailPool) AddRemoteFruits(fts []*types.SnailBlock, local bool) []error {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.pool = append(p.pool, fts...)
	if p.added != nil {
		p.added <- fts
	}
	return make([]error, len(fts))
}

// PendingFruits returns all the fruits known to the pool
func (p *testSnailPool) PendingFruits() map[common.Hash]*types.SnailBlock {
	p.lock.RLock()
	defer p.lock.RUnlock()

	rtfruits := make(map[common.Hash]*types.SnailBlock)

	for _, fruit := range p.pool {
		rtfruits[fruit.FastHash()] = types.CopyFruit(fruit)
	}

	return rtfruits
}

func (p *testSnailPool) SubscribeNewFruitEvent(ch chan<- types.NewFruitsEvent) event.Subscription {
	return p.fruitFeed.Subscribe(ch)
}

func (p *testSnailPool) RemovePendingFruitByFastHash(fasthash common.Hash) {
}

// testAgentNetwork is a fake, helper agent for testing purposes
type testAgentNetwork struct {
	agentFeed event.Feed
	nodeFeed  event.Feed
	en        *types.EncryptNodeMessage        // Collection of all fruits
	added     chan<- *types.EncryptNodeMessage // Notification channel for new fruits

	lock sync.RWMutex // Protects the transaction pool
}

func (p *testAgentNetwork) SubscribeNewPbftSignEvent(ch chan<- types.PbftSignEvent) event.Subscription {
	return p.agentFeed.Subscribe(ch)
}

// SubscribeNodeInfoEvent should return an event subscription of
// NodeInfoEvent and send events to the given channel.
func (p *testAgentNetwork) SubscribeNodeInfoEvent(ch chan<- types.NodeInfoEvent) event.Subscription {
	return p.nodeFeed.Subscribe(ch)
}

// AddRemoteNodeInfo should add the given NodeInfo to the pbft agent.
func (p *testAgentNetwork) AddRemoteNodeInfo(en *types.EncryptNodeMessage) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	if p.added != nil {
		p.added <- en
	}
	return nil
}

// newTestTransaction create a new dummy transaction.
func newTestTransaction(from *ecdsa.PrivateKey, nonce uint64, datasize int) *types.Transaction {
	tx := types.NewTransaction(nonce, common.Address{}, big.NewInt(0), 100000, big.NewInt(0), make([]byte, datasize), nil)
	tx, _ = types.SignTx(tx, types.NewCommonSigner(new(big.Int).Set(common.Big1)), from)
	return tx
}

// testPeer is a simulated peer to allow testing direct network calls.
type testPeer struct {
	net p2p.MsgReadWriter // Network layer reader/writer to simulate remote messaging
	app *p2p.MsgPipeRW    // Application layer reader/writer to simulate the local side
	*peer
}

// newTestPeer creates a new peer registered at the given protocol manager.
func newTestPeer(name string, version int, pm *ProtocolManager, shake bool) (*testPeer, <-chan error) {
	// Create a message pipe to communicate through
	app, net := p2p.MsgPipe()

	// Generate a random id and create the peer
	var id enode.ID
	rand.Read(id[:])

	peer := pm.newPeer(version, p2p.NewPeer(id, name, nil), net, pm.txpool.Get)

	// Start the peer on a new thread
	errc := make(chan error, 1)
	go func() {
		select {
		case pm.newPeerCh <- peer:
			errc <- pm.handle(peer)
		case <-pm.quitSync:
			errc <- p2p.DiscQuitting
		}
	}()
	tp := &testPeer{app: app, net: net, peer: peer}
	// Execute any implicitly requested handshakes and return
	if shake {
		var (
			genesis  = pm.blockchain.Genesis()
			fastHead = pm.blockchain.CurrentHeader()
			fastHash = fastHead.Hash()
		)
		tp.handshake(nil, big.NewInt(0), fastHash, genesis.Hash(), pm.blockchain)
	}
	return tp, errc
}

// handshake simulates a trivial handshake that expects the same state from the
// remote side as we are simulating locally.
func (p *testPeer) handshake(t *testing.T, td *big.Int, head common.Hash, genesis common.Hash, chain *core.BlockChain) {
	msg := &statusData{
		ProtocolVersion: uint32(p.version),
		NetworkID:       DefaultConfig.NetworkId,
		TD:              td,
		Head:            head,
		Genesis:         genesis,
		ForkID:          forkid.NewID(chain),
	}
	if err := p2p.ExpectMsg(p.app, StatusMsg, msg); err != nil {
		t.Fatalf("status recv: %v", err)
	}
	if err := p2p.Send(p.app, StatusMsg, msg); err != nil {
		t.Fatalf("status send: %v", err)
	}
}

// close terminates the local side of the peer, notifying the remote protocol
// manager of termination.
func (p *testPeer) close() {
	p.app.Close()
}
