// Copyright 2014 The go-ethereum Authors
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

// Package etrue implements the Truechain protocol.
package etrue

import (
	"errors"
	"fmt"
	"github.com/taiyuechain/taiyuechain/cim"
	"github.com/taiyuechain/taiyuechain/consensus/tbft"
	"github.com/taiyuechain/taiyuechain/crypto/taiCrypto"
	config "github.com/taiyuechain/taiyuechain/params"
	"math/big"
	"runtime"
	"strconv"
	"sync"
	//"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	//"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/taiyuechain/taiyuechain/accounts"
	"github.com/taiyuechain/taiyuechain/consensus"
	elect "github.com/taiyuechain/taiyuechain/consensus/election"
	ethash "github.com/taiyuechain/taiyuechain/consensus/minerva"
	"github.com/taiyuechain/taiyuechain/core"
	"github.com/taiyuechain/taiyuechain/core/bloombits"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/core/vm"
	//"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/etrue/downloader"
	"github.com/taiyuechain/taiyuechain/etrue/filters"
	"github.com/taiyuechain/taiyuechain/etrue/gasprice"
	"github.com/taiyuechain/taiyuechain/etruedb"
	"github.com/taiyuechain/taiyuechain/event"
	"github.com/taiyuechain/taiyuechain/internal/trueapi"
	//"github.com/taiyuechain/taiyuechain/miner"
	"github.com/taiyuechain/taiyuechain/node"
	"github.com/taiyuechain/taiyuechain/p2p"
	"github.com/taiyuechain/taiyuechain/params"
	"github.com/taiyuechain/taiyuechain/rpc"
)

type LesServer interface {
	Start(srvr *p2p.Server)
	Stop()
	Protocols() []p2p.Protocol
	SetBloomBitsIndexer(bbIndexer *core.ChainIndexer)
}

// Truechain implements the Truechain full node service.
type Truechain struct {
	config      *Config
	chainConfig *params.ChainConfig

	// Channel for shutting down the service
	shutdownChan chan bool // Channel for shutting down the Truechain

	// Handlers
	txPool *core.TxPool

	//snailPool *chain.SnailPool

	agent    *PbftAgent
	election *elect.Election

	blockchain      *core.BlockChain
	//snailblockchain *chain.SnailBlockChain
	protocolManager *ProtocolManager
	lesServer       LesServer

	// DB interfaces
	chainDb etruedb.Database // Block chain database

	eventMux       *event.TypeMux
	engine         consensus.Engine
	accountManager *accounts.Manager

	bloomRequests chan chan *bloombits.Retrieval // Channel receiving bloom data retrieval requests
	bloomIndexer  *core.ChainIndexer             // Bloom indexer operating during block imports

	APIBackend *TrueAPIBackend

	//miner     *miner.Miner
	gasPrice  *big.Int
	etherbase common.Address

	networkID     uint64
	netRPCService *trueapi.PublicNetAPI

	pbftServer *tbft.Node

	lock sync.RWMutex // Protects the variadic fields (e.g. gas price and etherbase)
}

func (s *Truechain) AddLesServer(ls LesServer) {
	s.lesServer = ls
	ls.SetBloomBitsIndexer(s.bloomIndexer)
}

// New creates a new Truechain object (including the
// initialisation of the common Truechain object)
func New(ctx *node.ServiceContext, config *Config) (*Truechain, error) {
	if config.SyncMode == downloader.LightSync {
		return nil, errors.New("can't run etrue.Truechain in light sync mode, use les.LightTruechain")
	}
	//if config.SyncMode == downloader.SnapShotSync {
	//	return nil, errors.New("can't run etrue.Truechain in SnapShotSync sync mode, use les.LightTruechain")
	//}

	if !config.SyncMode.IsValid() {
		return nil, fmt.Errorf("invalid sync mode %d", config.SyncMode)
	}
	chainDb, err := CreateDB(ctx, config, "chaindata")
	//chainDb, err := CreateDB(ctx, config, path)
	if err != nil {
		return nil, err
	}

	chainConfig, _, _, genesisErr := core.SetupGenesisBlock(chainDb, config.Genesis)
	if _, ok := genesisErr.(*params.ConfigCompatError); genesisErr != nil && !ok {
		return nil, genesisErr
	}

	log.Info("Initialised chain configuration", "config", chainConfig)

	/*if config.Genesis != nil {
		config.MinerGasFloor = config.Genesis.GasLimit * 9 / 10
		config.MinerGasCeil = config.Genesis.GasLimit * 11 / 10
	}*/

	etrue := &Truechain{
		config:         config,
		chainDb:        chainDb,
		chainConfig:    chainConfig,
		eventMux:       ctx.EventMux,
		accountManager: ctx.AccountManager,
		engine:         CreateConsensusEngine(ctx, &config.MinervaHash, chainConfig, chainDb),
		shutdownChan:   make(chan bool),
		networkID:      config.NetworkId,
		gasPrice:       config.GasPrice,
		etherbase:      config.Etherbase,
		bloomRequests:  make(chan chan *bloombits.Retrieval),
		bloomIndexer:   NewBloomIndexer(chainDb, params.BloomBitsBlocks),
	}

	log.Info("Initialising Truechain protocol", "versions", ProtocolVersions, "network", config.NetworkId)

	/*if !config.SkipBcVersionCheck {
		bcVersion := rawdb.ReadDatabaseVersion(chainDb)
		if bcVersion != core.BlockChainVersion && bcVersion != 0 {
			return nil, fmt.Errorf("Blockchain DB version mismatch (%d / %d). Run getrue upgradedb.\n", bcVersion, core.BlockChainVersion)
		}
		rawdb.WriteDatabaseVersion(chainDb, core.BlockChainVersion)
	}*/
	var (
		vmConfig    = vm.Config{EnablePreimageRecording: config.EnablePreimageRecording}
		cacheConfig = &core.CacheConfig{Deleted: config.DeletedState, Disabled: config.NoPruning, TrieNodeLimit: config.TrieCache, TrieTimeLimit: config.TrieTimeout}
	)

	etrue.blockchain, err = core.NewBlockChain(chainDb, cacheConfig, etrue.chainConfig, etrue.engine, vmConfig)
	if err != nil {
		return nil, err
	}

	/*etrue.snailblockchain, err = chain.NewSnailBlockChain(chainDb, etrue.chainConfig, etrue.engine, etrue.blockchain)
	if err != nil {
		return nil, err
	}*/

	// Rewind the chain in case of an incompatible config upgrade.
	/*if compat, ok := genesisErr.(*params.ConfigCompatError); ok {
		log.Warn("Rewinding chain to upgrade configuration", "err", compat)
		etrue.blockchain.SetHead(compat.RewindTo)
		rawdb.WriteChainConfig(chainDb, genesisHash, chainConfig)
	}*/

	//  rewind snail if case of incompatible config
	/*if compat, ok := genesisErr.(*params.ConfigCompatError); ok {
		log.Warn("Rewinding snail chain to upgrade configuration", "err", compat)
		etrue.snailblockchain.SetHead(compat.RewindTo)
		rawdb.WriteChainConfig(chainDb, genesisHash, chainConfig)
	}*/

	etrue.bloomIndexer.Start(etrue.blockchain)

	//sv := chain.NewBlockValidator(etrue.chainConfig, etrue.blockchain, etrue.snailblockchain, etrue.engine)
	//etrue.snailblockchain.SetValidator(sv)

	if config.TxPool.Journal != "" {
		config.TxPool.Journal = ctx.ResolvePath(config.TxPool.Journal)
	}

	/*if config.SnailPool.Journal != "" {
		config.SnailPool.Journal = ctx.ResolvePath(config.SnailPool.Journal)
	}*/

	etrue.txPool = core.NewTxPool(config.TxPool, etrue.chainConfig, etrue.blockchain)

	//etrue.snailPool = chain.NewSnailPool(config.SnailPool, etrue.blockchain, etrue.snailblockchain, etrue.engine, sv)
	//etrue.snailPool = chain.NewSnailPool(config.SnailPool, etrue.blockchain, etrue.snailblockchain, etrue.engine)

	etrue.election = elect.NewElection(etrue.blockchain, etrue.config)
	stateDB, err := etrue.blockchain.State()
	if err != nil {
		return nil, err
	}
	caCertList := vm.NewCACertList()
	err = caCertList.LoadCACertList(stateDB, types.CACertListAddress)
	for i, caCert := range caCertList.GetCACertMap() {
		cimCa, err := cim.NewCIM()
		if err != nil {
			return nil, err
		}
		cimCa.SetUpFromCA(caCert.GetByte())
		cim.CimMap[string(i)] = cimCa
	}

	//etrue.snailblockchain.Validator().SetElection(etrue.election, etrue.blockchain)

	etrue.engine.SetElection(etrue.election)
	//etrue.engine.SetSnailChainReader(etrue.snailblockchain)
	etrue.election.SetEngine(etrue.engine)

	//coinbase, _ := etrue.Etherbase()

	cacheLimit := cacheConfig.TrieCleanLimit //+ cacheConfig.TrieDirtyLimit
	checkpoint := config.Checkpoint
	//TODO neo
	/*if checkpoint == nil {
		checkpoint = params.TrustedCheckpoints[genesisHash]
	}*/
	etrue.agent = NewPbftAgent(etrue, etrue.chainConfig, etrue.engine, etrue.election, config.MinerGasFloor, config.MinerGasCeil)
	if etrue.protocolManager, err = NewProtocolManager(etrue.chainConfig, checkpoint, config.SyncMode,config.NetworkId,etrue.eventMux, etrue.txPool, etrue.engine, etrue.blockchain, chainDb, etrue.agent, cacheLimit, config.Whitelist); err != nil {
		return nil, err
	}


	//etrue.miner = miner.New(etrue, etrue.chainConfig, etrue.EventMux(), etrue.engine, etrue.election, etrue.Config().MineFruit, etrue.Config().NodeType, etrue.Config().RemoteMine, etrue.Config().Mine)
	//etrue.miner.SetExtra(makeExtraData(config.ExtraData))

	//committeeKey, err := crypto.ToECDSA(etrue.config.CommitteeKey)
	//if err == nil {
	//	etrue.miner.SetElection(etrue.config.EnableElection, crypto.FromECDSAPub(&committeeKey.PublicKey))
	//}

	etrue.APIBackend = &TrueAPIBackend{etrue, nil}
	gpoParams := config.GPO
	if gpoParams.Default == nil {
		gpoParams.Default = config.GasPrice
	}
	etrue.APIBackend.gpo = gasprice.NewOracle(etrue.APIBackend, gpoParams)
	return etrue, nil
}

func makeExtraData(extra []byte) []byte {
	if len(extra) == 0 {
		// create default extradata
		extra, _ = rlp.EncodeToBytes([]interface{}{
			uint(params.VersionMajor<<16 | params.VersionMinor<<8 | params.VersionPatch),
			"getrue",
			runtime.Version(),
			runtime.GOOS,
		})
	}
	if uint64(len(extra)) > params.MaximumExtraDataSize {
		log.Warn("Miner extra data exceed limit", "extra", hexutil.Bytes(extra), "limit", params.MaximumExtraDataSize)
		extra = nil
	}
	return extra
}

// CreateDB creates the chain database.
func CreateDB(ctx *node.ServiceContext, config *Config, name string) (etruedb.Database, error) {
	db, err := ctx.OpenDatabase(name, config.DatabaseCache, config.DatabaseHandles)
	if err != nil {
		return nil, err
	}
	if db, ok := db.(*etruedb.LDBDatabase); ok {
		db.Meter("etrue/db/chaindata/")
	}
	return db, nil
}

// CreateConsensusEngine creates the required type of consensus engine instance for an Truechain service
func CreateConsensusEngine(ctx *node.ServiceContext, config *ethash.Config, chainConfig *params.ChainConfig,
	db etruedb.Database) consensus.Engine {
	// If proof-of-authority is requested, set it up
	// snail chain not need clique
	/*
		if chainConfig.Clique != nil {
			return clique.New(chainConfig.Clique, db)
		}*/
	// Otherwise assume proof-of-work
	switch config.PowMode {
	case ethash.ModeFake:
		log.Info("-----Fake mode")
		log.Warn("Ethash used in fake mode")
		return ethash.NewFaker()
	case ethash.ModeTest:
		log.Warn("Ethash used in test mode")
		return ethash.NewTester()
	case ethash.ModeShared:
		log.Warn("Ethash used in shared mode")
		return ethash.NewShared()
	default:
		engine := ethash.New(ethash.Config{
			CacheDir:       ctx.ResolvePath(config.CacheDir),
			CachesInMem:    config.CachesInMem,
			CachesOnDisk:   config.CachesOnDisk,
			DatasetDir:     config.DatasetDir,
			DatasetsInMem:  config.DatasetsInMem,
			DatasetsOnDisk: config.DatasetsOnDisk,
			//Tip9:           chainConfig.TIP9.SnailNumber.Uint64(),
		})
		//engine.SetThreads(-1) // Disable CPU mining
		return engine
	}
}

// APIs return the collection of RPC services the etrue package offers.
// NOTE, some of these services probably need to be moved to somewhere else.
func (s *Truechain) APIs() []rpc.API {
	apis := trueapi.GetAPIs(s.APIBackend)

	// Append any APIs exposed explicitly by the consensus engine
	apis = append(apis, s.engine.APIs(s.BlockChain())...)

	// Append etrue	APIs and  Eth APIs
	namespaces := []string{"etrue", "eth"}
	for _, name := range namespaces {
		apis = append(apis, []rpc.API{
			{
				Namespace: name,
				Version:   "1.0",
				Service:   NewPublicTruechainAPI(s),
				Public:    true,
			}, /*{
				Namespace: name,
				Version:   "1.0",
				Service:   NewPublicMinerAPI(s),
				Public:    true,
			},*/{
				Namespace: name,
				Version:   "1.0",
				Service:   downloader.NewPublicDownloaderAPI(s.protocolManager.downloader, s.eventMux),
				Public:    true,
			}, {
				Namespace: name,
				Version:   "1.0",
				Service:   filters.NewPublicFilterAPI(s.APIBackend, false),
				Public:    true,
			},
		}...)
	}
	// Append all the local APIs and return
	return append(apis, []rpc.API{
		/*{
			Namespace: "miner",
			Version:   "1.0",
			Service:   NewPrivateMinerAPI(s),
			Public:    false,
		},*/{
			Namespace: "admin",
			Version:   "1.0",
			Service:   NewPrivateAdminAPI(s),
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPublicDebugAPI(s),
			Public:    true,
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPrivateDebugAPI(s.chainConfig, s),
		}, {
			Namespace: "net",
			Version:   "1.0",
			Service:   s.netRPCService,
			Public:    true,
		},
	}...)
}

func (s *Truechain) ResetWithGenesisBlock(gb *types.Block) {
	s.blockchain.ResetWithGenesisBlock(gb)
}

func (s *Truechain) ResetWithFastGenesisBlock(gb *types.Block) {
	s.blockchain.ResetWithGenesisBlock(gb)
}

func (s *Truechain) Etherbase() (eb common.Address, err error) {
	s.lock.RLock()
	etherbase := s.etherbase
	s.lock.RUnlock()

	if etherbase != (common.Address{}) {
		return etherbase, nil
	}
	if wallets := s.AccountManager().Wallets(); len(wallets) > 0 {
		if accounts := wallets[0].Accounts(); len(accounts) > 0 {
			etherbase := accounts[0].Address

			s.lock.Lock()
			s.etherbase = etherbase
			s.lock.Unlock()

			log.Info("Coinbase automatically configured", "address", etherbase)
			return etherbase, nil
		}
	}
	return common.Address{}, fmt.Errorf("coinbase must be explicitly specified")
}

// SetEtherbase sets the mining reward address.
func (s *Truechain) SetEtherbase(etherbase common.Address) {
	s.lock.Lock()
	s.etherbase = etherbase
	s.agent.committeeNode.Coinbase = etherbase
	s.lock.Unlock()

	//s.miner.SetEtherbase(etherbase)
}

/*func (s *Truechain) StartMining(local bool) error {
	eb, err := s.Etherbase()
	if err != nil {
		log.Error("Cannot start mining without coinbase", "err", err)
		return fmt.Errorf("coinbase missing: %v", err)
	}

	// snail chain not need clique

	if local {
		// If local (CPU) mining is started, we can disable the transaction rejection
		// mechanism introduced to speed sync times. CPU mining on mainnet is ludicrous
		// so none will ever hit this path, whereas marking sync done on CPU mining
		// will ensure that private networks work in single miner mode too.
		atomic.StoreUint32(&s.protocolManager.acceptFruits, 1)

	}
	go s.miner.Start(eb)
	return nil
}*/

//func (s *Truechain) StopMining()                       { s.miner.Stop() }
//func (s *Truechain) IsMining() bool                    { return s.miner.Mining() }
//func (s *Truechain) Miner() *miner.Miner               { return s.miner }
func (s *Truechain) PbftAgent() *PbftAgent             { return s.agent }
func (s *Truechain) AccountManager() *accounts.Manager { return s.accountManager }
func (s *Truechain) BlockChain() *core.BlockChain      { return s.blockchain }
func (s *Truechain) Config() *Config                   { return s.config }

//func (s *Truechain) SnailBlockChain() *chain.SnailBlockChain { return s.snailblockchain }
func (s *Truechain) TxPool() *core.TxPool                    { return s.txPool }

//func (s *Truechain) SnailPool() *chain.SnailPool { return s.snailPool }

func (s *Truechain) EventMux() *event.TypeMux           { return s.eventMux }
func (s *Truechain) Engine() consensus.Engine           { return s.engine }
func (s *Truechain) ChainDb() etruedb.Database          { return s.chainDb }
func (s *Truechain) IsListening() bool                  { return true } // Always listening
func (s *Truechain) EthVersion() int                    { return int(s.protocolManager.SubProtocols[0].Version) }
func (s *Truechain) NetVersion() uint64                 { return s.networkID }
func (s *Truechain) Downloader() *downloader.Downloader { return s.protocolManager.downloader }


// Protocols implements node.Service, returning all the currently configured
// network protocols to start.
func (s *Truechain) Protocols() []p2p.Protocol {

	if s.lesServer == nil {
		return s.protocolManager.SubProtocols
	}
	return append(s.protocolManager.SubProtocols, s.lesServer.Protocols()...)
	/*protos := make([]p2p.Protocol, len(ProtocolVersions))
	for i, vsn := range ProtocolVersions {
		protos[i] = s.protocolManager.makeProtocol(vsn)
		//protos[i].Attributes = []enr.Entry{s.currentEthEntry()}
		//protos[i].DialCandidates = s.dialCandiates
	}
	if s.lesServer != nil {
		protos = append(protos, s.lesServer.Protocols()...)
	}
	return protos*/
}

// Start implements node.Service, starting all internal goroutines needed by the
// Truechain protocol implementation.
func (s *Truechain) Start(srvr *p2p.Server) error {

	// Start the bloom bits servicing goroutines
	s.startBloomHandlers()

	// Start the RPC service
	s.netRPCService = trueapi.NewPublicNetAPI(srvr, s.NetVersion())

	// Figure out a max peers count based on the server limits
	maxPeers := srvr.MaxPeers
	if s.config.LightServ > 0 {
		if s.config.LightPeers >= srvr.MaxPeers {
			return fmt.Errorf("invalid peer config: light peer count (%d) >= total peer count (%d)", s.config.LightPeers, srvr.MaxPeers)
		}
		maxPeers -= s.config.LightPeers
	}
	// Start the networking layer and the light server if requested
	s.protocolManager.Start(maxPeers)
	if s.lesServer != nil {
		s.lesServer.Start(srvr)
	}
	s.startPbftServer()
	if s.pbftServer == nil {
		log.Error("start pbft server failed.")
		return errors.New("start pbft server failed.")
	}
	s.agent.server = s.pbftServer
	log.Info("", "server", s.agent.server)
	s.agent.Start()

	s.election.Start()

	//start fruit journal
	//s.snailPool.Start()

	// Start the networking layer and the light server if requested
	/*s.protocolManager.Start2(maxPeers)
	if s.lesServer != nil {
		s.lesServer.Start(srvr)
	}*/

	return nil
}

// Stop implements node.Service, terminating all internal goroutines used by the
// Truechain protocol.
func (s *Truechain) Stop() error {
	s.stopPbftServer()
	s.bloomIndexer.Close()
	s.blockchain.Stop()
	//s.snailblockchain.Stop()
	s.protocolManager.Stop()
	if s.lesServer != nil {
		s.lesServer.Stop()
	}
	s.txPool.Stop()
	//s.snailPool.Stop()
	//s.miner.Stop()
	s.eventMux.Stop()

	s.chainDb.Close()
	close(s.shutdownChan)

	return nil
}

func (s *Truechain) startPbftServer() error {
	var taiprivate taiCrypto.TaiPrivateKey
	//caoliang modify
	//priv, err := crypto.ToECDSA(s.config.CommitteeKey)
	priv, err := taiprivate.ToECDSA(s.config.CommitteeKey)
	if err != nil {
		return err
	}

	cfg := config.DefaultConfig()
	cfg.P2P.ListenAddress1 = "tcp://0.0.0.0:" + strconv.Itoa(s.config.Port)
	cfg.P2P.ListenAddress2 = "tcp://0.0.0.0:" + strconv.Itoa(s.config.StandbyPort)

	n1, err := tbft.NewNode(cfg, "1", &priv.Private, s.agent)
	if err != nil {
		return err
	}
	s.pbftServer = n1
	return n1.Start()
}

func (s *Truechain) stopPbftServer() error {
	if s.pbftServer != nil {
		s.pbftServer.Stop()
	}
	return nil
}
