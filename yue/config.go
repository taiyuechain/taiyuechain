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

package yue

import (
	"math/big"
	"os"
	"os/user"
	"time"

	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/common/hexutil"
	"github.com/taiyuechain/taiyuechain/core"
	"github.com/taiyuechain/taiyuechain/params"
	"github.com/taiyuechain/taiyuechain/yue/downloader"
	"github.com/taiyuechain/taiyuechain/yue/gasprice"
)

// DefaultConfig contains default settings for use on the Taiyuechain main net.
var DefaultConfig = Config{
	SyncMode:      downloader.FullSync,
	NodeType:      false,
	NetworkId:     19330,
	DatabaseCache: 768,
	TrieCache:     256,
	TrieTimeout:   60 * time.Minute,
	//GasPrice:      big.NewInt(18 * params.Shannon),
	MinervaMode: 0,
	GasPrice:    big.NewInt(1 * params.Babbage),
	MinerGasFloor: 12000000,
	MinerGasCeil:  16000000,
	TxPool:      core.DefaultTxPoolConfig,
	GPO: gasprice.Config{
		Blocks:     20,
		Percentile: 60,
	},
	Port:        30310,
	StandbyPort: 30311,
}

func init() {
	home := os.Getenv("HOME")
	if home == "" {
		if user, err := user.Current(); err == nil {
			home = user.HomeDir
		}
	}
}

//go:generate gencodec -type Config -field-override configMarshaling -formats toml -out gen_config.go

type Config struct {
	// The genesis block, which is inserted if the database is empty.
	// If nil, the Taiyuechain main net block is used.
	Genesis *core.Genesis

	// Protocol options
	NetworkId    uint64 // Network ID to use for selecting peers to connect to
	SyncMode     downloader.SyncMode
	NoPruning    bool
	DeletedState bool

	// Whitelist of required block number -> hash values to accept
	Whitelist map[uint64]common.Hash `toml:"-"`
	// GasPrice used for estimate gas
	GasPrice *big.Int `toml:",omitempty"`
	// CommitteeKey is the ECDSA private key for committee member.
	// If this filed is empty, can't be a committee member.
	CommitteeKey  []byte
	CommitteeBase common.Address
	// Node Cert used for consensus
	NodeCert []byte
	// Host is the host interface on which to start the pbft server. If this
	// field is empty, can't be a committee member.
	Host string `toml:",omitempty"`

	// Port is the TCP port number on which to start the pbft server.
	Port int `toml:",omitempty"`

	// StandByPort is the TCP port number on which to start the pbft server.
	StandbyPort int `toml:",omitempty"`
	// Database options
	SkipBcVersionCheck bool `toml:"-"`
	DatabaseHandles    int  `toml:"-"`
	DatabaseCache      int
	TrieCache          int
	TrieTimeout        time.Duration
	// ModeNormal(0) for Minerva
	MinervaMode   int
	MinerGasCeil  uint64
	MinerGasFloor uint64
	// Transaction pool options
	TxPool core.TxPoolConfig
	// Gas Price Oracle options
	GPO gasprice.Config

	// // Enables tracking of SHA3 preimages in the VM
	EnablePreimageRecording bool

	// // Miscellaneous options
	DocRoot string `toml:"-"`

	// // true indicate singlenode start
	NodeType bool `toml:",omitempty"`
	// Checkpoint is a hardcoded checkpoint which can be nil.
	Checkpoint *params.TrustedCheckpoint `toml:",omitempty"`
}
type configMarshaling struct {
	CommitteeKey hexutil.Bytes
	NodeCert     hexutil.Bytes
	P2PNodeCert  hexutil.Bytes
}

func (c *Config) GetNodeType() bool {
	return c.NodeType
}
