//// Copyright 2017 The go-ethereum Authors
//// This file is part of the go-ethereum library.
////
//// The go-ethereum library is free software: you can redistribute it and/or modify
//// it under the terms of the GNU Lesser General Public License as published by
//// the Free Software Foundation, either version 3 of the License, or
//// (at your option) any later version.
////
//// The go-ethereum library is distributed in the hope that it will be useful,
//// but WITHOUT ANY WARRANTY; without even the implied warranty of
//// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//// GNU Lesser General Public License for more details.
////
//// You should have received a copy of the GNU Lesser General Public License
//// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.
//
package core

//
import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"testing"

	"github.com/taiyuechain/taiyuechain/crypto"

	"github.com/davecgh/go-spew/spew"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/core/rawdb"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/params"
	"github.com/taiyuechain/taiyuechain/yuedb"
)

func TestDefaultGenesisBlock(t *testing.T) {
	block := DefaultGenesisBlock().ToBlock(nil)
	if block.Hash() != params.MainnetGenesisHash {
		t.Errorf("wrong mainnet genesis hash, got %v, want %v", common.ToHex(block.Hash().Bytes()), params.MainnetGenesisHash)
	}
	block = DefaultTestnetGenesisBlock().ToBlock(nil)
	if block.Hash() != params.TestnetGenesisHash {
		t.Errorf("wrong testnet genesis hash, got %v, want %v", common.ToHex(block.Hash().Bytes()), params.TestnetGenesisHash)
	}
}

func TestSetupGenesis(t *testing.T) {
	var (
		customghash = common.HexToHash("0x3fec74f04bae7d8a8c71d250a6edfb330ecc18d2a4bbb44c85ca1cbec21bee29")
		customg     = Genesis{
			Config: params.TestChainConfig,
			Alloc: types.GenesisAlloc{
				{1}: {Balance: big.NewInt(1), Storage: map[common.Hash]common.Hash{{1}: {1}}},
			},
		}
		oldcustomg = customg
	)
	oldcustomg.Config = &params.ChainConfig{}
	tests := []struct {
		name       string
		fn         func(yuedb.Database) (*params.ChainConfig, common.Hash, error)
		wantConfig *params.ChainConfig
		wantHash   common.Hash
		wantErr    error
	}{
		{
			name: "genesis without ChainConfig",
			fn: func(db yuedb.Database) (*params.ChainConfig, common.Hash, error) {
				return SetupGenesisBlock(db, new(Genesis))
			},
			wantErr:    errGenesisNoConfig,
			wantConfig: params.AllMinervaProtocolChanges,
		},
		{
			name: "no block in DB, genesis == nil",
			fn: func(db yuedb.Database) (*params.ChainConfig, common.Hash, error) {
				return SetupGenesisBlock(db, nil)
			},
			wantHash:   params.MainnetGenesisHash,
			wantConfig: params.MainnetChainConfig,
		},
		{
			name: "mainnet block in DB, genesis == nil",
			fn: func(db yuedb.Database) (*params.ChainConfig, common.Hash, error) {
				DefaultGenesisBlock().MustCommit(db)
				return SetupGenesisBlock(db, nil)
			},
			wantHash:   params.MainnetGenesisHash,
			wantConfig: params.MainnetChainConfig,
		},
		{
			name: "custom block in DB, genesis == testnet",
			fn: func(db yuedb.Database) (*params.ChainConfig, common.Hash, error) {
				customg.MustCommit(db)
				return SetupGenesisBlock(db, DefaultTestnetGenesisBlock())
			},
			wantErr:    &GenesisMismatchError{Stored: customghash, New: params.TestnetGenesisHash},
			wantHash:   params.TestnetGenesisHash,
			wantConfig: params.TestnetChainConfig,
		},
		// {
		// 	name: "compatible config in DB",
		// 	fn: func(db yuedb.Database) (*params.ChainConfig, common.Hash, error, *params.ChainConfig, common.Hash, error) {
		// 		oldcustomg.MustCommit(db)
		// 		oldcustomg.MustSnailCommit(db)
		// 		return SetupGenesisBlock(db, &customg)
		// 	},
		// 	wantHash:   customghash,
		// 	wantConfig: customg.Config,
		// },
		// {
		// 	name: "incompatible config in DB",
		// 	fn: func(db yuedb.Database) (*params.ChainConfig, common.Hash, error, *params.ChainConfig, common.Hash, error) {
		// 		// Commit the 'old' genesis block with Homestead transition at #2.
		// 		// Advance to block #4, past the homestead transition block of customg.
		// 		genesis := oldcustomg.MustCommit(db)

		// 		// bc, _ := NewFastBlockChain(db, nil, oldcustomg.Config, ethash.NewFullFaker(), vm.Config{})
		// 		// defer bc.Stop()

		// 		blocks, _ := GenerateChain(oldcustomg.Config, genesis, ethash.NewFaker(), db, 4, nil)
		// 		// bc.InsertChain(blocks)
		// 		// bc.CurrentBlock()
		// 		// This should return a compatibility error.
		// 		return SetupGenesisBlock(db, &customg)
		// 	},
		// 	wantHash:   customghash,
		// 	wantConfig: customg.Config,
		// 	wantErr: &params.ConfigCompatError{
		// 		What:         "Homestead fork block",
		// 		StoredConfig: big.NewInt(2),
		// 		NewConfig:    big.NewInt(3),
		// 		RewindTo:     1,
		// 	},
		// },
	}

	for _, test := range tests {
		db := yuedb.NewMemDatabase()
		config, hash, err := test.fn(db)
		// Check the return values.
		if !reflect.DeepEqual(err, test.wantErr) {
			spew := spew.ConfigState{DisablePointerAddresses: true, DisableCapacities: true}
			t.Errorf("%s: returned error %#v, want %#v", test.name, spew.NewFormatter(err), spew.NewFormatter(test.wantErr))
		}
		if !reflect.DeepEqual(config, test.wantConfig) {
			t.Errorf("%s:\nreturned %v\nwant     %v", test.name, config, test.wantConfig)
		}
		if hash != test.wantHash {
			t.Errorf("%s: returned hash %s, want %s", test.name, hash.Hex(), test.wantHash.Hex())
		} else if err == nil {
			// Check database content.
			stored := rawdb.ReadBlock(db, test.wantHash, 0)
			if stored.Hash() != test.wantHash {
				t.Errorf("%s: block in DB has hash %s, want %s", test.name, stored.Hash(), test.wantHash)
			}
		}
	}
}

func TestSetupSnailGenesis(t *testing.T) {
	var (
		//customghash = common.HexToHash("0x62e8674fcc8df82c74aad443e97c4cfdb748652ea117c8afe86cd4a04e5f44f8")
		customg = Genesis{
			Alloc: types.GenesisAlloc{
				{1}: {Balance: big.NewInt(1), Storage: map[common.Hash]common.Hash{{1}: {1}}},
			},
		}
		oldcustomg = customg
	)
	oldcustomg.Config = &params.ChainConfig{}
	tests := []struct {
		name       string
		fn         func(yuedb.Database) (*params.ChainConfig, common.Hash, error)
		wantConfig *params.ChainConfig
		wantHash   common.Hash
		wantErr    error
	}{
		{
			name: "genesis without ChainConfig",
			fn: func(db yuedb.Database) (*params.ChainConfig, common.Hash, error) {
				return SetupGenesisBlock(db, new(Genesis))
			},
			wantErr:    errGenesisNoConfig,
			wantConfig: params.AllMinervaProtocolChanges,
		},
		{
			name: "no block in DB, genesis == nil",
			fn: func(db yuedb.Database) (*params.ChainConfig, common.Hash, error) {
				return SetupGenesisBlock(db, nil)
			},
			wantHash:   params.MainnetSnailGenesisHash,
			wantConfig: params.MainnetChainConfig,
		},
		{
			name: "mainnet block in DB, genesis == nil",
			fn: func(db yuedb.Database) (*params.ChainConfig, common.Hash, error) {
				DefaultGenesisBlock().MustCommit(db)
				return SetupGenesisBlock(db, nil)
			},
			wantHash:   params.MainnetSnailGenesisHash,
			wantConfig: params.MainnetChainConfig,
		},
		// {
		// 	name: "custom block in DB, genesis == testnet",
		// 	fn: func(db yuedb.Database) (*params.ChainConfig, common.Hash, common.Hash, error) {
		// 		//customg.MustCommit(db)
		// 		customg.MustSnailCommit(db)
		// 		return SetupGenesisBlock(db, DefaultTestnetGenesisBlock())
		// 	},
		// 	wantErr:    &GenesisMismatchError{Stored: customghash, New: params.TestnetSnailGenesisHash},
		// 	wantHash:   params.TestnetSnailGenesisHash,
		// 	wantConfig: params.TestnetChainConfig,
		// },
		// {
		// 	name: "compatible config in DB",
		// 	fn: func(db yuedb.Database) (*params.ChainConfig, common.Hash, error, *params.ChainConfig, common.Hash, error) {
		// 		oldcustomg.MustCommit(db)
		// 		oldcustomg.MustSnailCommit(db)
		// 		return SetupGenesisBlock(db, &customg)
		// 	},
		// 	wantHash:   customghash,
		// 	wantConfig: customg.Config,
		// },
		// {
		// 	name: "incompatible config in DB",
		// 	fn: func(db yuedb.Database) (*params.ChainConfig, common.Hash, error, *params.ChainConfig, common.Hash, error) {
		// 		// Commit the 'old' genesis block with Homestead transition at #2.
		// 		// Advance to block #4, past the homestead transition block of customg.
		// 		genesis := oldcustomg.MustCommit(db)

		// 		// bc, _ := NewFastBlockChain(db, nil, oldcustomg.Config, ethash.NewFullFaker(), vm.Config{})
		// 		// defer bc.Stop()

		// 		blocks, _ := GenerateChain(oldcustomg.Config, genesis, ethash.NewFaker(), db, 4, nil)
		// 		// bc.InsertChain(blocks)
		// 		// bc.CurrentBlock()
		// 		// This should return a compatibility error.
		// 		return SetupGenesisBlock(db, &customg)
		// 	},
		// 	wantHash:   customghash,
		// 	wantConfig: customg.Config,
		// 	wantErr: &params.ConfigCompatError{
		// 		What:         "Homestead fork block",
		// 		StoredConfig: big.NewInt(2),
		// 		NewConfig:    big.NewInt(3),
		// 		RewindTo:     1,
		// 	},
		// },
	}

	for _, test := range tests {
		db := yuedb.NewMemDatabase()
		config, hash, err := test.fn(db)
		// Check the return values.
		if !reflect.DeepEqual(err, test.wantErr) {
			spew := spew.ConfigState{DisablePointerAddresses: true, DisableCapacities: true}
			t.Errorf("%s: returned error %#v, want %#v", test.name, spew.NewFormatter(err), spew.NewFormatter(test.wantErr))
		}
		if !reflect.DeepEqual(config, test.wantConfig) {
			t.Errorf("%s:\nreturned %v\nwant     %v", test.name, config, test.wantConfig)
		}
		if hash != test.wantHash {
			t.Errorf("%s: returned hash %s, want %s", test.name, hash.Hex(), test.wantHash.Hex())
		}
	}
}
func TestGetAddress(t *testing.T) {
	priv1, _ := crypto.HexToECDSA("d5939c73167cd3a815530fd8b4b13f1f5492c1c75e4eafb5c07e8fb7f4b09c7c")
	priv2, _ := crypto.HexToECDSA("ea4297749d514cc476fe971a7fe20100cbd29f010864341b3e624e8744d46cec")
	priv3, _ := crypto.HexToECDSA("86937006ac1e6e2c846e160d93f86c0d63b0fcefc39a46e9eaeb65188909fbdc")
	priv4, _ := crypto.HexToECDSA("cbddcbecd252a8586a4fd759babb0cc77f119d55f38bc7f80a708e75964dd801")

	fmt.Println("address1 ", crypto.AddressToHex(crypto.PubkeyToAddress(priv1.PublicKey)),
		" address2 ", crypto.AddressToHex(crypto.PubkeyToAddress(priv2.PublicKey)),
		" address3 ", crypto.AddressToHex(crypto.PubkeyToAddress(priv3.PublicKey)),
		" address4 ", crypto.AddressToHex(crypto.PubkeyToAddress(priv4.PublicKey)),
	)
}
func TestGenesisFromJson(t *testing.T) {
	// Make sure we have a valid genesis JSON
	genesisPath := "d:\\genesis.json"
	if len(genesisPath) == 0 {
		fmt.Println("Must supply path to genesis JSON file")
		return
	}
	file, err := os.Open(genesisPath)
	if err != nil {
		fmt.Println("Failed to read genesis file:", err)
		return
	}
	defer file.Close()

	genesis := new(Genesis)
	if err := json.NewDecoder(file).Decode(genesis); err != nil {
		fmt.Println("invalid genesis file：", err)
		return
	}
	db := yuedb.NewMemDatabase()
	_, h, genesisErr := SetupGenesisBlock(db, genesis)
	if genesisErr != nil {
		fmt.Println("err:", genesisErr)
	} else {
		fmt.Println("hash:", h)
	}
	fmt.Println("finish")
}
func updateSlice(s *[]int,a int) {
	*s = append(*s,a)
}
func Test07(t *testing.T) {
	aa := []int{1,2}
	updateSlice(&aa,3)
	m3 := map[string]*big.Int{
		"a": big.NewInt(10),
		"b": big.NewInt(20),
	}
	if m3["c"] == nil {
		m3["c"] = big.NewInt(30)
	}
	fmt.Println("m3[c]", m3["c"])
}
