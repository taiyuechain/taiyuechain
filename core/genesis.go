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

package core

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/common/hexutil"
	"github.com/taiyuechain/taiyuechain/common/math"
	"github.com/taiyuechain/taiyuechain/consensus"
	"github.com/taiyuechain/taiyuechain/core/rawdb"
	"github.com/taiyuechain/taiyuechain/core/state"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/log"
	"github.com/taiyuechain/taiyuechain/params"
	"github.com/taiyuechain/taiyuechain/rlp"
	"github.com/taiyuechain/taiyuechain/yuedb"
)

//go:generate gencodec -type Genesis -field-override genesisSpecMarshaling -out gen_genesis.go
//go:generate gencodec -type GenesisAccount -field-override genesisAccountMarshaling -out gen_genesis_account.go

var errGenesisNoConfig = errors.New("genesis has no chain configuration")

const (
	SYMMETRICCRYPTOSM4    = 1
	SYMMETRICCRYPTOAES    = 2
	ASYMMETRICCRYPTOECDSA = 3
	ASYMMETRICCRYPTOSM2   = 4
	HASHCRYPTOSM3         = 5
	HASHCRYPTOHAS3        = 6
)

// Genesis specifies the header fields, state of a genesis block. It also defines hard
// fork switch-over blocks through the chain configuration.
type Genesis struct {
	Config       *params.ChainConfig      `json:"config"`
	Timestamp    uint64                   `json:"timestamp"`
	ExtraData    []byte                   `json:"extraData"`
	GasLimit     uint64                   `json:"gasLimit"   gencodec:"required"`
	UseGas       uint8                    `json:"useGas" 		gencodec:"required"`
	IsCoin   uint8                    	  `json:"isCoin" 		gencodec:"required"`
	KindOfCrypto uint8                    `json:"kindOfCrypto" 		gencodec:"required"`
	PermisionWlSendTx   uint8             `json:"permisionWlSendTx" 		gencodec:"required"`
	PermisionWlCreateTx  uint8            `json:"permisionWlCreateTx" 		gencodec:"required"`
	Coinbase     common.Address           `json:"coinbase"`
	Alloc        types.GenesisAlloc       `json:"alloc"`
	Committee    []*types.CommitteeMember `json:"committee"      gencodec:"required"`
	CertList     [][]byte                 `json:"CertList"      gencodec:"required"`

	// These fields are used for consensus tests. Please don't use them
	// in actual genesis blocks.
	Number     uint64      `json:"number"`
	GasUsed    uint64      `json:"gasUsed"`
	ParentHash common.Hash `json:"parentHash"`
}

// GenesisAccount is an account in the state of the genesis block.
type GenesisAccount struct {
	Code       []byte                      `json:"code,omitempty"`
	Storage    map[common.Hash]common.Hash `json:"storage,omitempty"`
	Balance    *big.Int                    `json:"balance" gencodec:"required"`
	Nonce      uint64                      `json:"nonce,omitempty"`
	PrivateKey []byte                      `json:"secretKey,omitempty"` // for tests
}

// field type overrides for gencodec
type genesisSpecMarshaling struct {
	Timestamp math.HexOrDecimal64
	ExtraData hexutil.Bytes
	GasLimit  math.HexOrDecimal64
	GasUsed   math.HexOrDecimal64
	Number    math.HexOrDecimal64
	CertList  []hexutil.Bytes
	Alloc     map[common.UnprefixedAddress]types.GenesisAccount
}

type genesisAccountMarshaling struct {
	Code       hexutil.Bytes
	Balance    *math.HexOrDecimal256
	Nonce      math.HexOrDecimal64
	Storage    map[storageJSON]storageJSON
	PrivateKey hexutil.Bytes
}

type specialString string
type Foo2 struct{ M map[string]string }

type foo2Marshaling struct{ S map[string]specialString }

// storageJSON represents a 256 bit byte array, but allows less than 256 bits when
// unmarshaling from hex.
type storageJSON common.Hash

func (h *storageJSON) UnmarshalText(text []byte) error {
	text = bytes.TrimPrefix(text, []byte("0x"))
	if len(text) > 64 {
		return fmt.Errorf("too many hex characters in storage key/value %q", text)
	}
	offset := len(h) - len(text)/2 // pad on the left
	if _, err := hex.Decode(h[offset:], text); err != nil {
		fmt.Println(err)
		return fmt.Errorf("invalid hex storage key/value %q", text)
	}
	return nil
}

func (h storageJSON) MarshalText() ([]byte, error) {
	return hexutil.Bytes(h[:]).MarshalText()
}

// GenesisMismatchError is raised when trying to overwrite an existing
// genesis block with an incompatible one.
type GenesisMismatchError struct {
	Stored, New common.Hash
}

func (e *GenesisMismatchError) Error() string {
	return fmt.Sprintf("database already contains an incompatible genesis block (have %x, new %x)", e.Stored[:8], e.New[:8])
}

// SetupGenesisBlock writes or updates the genesis block in db.
// The block that will be used is:
//
//                          genesis == nil       genesis != nil
//                       +------------------------------------------
//     db has no genesis |  main-net default  |  genesis
//     db has genesis    |  from DB           |  genesis (if compatible)
//
// The stored chain configuration will be updated if it is compatible (i.e. does not
// specify a fork block below the local head block). In case of a conflict, the
// error is a *params.ConfigCompatError and the new, unwritten config is returned.
//
// The returned chain configuration is never nil.
func SetupGenesisBlock(db yuedb.Database, genesis *Genesis) (*params.ChainConfig, common.Hash, error) {
	if genesis != nil && genesis.Config == nil {
		return params.AllMinervaProtocolChanges, common.Hash{}, errGenesisNoConfig
	}

	fastConfig, fastHash, fastErr := setupGenesisBlock(db, genesis)
	genesisBlock := rawdb.ReadBlock(db, fastHash, 0)
	if genesisBlock != nil {
		data := genesisBlock.Header().Extra
		params.ParseExtraDataFromGenesis(data)
		GasUsed, IsCoin, KindOfCrypto := data[0], data[1], data[2]
		if err := baseCheck(GasUsed,IsCoin,KindOfCrypto); err != nil {
			return nil,common.Hash{},err
		}
	}
	return fastConfig, fastHash, fastErr

}

// setupGenesisBlock writes or updates the fast genesis block in db.
// The block that will be used is:
//
//                          genesis == nil       genesis != nil
//                       +------------------------------------------
//     db has no genesis |  main-net default  |  genesis
//     db has genesis    |  from DB           |  genesis (if compatible)
//
// The stored chain configuration will be updated if it is compatible (i.e. does not
// specify a fork block below the local head block). In case of a conflict, the
// error is a *params.ConfigCompatError and the new, unwritten config is returned.
//
// The returned chain configuration is never nil.
func setupGenesisBlock(db yuedb.Database, genesis *Genesis) (*params.ChainConfig, common.Hash, error) {
	if genesis != nil && genesis.Config == nil {
		return params.AllMinervaProtocolChanges, common.Hash{}, errGenesisNoConfig
	}

	// Just commit the new block if there is no stored genesis block.
	stored := rawdb.ReadCanonicalHash(db, 0)
	if (stored == common.Hash{}) {
		if genesis == nil {
			log.Info("Writing default main-net genesis block")
			genesis = DefaultGenesisBlock()
		} else {
			log.Info("Writing custom genesis block")
		}
		block, err := genesis.Commit(db)
		return genesis.Config, block.Hash(), err
	}

	// Check whether the genesis block is already written.
	if genesis != nil {
		hash := genesis.ToBlock(nil).Hash()
		if hash != stored {
			return genesis.Config, hash, &GenesisMismatchError{stored, hash}
		}
	}

	// Get the existing chain configuration.
	newcfg := genesis.configOrDefault(stored)
	storedcfg := rawdb.ReadChainConfig(db, stored)
	if storedcfg == nil {
		log.Warn("Found genesis block without chain config")
		rawdb.WriteChainConfig(db, stored, newcfg)
		return newcfg, stored, nil
	}
	// Special case: don't change the existing config of a non-mainnet chain if no new
	// config is supplied. These chains would get AllProtocolChanges (and a compat error)
	// if we just continued here.
	if genesis == nil && stored != params.MainnetGenesisHash {
		return storedcfg, stored, nil
	}

	// Check config compatibility and write the config. Compatibility errors
	// are returned to the caller unless we're already at block zero.
	height := rawdb.ReadHeaderNumber(db, rawdb.ReadHeadHeaderHash(db))
	if height == nil {
		return newcfg, stored, fmt.Errorf("missing block number for head header hash")
	}
	compatErr := storedcfg.CheckCompatible(newcfg, *height)
	if compatErr != nil && *height != 0 && compatErr.RewindTo != 0 {
		return newcfg, stored, compatErr
	}
	rawdb.WriteChainConfig(db, stored, newcfg)
	return newcfg, stored, nil
}

// Commit writes the block and state of a genesis specification to the database.
// The block is committed as the canonical head block.
func (g *Genesis) Commit(db yuedb.Database) (*types.Block, error) {
	block := g.ToBlock(db)
	if block.Number().Sign() != 0 {
		return nil, fmt.Errorf("can't commit genesis block with number > 0")
	}
	rawdb.WriteBlock(db, block)
	rawdb.WriteReceipts(db, block.Hash(), block.NumberU64(), nil)
	rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	rawdb.WriteHeadBlockHash(db, block.Hash())
	rawdb.WriteHeadHeaderHash(db, block.Hash())
	rawdb.WriteStateGcBR(db, block.NumberU64())

	config := g.Config
	if config == nil {
		config = params.AllMinervaProtocolChanges
	}
	rawdb.WriteChainConfig(db, block.Hash(), config)
	return block, nil
}
func (g *Genesis) makeExtraData() []byte {
	h := []byte{g.UseGas, g.IsCoin, g.KindOfCrypto,g.PermisionWlSendTx,g.PermisionWlCreateTx}
	g.ExtraData = h
	return g.ExtraData
}

// ToBlock creates the genesis block and writes state of a genesis specification
// to the given database (or discards it if nil).
func (g *Genesis) ToBlock(db yuedb.Database) *types.Block {

	if db == nil {
		db = yuedb.NewMemDatabase()
	}
	g.ExtraData = g.makeExtraData()
	params.ParseExtraDataFromGenesis(g.ExtraData)
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(db))
	for addr, account := range g.Alloc {
		if g.IsCoin > 0 {
			statedb.AddBalance(addr, account.Balance)
		}
		statedb.SetCode(addr, account.Code)
		statedb.SetNonce(addr, account.Nonce)
		for key, value := range account.Storage {
			statedb.SetState(addr, key, value)
		}
	}
	pubk := [][]byte{}
	coinAddr := []common.Address{}
	for _,v:= range  g.Committee{
		pubk = append(pubk,v.Publickey)
		coinAddr = append(coinAddr,v.Coinbase)
	}
	consensus.OnceInitCAState(statedb, new(big.Int).SetUint64(g.Number), g.CertList,pubk,coinAddr)
	root := statedb.IntermediateRoot(false)

	head := &types.Header{
		Number:     new(big.Int).SetUint64(g.Number),
		Time:       new(big.Int).SetUint64(g.Timestamp),
		ParentHash: g.ParentHash,
		Extra:      g.ExtraData,
		GasLimit:   g.GasLimit,
		GasUsed:    g.GasUsed,
		Root:       root,
	}
	if g.GasLimit == 0 {
		head.GasLimit = params.GenesisGasLimit
	}
	statedb.Commit(false)
	statedb.Database().TrieDB().Commit(root, true)

	// All genesis committee members are included in switchinfo of block #0
	committee := &types.SwitchInfos{CID: common.Big0, Members: g.Committee, BackMembers: make([]*types.CommitteeMember, 0), Vals: make([]*types.SwitchEnter, 0)}
	for _, member := range committee.Members {
		//caolaing modify
		//pubkey, _ := crypto.UnmarshalPubkey(member.Publickey)
		// cc := hex.EncodeToString(member.Publickey)
		// fmt.Sprintln("cccccc" + cc)
		pubkey, e := crypto.UnmarshalPubkey(member.Publickey)
		if e != nil {
			fmt.Println(e)
		}
		member.Flag = types.StateUsedFlag
		member.MType = types.TypeFixed
		//caolaing modify
		member.CommitteeBase = crypto.PubkeyToAddress(*pubkey)
		///member.CommitteeBase = taipublic.PubkeyToAddress(*pubkey)
	}
	return types.NewBlock(head, nil, nil, nil, committee.Members)
}

// MustCommit writes the genesis block and state to db, panicking on error.
// The block is committed as the canonical head block.
func (g *Genesis) MustCommit(db yuedb.Database) *types.Block {
	if err := baseCheck(g.UseGas,g.IsCoin,g.KindOfCrypto); err != nil {
		panic(err)
	}
	block, err := g.Commit(db)
	if err != nil {
		panic(err)
	}
	return block
}

// DefaultGenesisBlock returns the Taiyuechain main net snail block.
func DefaultGenesisBlock() *Genesis {
	seedkey1 := hexutil.MustDecode("0x04bdf9699d20b4ebabe76e76260480e5492c87aaeda51b138bd22c6d66b69549313dc3eb8c96dc9a1cbbf3b347322c51c05afdd609622277444e0f07e6bd35d8bd")
	seedkey2 := hexutil.MustDecode("0x045e1711b6cd8550a5e5466f7f0868b5507929cb69c2f0fca84f8f94816eb40a808ea8a77c3d83c9d16341acb037fbea2f7d9d4af46326defa39b408f40f28fb98")
	seedkey3 := hexutil.MustDecode("0x041b931d350257e881f27bce2563d98c99b13ca4f525a0662f5e7d53f085edff0dca8ceaae550c9f4ceecf217f72806a48a48fb024916392ae41d7c45168e89b94")
	seedkey4 := hexutil.MustDecode("0x049923777d866fd80485be57a126d638cc7dda78a5d6958aff784ca7ed9d9c7be494125bf75fd0328490ae51020274427b9fbb07f59e4c9b5104ac6924721a4438")

	strcert1 := "308201453081ec0209008c731f572c5ec0c6300a06082a811ccf55018375302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d301e170d3230303831303033333535345a170d3230303930393033333535345a302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d3059301306072a8648ce3d020106082a811ccf5501822d03420004bdf9699d20b4ebabe76e76260480e5492c87aaeda51b138bd22c6d66b69549313dc3eb8c96dc9a1cbbf3b347322c51c05afdd609622277444e0f07e6bd35d8bd300a06082a811ccf55018375034800304502202ead6d5cf1ecaa477851a563b2971902058729305678122aa91da2f2fb2b82b6022100af38c200f3c91a54977c305a9d59188abd336e7c785086c3b11279210222508e"
	strcert2 := "308201443081ec020900a0a258e3eb721c0f300a06082a811ccf55018375302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d301e170d3230303831303033343635335a170d3230303930393033343635335a302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d3059301306072a8648ce3d020106082a811ccf5501822d034200045e1711b6cd8550a5e5466f7f0868b5507929cb69c2f0fca84f8f94816eb40a808ea8a77c3d83c9d16341acb037fbea2f7d9d4af46326defa39b408f40f28fb98300a06082a811ccf550183750347003044022015061090dd66305dbcf1d89a468fbc9470bb9bffef95c4d6aaba449cfa3376130220543ff626a7bede39d87c3ec65b7ce8ff83a93ad8df79a7ec19bbdcc7d347ba95"
	strcert3 := "308201453081ec020900fbbcf890b206f70c300a06082a811ccf55018375302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d301e170d3230303831303036333734365a170d3230303930393036333734365a302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d3059301306072a8648ce3d020106082a811ccf5501822d034200041b931d350257e881f27bce2563d98c99b13ca4f525a0662f5e7d53f085edff0dca8ceaae550c9f4ceecf217f72806a48a48fb024916392ae41d7c45168e89b94300a06082a811ccf550183750348003045022100c5fed38b5508249a32ea63d7aa5c765a13d06b26944d089f5732361ee09fb9a802200229930514862e73f163d50c300e728e44be9cfa4cffa6fa3e240556bb66adbe"
	strcert4 := "308201453081ec020900d734a4e8691802ce300a06082a811ccf55018375302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d301e170d3230303831303036333831395a170d3230303930393036333831395a302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d3059301306072a8648ce3d020106082a811ccf5501822d034200049923777d866fd80485be57a126d638cc7dda78a5d6958aff784ca7ed9d9c7be494125bf75fd0328490ae51020274427b9fbb07f59e4c9b5104ac6924721a4438300a06082a811ccf550183750348003045022100a14c345198b20306e42273d760565279327858fbb94f1f355be5440544f94a4802203dd3a45f0b61d04bf80ff661404f879dd885fbf55632518a98ea7f874621b4be"
	cert1, _ := hex.DecodeString(strcert1)
	cert2, _ := hex.DecodeString(strcert2)
	cert3, _ := hex.DecodeString(strcert3)
	cert4, _ := hex.DecodeString(strcert4)
	var certList = [][]byte{cert1, cert2, cert3, cert4}
	amount1, _ := new(big.Int).SetString("24000000000000000000000000", 10)

	return &Genesis{
		Config:       params.MainnetChainConfig,
		GasLimit:     16777216,
		UseGas:       1,
		IsCoin:   1,
		KindOfCrypto: 2,
		PermisionWlSendTx:		1,
		PermisionWlCreateTx:		1,
		Timestamp:    1537891200,
		Coinbase:   common.HexToAddress("0x0000000000000000000000000000000000000000"),
		ParentHash: common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		Alloc: map[common.Address]types.GenesisAccount{
			common.HexToAddress("0x68231C69431Cd7592356aBaC59E7A9D325406653"): {Balance: amount1},
			common.HexToAddress("0xf7547aB248CEdCD8DdEe37b3E2e331061898f869"): {Balance: amount1},
			common.HexToAddress("0xA9b892D0A141932645BF8143cC984cbF1168bf97"): {Balance: amount1},
			common.HexToAddress("0xA17aF10277326021CEa21BC8BdDece55a17C4585"): {Balance: amount1},
		},
		Committee: []*types.CommitteeMember{
			{Coinbase: getAddressFromPub(seedkey1), Publickey: seedkey1},
			{Coinbase: getAddressFromPub(seedkey2), Publickey: seedkey2},
			{Coinbase: getAddressFromPub(seedkey3), Publickey: seedkey3},
			{Coinbase: getAddressFromPub(seedkey4), Publickey: seedkey4},
		},
		CertList: certList,
	}
}

func getAddressFromPub(pubByte []byte) common.Address  {
	pub,_ := crypto.UnmarshalPubkey(pubByte)
	addr4 := crypto.PubkeyToAddress(*pub)
	return addr4
}

func (g *Genesis) configOrDefault(ghash common.Hash) *params.ChainConfig {
	switch {
	case g != nil:
		return g.Config
	case ghash == params.MainnetGenesisHash:
		return params.MainnetChainConfig
	case ghash == params.MainnetSnailGenesisHash:
		return params.MainnetChainConfig
	case ghash == params.TestnetGenesisHash:
		return params.TestnetChainConfig
	case ghash == params.TestnetSnailGenesisHash:
		return params.TestnetChainConfig
	default:
		return params.AllMinervaProtocolChanges
	}
}

func decodePrealloc(data string) types.GenesisAlloc {
	var p []struct{ Addr, Balance *big.Int }
	if err := rlp.NewStream(strings.NewReader(data), 0).Decode(&p); err != nil {
		panic(err)
	}
	ga := make(types.GenesisAlloc, len(p))
	for _, account := range p {
		ga[common.BigToAddress(account.Addr)] = types.GenesisAccount{Balance: account.Balance}
	}
	return ga
}

// GenesisBlockForTesting creates and writes a block in which addr has the given wei balance.
func GenesisBlockForTesting(db yuedb.Database, addr common.Address, balance *big.Int) *types.Block {
	g := Genesis{Alloc: types.GenesisAlloc{addr: {Balance: balance}}, Config: params.AllMinervaProtocolChanges}
	return g.MustCommit(db)
}

// DefaultDevGenesisBlock returns the Rinkeby network genesis block.
func DefaultDevGenesisBlock() *Genesis {
	i, _ := new(big.Int).SetString("90000000000000000000000", 10)

	return &Genesis{
		Config:       params.DevnetChainConfig,
		GasLimit:     88080384,
		UseGas:       1,
		IsCoin:   1,
		KindOfCrypto: 2,
		PermisionWlSendTx:		1,
		PermisionWlCreateTx:		1,
		//Alloc:      decodePrealloc(mainnetAllocData),
		Alloc: map[common.Address]types.GenesisAccount{
			common.HexToAddress("0x3f9061bf173d8f096c94db95c40f3658b4c7eaad"): {Balance: i},
			common.HexToAddress("0x2cdac3658f85b5da3b70223cc3ad3b2dfe7c1930"): {Balance: i},
			common.HexToAddress("0x41acde8dd7611338c2a30e90149e682566716e9d"): {Balance: i},
			common.HexToAddress("0x0ffd116a3bf97a7112ff8779cc770b13ea3c66a5"): {Balance: i},
		},
		Committee: []*types.CommitteeMember{},
	}
}

func DefaultSingleNodeGenesisBlock() *Genesis {
	i, _ := new(big.Int).SetString("90000000000000000000000", 10)
	key1 := hexutil.MustDecode(
		"0x04b05c899076beccd524718daf560f5922fddeee001ab8decb65a81c384cafed5edeae5e1ad7790bec895d45a840eaf2ab8f9b401d173bad0a3ea125f424e3c746")

	strcert1 := "308201453081ec0209008c731f572c5ec0c6300a06082a811ccf55018375302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d301e170d3230303831303033333535345a170d3230303930393033333535345a302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d3059301306072a8648ce3d020106082a811ccf5501822d03420004bdf9699d20b4ebabe76e76260480e5492c87aaeda51b138bd22c6d66b69549313dc3eb8c96dc9a1cbbf3b347322c51c05afdd609622277444e0f07e6bd35d8bd300a06082a811ccf55018375034800304502202ead6d5cf1ecaa477851a563b2971902058729305678122aa91da2f2fb2b82b6022100af38c200f3c91a54977c305a9d59188abd336e7c785086c3b11279210222508e"
	cert1, _ := hex.DecodeString(strcert1)

	var certList = [][]byte{cert1}
	return &Genesis{
		Config:       params.SingleNodeChainConfig,
		GasLimit:     22020096,
		UseGas:       1,
		IsCoin:   1,
		KindOfCrypto: 3,
		PermisionWlSendTx:		1,
		PermisionWlCreateTx:		1,
		//Alloc:      decodePrealloc(mainnetAllocData),
		Alloc: map[common.Address]types.GenesisAccount{
			common.HexToAddress("0x966DfF880c6598C07DC5d09A24F61892aFAfd950"): {Balance: i},
		},
		Committee: []*types.CommitteeMember{
			{Coinbase: common.HexToAddress("0x966DfF880c6598C07DC5d09A24F61892aFAfd950"), Publickey: key1},
		},
		CertList: certList,
	}
}

// DefaultTestnetGenesisBlock returns the Ropsten network genesis block.
func DefaultTestnetGenesisBlock() *Genesis {
	seedkey1 := hexutil.MustDecode("0x04bdf9699d20b4ebabe76e76260480e5492c87aaeda51b138bd22c6d66b69549313dc3eb8c96dc9a1cbbf3b347322c51c05afdd609622277444e0f07e6bd35d8bd")
	seedkey2 := hexutil.MustDecode("0x045e1711b6cd8550a5e5466f7f0868b5507929cb69c2f0fca84f8f94816eb40a808ea8a77c3d83c9d16341acb037fbea2f7d9d4af46326defa39b408f40f28fb98")
	seedkey3 := hexutil.MustDecode("0x041b931d350257e881f27bce2563d98c99b13ca4f525a0662f5e7d53f085edff0dca8ceaae550c9f4ceecf217f72806a48a48fb024916392ae41d7c45168e89b94")
	seedkey4 := hexutil.MustDecode("0x049923777d866fd80485be57a126d638cc7dda78a5d6958aff784ca7ed9d9c7be494125bf75fd0328490ae51020274427b9fbb07f59e4c9b5104ac6924721a4438")

	// sm2
	//strcert1 := "308201453081ec0209008c731f572c5ec0c6300a06082a811ccf55018375302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d301e170d3230303831303033333535345a170d3230303930393033333535345a302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d3059301306072a8648ce3d020106082a811ccf5501822d03420004bdf9699d20b4ebabe76e76260480e5492c87aaeda51b138bd22c6d66b69549313dc3eb8c96dc9a1cbbf3b347322c51c05afdd609622277444e0f07e6bd35d8bd300a06082a811ccf55018375034800304502202ead6d5cf1ecaa477851a563b2971902058729305678122aa91da2f2fb2b82b6022100af38c200f3c91a54977c305a9d59188abd336e7c785086c3b11279210222508e"
	//strcert2 := "308201443081ec020900a0a258e3eb721c0f300a06082a811ccf55018375302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d301e170d3230303831303033343635335a170d3230303930393033343635335a302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d3059301306072a8648ce3d020106082a811ccf5501822d034200045e1711b6cd8550a5e5466f7f0868b5507929cb69c2f0fca84f8f94816eb40a808ea8a77c3d83c9d16341acb037fbea2f7d9d4af46326defa39b408f40f28fb98300a06082a811ccf550183750347003044022015061090dd66305dbcf1d89a468fbc9470bb9bffef95c4d6aaba449cfa3376130220543ff626a7bede39d87c3ec65b7ce8ff83a93ad8df79a7ec19bbdcc7d347ba95"
	//strcert3 := "308201453081ec020900fbbcf890b206f70c300a06082a811ccf55018375302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d301e170d3230303831303036333734365a170d3230303930393036333734365a302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d3059301306072a8648ce3d020106082a811ccf5501822d034200041b931d350257e881f27bce2563d98c99b13ca4f525a0662f5e7d53f085edff0dca8ceaae550c9f4ceecf217f72806a48a48fb024916392ae41d7c45168e89b94300a06082a811ccf550183750348003045022100c5fed38b5508249a32ea63d7aa5c765a13d06b26944d089f5732361ee09fb9a802200229930514862e73f163d50c300e728e44be9cfa4cffa6fa3e240556bb66adbe"
	//strcert4 := "308201453081ec020900d734a4e8691802ce300a06082a811ccf55018375302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d301e170d3230303831303036333831395a170d3230303930393036333831395a302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d3059301306072a8648ce3d020106082a811ccf5501822d034200049923777d866fd80485be57a126d638cc7dda78a5d6958aff784ca7ed9d9c7be494125bf75fd0328490ae51020274427b9fbb07f59e4c9b5104ac6924721a4438300a06082a811ccf550183750348003045022100a14c345198b20306e42273d760565279327858fbb94f1f355be5440544f94a4802203dd3a45f0b61d04bf80ff661404f879dd885fbf55632518a98ea7f874621b4be"

	// rsa
	strcert1 := "308201cd30820136020900ba611dfd2de0206c300d06092a864886f70d01010b0500302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d301e170d3230303831303039323835385a170d3230303930393039323835385a302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d30819f300d06092a864886f70d010101050003818d0030818902818100e24788644afaa1c23649edcbb43eee3c8fcb594d7c6a8c932861e8f5b65ef9bbaab9703fd4ea1248d9d4b82824c7bd6c744551d22c4a437904f0fbe386c0dced3cb9a7e0e126f95fa256d2ae45d3bbb6ba3730e3412e0706cffadbe5c8ba0468b0f9e3fd69a54cbcf40341c94c29571670bebb9f79a1d3edc35c8c216af1f8890203010001300d06092a864886f70d01010b050003818100993e2fbb8f5955abc8afd8f31cf823b730772c9a14dad814d5b77639ce724f3e926a8de43ca405fcef864c83b4abc0efb233b5f5198b997771e63187e7483abf171e48976eb93f06e3b67786c3ec8539e0b3c172e913b9f9a011074d88226f62d1768ed06b288f3d996cd2180e62d8c204c09166987cffbe4037dffcafc84814"
	strcert2 := "308201cd308201360209009a54c40bb84ab35a300d06092a864886f70d01010b0500302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d301e170d3230303831303039333431355a170d3230303930393039333431355a302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d30819f300d06092a864886f70d010101050003818d0030818902818100b934b98ad860c574e19b3e8049df71daf5efe8e33e0330b2a038f9f82d5fb872ada25af6fa835ac69fc0010d56dc38e1e6652b5e44910c3b938bbec657cba22e15ab6d78fcffed4ef9c7775cad52f31e77393e2500c0a3fcd1391c182d20b25c0cb66f9ae86ca3857fdfcccd81205f5dbf66811f68da02d21b7bdbe5da821d150203010001300d06092a864886f70d01010b050003818100177e4f188f3628653b9cb718cfcad3ba29c18815448971313967b8ccfe3a75c397a4049e80aa1203d576399fd05d86a80024c4e5028140a556e253a1a9d7b883bcc24daa709acd445e974d512eb0fbd74f19dfa7b9fecd986e84ba21f67b24bce9f07793d510fc1ec68e7d6947e79d653da265349bf13d2752c2fe489af32c1d"
	strcert3 := "308201cd30820136020900fac91ee1dac2756d300d06092a864886f70d01010b0500302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d301e170d3230303831303039333434375a170d3230303930393039333434375a302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d30819f300d06092a864886f70d010101050003818d0030818902818100c018b76bdd0190fa0d0a892cd61028b3e0ce492b44f0c284e0dc537b9c9d082ab330ec9b7cfa8a4d57883a9cf9a7fb9c0c26c679e8452f02f554c0246b63c26ba99c24433f848ca85842000debe7469cfe48dbb6ed7f98f1a10f28278980362b385dc392926a69c1a7a74a7ab61f33f9d0df1cdbfea7f52897dd668b81f9fa110203010001300d06092a864886f70d01010b050003818100bbcc9b38f2ae02e45ebb0333583d671523e49112eeb170a734a46a4d9a4901ce9a6244f804f84761dfcbd880c99fbd6d35ad122c4526661023365593bfbf9fc0f4b728ec8067531e0411af0356f6fae5a8a825dbed32543c3387403f5bcfcd467480d1175c6edf6b320a08c9dfc858cab562516a7cf2dd963375e8d7fb06fb93"
	strcert4 := "308201cd3082013602090084b6f3a060188371300d06092a864886f70d01010b0500302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d301e170d3230303831303039333531335a170d3230303930393039333531335a302b310f300d060355040a0c06e6b3b0e5b2b33118301606035504030c0f746169797565636861696e2e636f6d30819f300d06092a864886f70d010101050003818d0030818902818100e5bbc82a530f07b13e547f13f0cfb6211b9bfda78ea466ba0cc452bba0039c4d3eabc5c900d06b3b15040f3ac9647e2f3af231632b24d7f863ec5506206552e5d6e7aabf5aa53734ac859e87cd125a9e913fcac5b49cfd220679673e0be7528482f39898119022149f0f7d539a16c15db829e479df64af5aa3e978074efcdd650203010001300d06092a864886f70d01010b05000381810024f028c2db4311a09a60bfe003172bacc2ad9012ae43f3398037136699e08b1ce3a2e2b99abe8628335552bb4fbdc1bcab9c10772b1ffe5bdf2072e51ca575ed244b1cb9d9ee1d72d32e1d01868e85a5d894288d6b76e2174640b5802c02459156e23f041d99e24a781b336b4ce5482c6c57b4a52f52b6ae168e453cdaff3d98"

	cert1, _ := hex.DecodeString(strcert1)
	cert2, _ := hex.DecodeString(strcert2)
	cert3, _ := hex.DecodeString(strcert3)
	cert4, _ := hex.DecodeString(strcert4)
	var certList = [][]byte{cert1, cert2, cert3, cert4}
	amount1, _ := new(big.Int).SetString("24000000000000000000000000", 10)
	return &Genesis{
		Config:       params.TestnetChainConfig,
		GasLimit:     20971520,
		UseGas:       1,
		IsCoin:   1,
		KindOfCrypto: 2,
		PermisionWlSendTx:		1,
		PermisionWlCreateTx:		1,
		Timestamp:    1537891200,
		Coinbase:     common.HexToAddress("0x0000000000000000000000000000000000000000"),
		ParentHash:   common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		Alloc: map[common.Address]types.GenesisAccount{
			common.HexToAddress("0x68231C69431Cd7592356aBaC59E7A9D325406653"): {Balance: amount1},
			common.HexToAddress("0xf7547aB248CEdCD8DdEe37b3E2e331061898f869"): {Balance: amount1},
			common.HexToAddress("0xA9b892D0A141932645BF8143cC984cbF1168bf97"): {Balance: amount1},
			common.HexToAddress("0xA17aF10277326021CEa21BC8BdDece55a17C4585"): {Balance: amount1},
		},
		Committee: []*types.CommitteeMember{
			{Coinbase: getAddressFromPub(seedkey1), Publickey: seedkey1},
			{Coinbase: getAddressFromPub(seedkey2), Publickey: seedkey2},
			{Coinbase: getAddressFromPub(seedkey3), Publickey: seedkey3},
			{Coinbase: getAddressFromPub(seedkey4), Publickey: seedkey4},
		},
		CertList: certList,
	}
}
func baseCheck(useGas,isCoin,kindCrypto byte) error {
	if int(kindCrypto) < crypto.CRYPTO_P256_SH3_AES || int(kindCrypto) > crypto.CRYPTO_S256_SH3_AES {
		return errors.New("wrong param on kindCrypto")
	}
	if isCoin == 0 && useGas != 0 {
		return errors.New("has gas used on no any rewards")
	}
	return nil
}