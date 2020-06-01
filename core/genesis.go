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
	"github.com/taiyuechain/taiyuechain/taidb"
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
	Config     *params.ChainConfig      `json:"config"`
	Nonce      uint64                   `json:"nonce"`
	Timestamp  uint64                   `json:"timestamp"`
	ExtraData  []byte                   `json:"extraData"`
	GasLimit   uint64                   `json:"gasLimit"   gencodec:"required"`
	Difficulty *big.Int                 `json:"difficulty" gencodec:"required"`
	Mixhash    common.Hash              `json:"mixHash"`
	Coinbase   common.Address           `json:"coinbase"`
	Alloc      types.GenesisAlloc       `json:"alloc"      gencodec:"required"`
	Committee  []*types.CommitteeMember `json:"committee"      gencodec:"required"`
	CertList   [][]byte                 `json:"CertList"      gencodec:"required"`

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
	Nonce      math.HexOrDecimal64
	Timestamp  math.HexOrDecimal64
	ExtraData  hexutil.Bytes
	GasLimit   math.HexOrDecimal64
	GasUsed    math.HexOrDecimal64
	Number     math.HexOrDecimal64
	Difficulty *math.HexOrDecimal256
	Alloc      map[common.UnprefixedAddress]GenesisAccount
}

type genesisAccountMarshaling struct {
	Code       hexutil.Bytes
	Balance    *math.HexOrDecimal256
	Nonce      math.HexOrDecimal64
	Storage    map[storageJSON]storageJSON
	PrivateKey hexutil.Bytes
}

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
func SetupGenesisBlock(db taidb.Database, genesis *Genesis) (*params.ChainConfig, common.Hash, common.Hash, error) {
	if genesis != nil && genesis.Config == nil {
		return params.AllMinervaProtocolChanges, common.Hash{}, common.Hash{}, errGenesisNoConfig
	}

	fastConfig, fastHash, fastErr := setupFastGenesisBlock(db, genesis)

	return fastConfig, fastHash, common.Hash{}, fastErr

}

// setupFastGenesisBlock writes or updates the fast genesis block in db.
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
func setupFastGenesisBlock(db taidb.Database, genesis *Genesis) (*params.ChainConfig, common.Hash, error) {
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
		block, err := genesis.CommitFast(db)
		return genesis.Config, block.Hash(), err
	}

	// Check whether the genesis block is already written.
	if genesis != nil {
		hash := genesis.ToFastBlock(nil).Hash()
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

// CommitFast writes the block and state of a genesis specification to the database.
// The block is committed as the canonical head block.
func (g *Genesis) CommitFast(db taidb.Database) (*types.Block, error) {
	block := g.ToFastBlock(db)
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

// ToFastBlock creates the genesis block and writes state of a genesis specification
// to the given database (or discards it if nil).
func (g *Genesis) ToFastBlock(db taidb.Database) *types.Block {

	if db == nil {
		db = taidb.NewMemDatabase()
	}
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(db))
	for addr, account := range g.Alloc {
		statedb.AddBalance(addr, account.Balance)
		statedb.SetCode(addr, account.Code)
		statedb.SetNonce(addr, account.Nonce)
		for key, value := range account.Storage {
			statedb.SetState(addr, key, value)
		}
	}

	consensus.OnceInitCAState(g.Config, statedb, new(big.Int).SetUint64(g.Number), g.CertList)
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
		cc := hex.EncodeToString(member.Publickey)
		fmt.Sprintln("cccccc" + cc)
		pubkey, _ := crypto.UnmarshalPubkey(member.Publickey)

		member.Flag = types.StateUsedFlag
		member.MType = types.TypeFixed
		//caolaing modify
		member.CommitteeBase = crypto.PubkeyToAddress(*pubkey)
		///member.CommitteeBase = taipublic.PubkeyToAddress(*pubkey)
	}
	return types.NewBlock(head, nil, nil, nil, committee.Members)
}

// MustFastCommit writes the genesis block and state to db, panicking on error.
// The block is committed as the canonical head block.
func (g *Genesis) MustFastCommit(db taidb.Database) *types.Block {
	block, err := g.CommitFast(db)
	if err != nil {
		panic(err)
	}
	return block
}

// setupSnailGenesisBlock writes or updates the genesis snail block in db.
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
/*func setupSnailGenesisBlock(db etruedb.Database, genesis *Genesis) (*params.ChainConfig, common.Hash, error) {
	if genesis != nil && genesis.Config == nil {
		return params.AllMinervaProtocolChanges, common.Hash{}, errGenesisNoConfig
	}
	// Just commit the new block if there is no stored genesis block.
	stored := snaildb.ReadCanonicalHash(db, 0)
	if (stored == common.Hash{}) {
		if genesis == nil {
			log.Info("Writing default main-net genesis block")
			genesis = DefaultGenesisBlock()
		} else {
			log.Info("Writing custom genesis block")
		}
		block, err := genesis.CommitSnail(db)
		return genesis.Config, block.Hash(), err
	}

	// Check whether the genesis block is already written.
	if genesis != nil {
		hash := genesis.ToSnailBlock(nil).Hash()
		if hash != stored {
			return genesis.Config, hash, &GenesisMismatchError{stored, hash}
		}
	}

	// Get the existing chain configuration.
	newcfg := genesis.configOrDefault(stored)
	return newcfg, stored, nil
}*/

// ToSnailBlock creates the genesis block and writes state of a genesis specification
// to the given database (or discards it if nil).
func (g *Genesis) ToSnailBlock(db taidb.Database) *types.SnailBlock {
	if db == nil {
		db = taidb.NewMemDatabase()
	}

	head := &types.SnailHeader{
		Number:     new(big.Int).SetUint64(g.Number),
		Nonce:      types.EncodeNonce(g.Nonce),
		Time:       new(big.Int).SetUint64(g.Timestamp),
		ParentHash: g.ParentHash,
		Extra:      g.ExtraData,
		Difficulty: g.Difficulty,
		MixDigest:  g.Mixhash,
		Coinbase:   g.Coinbase,
	}

	if g.Difficulty == nil {
		head.Difficulty = params.GenesisDifficulty
		g.Difficulty = params.GenesisDifficulty
	}

	fastBlock := g.ToFastBlock(db)
	fruitHead := &types.SnailHeader{
		Number:          new(big.Int).SetUint64(g.Number),
		Nonce:           types.EncodeNonce(g.Nonce),
		Time:            new(big.Int).SetUint64(g.Timestamp),
		ParentHash:      g.ParentHash,
		FastNumber:      fastBlock.Number(),
		FastHash:        fastBlock.Hash(),
		FruitDifficulty: new(big.Int).Div(g.Difficulty, params.FruitBlockRatio),
		Coinbase:        g.Coinbase,
	}
	fruit := types.NewSnailBlock(fruitHead, nil, nil, nil, g.Config)

	return types.NewSnailBlock(head, []*types.SnailBlock{fruit}, nil, nil, g.Config)
}

// CommitSnail writes the block and state of a genesis specification to the database.
// The block is committed as the canonical head block.
/*func (g *Genesis) CommitSnail(db etruedb.Database) (*types.SnailBlock, error) {
	block := g.ToSnailBlock(db)
	if block.Number().Sign() != 0 {
		return nil, fmt.Errorf("can't commit genesis block with number > 0")
	}
	snaildb.WriteTd(db, block.Hash(), block.NumberU64(), g.Difficulty)
	snaildb.WriteBlock(db, block)
	snaildb.WriteFtLookupEntries(db, block)
	snaildb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	snaildb.WriteHeadBlockHash(db, block.Hash())
	snaildb.WriteHeadHeaderHash(db, block.Hash())

	// config := g.Config
	// if config == nil {
	// 	config = params.AllMinervaProtocolChanges
	// }
	// snaildb.WriteChainConfig(db, block.Hash(), config)
	return block, nil
}*/

// MustSnailCommit writes the genesis block and state to db, panicking on error.
// The block is committed as the canonical head block.
/*func (g *Genesis) MustSnailCommit(db etruedb.Database) *types.SnailBlock {
	block, err := g.CommitSnail(db)
	if err != nil {
		panic(err)
	}
	return block
}
*/
// DefaultGenesisBlock returns the Taiyuechain main net snail block.
func DefaultGenesisBlock() *Genesis {
	i, _ := new(big.Int).SetString("65750000000000000000000000", 10)
	j, _ := new(big.Int).SetString("8250000000000000000000000", 10)
	key1 := hexutil.MustDecode("0x0406e9c1f797fe21229f8146f5ecf837a545e4d7e96dc88903286ce3036f425f307c88418f902c9b08fd07e0aee0f249994cf19819235fd607acd38ce77f777d1a")
	key2 := hexutil.MustDecode("0x04ce1b2f41acdb293408da34a84162bc313be4b8682c183c7bdd4891ac87c514549a14ac564a9de615e7e8eae75441b1332042a2d00160079b2714b4bed1665f29")
	key3 := hexutil.MustDecode("0x045e020f6f27adf1bdc8e682c6fb7a7623d8a5899fa88702d436b18e245e35dd4b573c28565b4105abb48a14d5aa442326c56a9eb2fa3f8509aea3f5625cfd621b")
	key4 := hexutil.MustDecode("0x04028b42cb580bd78579441c96fb25b54b284c3f3258bb7ec9e37828f716cfe2ca4fb3dabc51b3d4215f14715a0999c86ae9ce4bc4e4bccfbcf7b64b6969746fb8")
	key5 := hexutil.MustDecode("0x04a36c5cc785b10b8d5c7f18f6387f511c060ca0760c06b816db5cdb087723d185f034988ce1a117cd81138f7c971d272a6b6e8affa49ccf82df0d0388c644a6c1")
	key6 := hexutil.MustDecode("0x049b240252750233ffb2e2fb0872e9dc8029a0af2a0bf8cb494181eae1f2673d662bbbb56215a42cb509ec42e80b089e2d6be581d084f54efe094a3fba3e990717")
	key7 := hexutil.MustDecode("0x048a0560f53440a84bad6286eb65a756a1a1880492e19f7500e4f3ef760b939b9fafb9e14660ce5fc7a90d45136117690beac13121d22952d054d4727b39764468")
	key8 := hexutil.MustDecode("0x0409e96160f03587376c3dff6a3b2f8d6028afc25668aa653d7f1bfe9eff8fb1165474cb93d8b2f292a6e4364d5447ca28002ae211b1624e33447864511e1d4d5d")
	key9 := hexutil.MustDecode("0x040d721ac02c250be372156b4bf2620e6bec1799c70105705fc8aee7f11a11b2a6697086ca2161176b85b663f2d9b98275644fd3971af5d08fd7f6070f45314f55")
	key10 := hexutil.MustDecode("0x04487dc07260059573abe6e7bf3209c975985c49400092ec246d28cc4d1eb54a6f7f5eb8375a2f7d398f1e0bb75406e5d38451935cc16376ddbac5d057c66a231c")
	key11 := hexutil.MustDecode("0x04f3611f44cd7913fbd2452040716e13c8759743dd44a566e94df1f81078234a45d36259ede0186cbbec3e2e7bd638d7fca1586ddf47d596bb41c668e39021556a")
	key12 := hexutil.MustDecode("0x0465c75fa5e80eabd141b08a4345573d43d582b42aed524025e7dcac4919bc16eee14705f49da7f381747a5196de792ba4a11ede9079a9025e11bcb0930760ef2e")
	key13 := hexutil.MustDecode("0x049a943801bd862f0287eacb8221f13bff351c63b7ab78c9a1f71472ae8a8c28779f32c4dcfd904f36d9edb54d8a0c57462654026cde4f5022fe2d99b63174b9ae")
	key14 := hexutil.MustDecode("0x04c4e01103818ca955c9219000c297c928b02b89d0eb3043886f524d645e20251343bf117d5a1b553708638c7dca8d1a12fb6379ae2d20756b57fdc5052a0dd787")

	return &Genesis{
		Config:     params.MainnetChainConfig,
		Nonce:      330,
		ExtraData:  hexutil.MustDecode("0x54727565436861696E204D61696E4E6574"),
		GasLimit:   16777216,
		Difficulty: big.NewInt(2147483648),
		//Timestamp:  1553918400,
		Coinbase:   common.HexToAddress("0x0000000000000000000000000000000000000000"),
		Mixhash:    common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		ParentHash: common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		//Alloc:      decodePrealloc(mainnetAllocData),
		Alloc: map[common.Address]types.GenesisAccount{
			common.HexToAddress("0xa5F41eaf51d24c8eDcDF254F200f8a6D818a6836"): {Balance: i},
			common.HexToAddress("0xbD1edee3bdD812BB5058Df1F1392dDdd99dE58cc"): {Balance: j},
		},
		Committee: []*types.CommitteeMember{
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xfC5659050350eB76F9Ebcc6c2b1598C3a2fFc625"), Publickey: key1},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xfC5659050350eB76F9Ebcc6c2b1598C3a2fFc625"), Publickey: key2},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xfC5659050350eB76F9Ebcc6c2b1598C3a2fFc625"), Publickey: key3},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xfC5659050350eB76F9Ebcc6c2b1598C3a2fFc625"), Publickey: key4},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xfC5659050350eB76F9Ebcc6c2b1598C3a2fFc625"), Publickey: key5},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xfC5659050350eB76F9Ebcc6c2b1598C3a2fFc625"), Publickey: key6},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xfC5659050350eB76F9Ebcc6c2b1598C3a2fFc625"), Publickey: key7},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xfC5659050350eB76F9Ebcc6c2b1598C3a2fFc625"), Publickey: key8},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xfC5659050350eB76F9Ebcc6c2b1598C3a2fFc625"), Publickey: key9},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xfC5659050350eB76F9Ebcc6c2b1598C3a2fFc625"), Publickey: key10},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xfC5659050350eB76F9Ebcc6c2b1598C3a2fFc625"), Publickey: key11},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xfC5659050350eB76F9Ebcc6c2b1598C3a2fFc625"), Publickey: key12},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xfC5659050350eB76F9Ebcc6c2b1598C3a2fFc625"), Publickey: key13},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xfC5659050350eB76F9Ebcc6c2b1598C3a2fFc625"), Publickey: key14},
		},
	}
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

// GenesisFastBlockForTesting creates and writes a block in which addr has the given wei balance.
func GenesisFastBlockForTesting(db taidb.Database, addr common.Address, balance *big.Int) *types.Block {
	g := Genesis{Alloc: types.GenesisAlloc{addr: {Balance: balance}}, Config: params.AllMinervaProtocolChanges}
	return g.MustFastCommit(db)
}

// GenesisSnailBlockForTesting creates and writes a block in which addr has the given wei balance.
func GenesisSnailBlockForTesting(db taidb.Database, addr common.Address, balance *big.Int) *types.SnailBlock {
	//g := Genesis{Alloc: types.GenesisAlloc{addr: {Balance: balance}}, Config: params.AllMinervaProtocolChanges}
	//return g.MustSnailCommit(db)
	return nil
}

// DefaultDevGenesisBlock returns the Rinkeby network genesis block.
func DefaultDevGenesisBlock() *Genesis {
	i, _ := new(big.Int).SetString("90000000000000000000000", 10)

	return &Genesis{
		Config:     params.DevnetChainConfig,
		Nonce:      928,
		ExtraData:  nil,
		GasLimit:   88080384,
		Difficulty: big.NewInt(20000),
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
		//"0x04044308742b61976de7344edb8662d6d10be1c477dd46e8e4c433c1288442a79183480894107299ff7b0706490f1fb9c9b7c9e62ae62d57bd84a1e469460d8ac1")
		"0x04bdf9699d20b4ebabe76e76260480e5492c87aaeda51b138bd22c6d66b69549313dc3eb8c96dc9a1cbbf3b347322c51c05afdd609622277444e0f07e6bd35d8bd")

	return &Genesis{
		Config:     params.SingleNodeChainConfig,
		Nonce:      66,
		ExtraData:  nil,
		GasLimit:   22020096,
		Difficulty: big.NewInt(256),
		//Alloc:      decodePrealloc(mainnetAllocData),
		Alloc: map[common.Address]types.GenesisAccount{
			common.HexToAddress("0xbd54a6c8298a70e9636d0555a77ffa412abdd71a"): {Balance: i},
			common.HexToAddress("0x3c2e0a65a023465090aaedaa6ed2975aec9ef7f9"): {Balance: i},
			common.HexToAddress("0x7c357530174275dd30e46319b89f71186256e4f7"): {Balance: i},
			common.HexToAddress("0xeeb69c67751e9f4917b605840fa9a28be4517871"): {Balance: i},
			common.HexToAddress("0x9810a954bb88fdc251374d666ed7e06748ea672d"): {Balance: i},
		},
		Committee: []*types.CommitteeMember{
			{Coinbase: common.HexToAddress("0x76ea2f3a002431fede1141b660dbb75c26ba6d97"),
				Publickey: key1},
		},
	}
}

// DefaultTestnetGenesisBlock returns the Ropsten network genesis block.
func DefaultTestnetGenesisBlock() *Genesis {
	seedkey1 := hexutil.MustDecode("0x04bdf9699d20b4ebabe76e76260480e5492c87aaeda51b138bd22c6d66b69549313dc3eb8c96dc9a1cbbf3b347322c51c05afdd609622277444e0f07e6bd35d8bd")
	seedkey2 := hexutil.MustDecode("0x045e1711b6cd8550a5e5466f7f0868b5507929cb69c2f0fca84f8f94816eb40a808ea8a77c3d83c9d16341acb037fbea2f7d9d4af46326defa39b408f40f28fb98")
	seedkey3 := hexutil.MustDecode("0x041b931d350257e881f27bce2563d98c99b13ca4f525a0662f5e7d53f085edff0dca8ceaae550c9f4ceecf217f72806a48a48fb024916392ae41d7c45168e89b94")
	seedkey4 := hexutil.MustDecode("0x049923777d866fd80485be57a126d638cc7dda78a5d6958aff784ca7ed9d9c7be494125bf75fd0328490ae51020274427b9fbb07f59e4c9b5104ac6924721a4438")

	/*	cert1 := []byte{48, 130, 2, 142, 48, 130, 2, 58, 160, 3, 2, 1, 2, 2, 1, 255, 48, 10, 6, 8, 42, 129, 28, 207, 85, 1, 131, 117, 48, 48, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12, 10, 206, 163, 32, 65, 99, 109, 101, 32, 67, 111, 49, 25, 48, 23, 6, 3, 85, 4, 3, 19, 16, 116, 101, 115, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 30, 23, 13, 50, 48, 48, 53, 49, 50, 49, 49, 49, 57, 49, 54, 90, 23, 13, 50, 51, 48, 55, 49, 51, 50, 49, 48, 53, 53, 54, 90, 48, 48, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12, 10, 206, 163, 32, 65, 99, 109, 101, 32, 67, 111, 49, 25, 48, 23, 6, 3, 85, 4, 3, 19, 16, 116, 101, 115, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 129, 28, 207, 85, 1, 130, 45, 3, 66, 0, 4, 189, 249, 105, 157, 32, 180, 235, 171, 231, 110, 118, 38, 4, 128, 229, 73, 44, 135, 170, 237, 165, 27, 19, 139, 210, 44, 109, 102, 182, 149, 73, 49, 61, 195, 235, 140, 150, 220, 154, 28, 187, 243, 179, 71, 50, 44, 81, 192, 90, 253, 214, 9, 98, 34, 119, 68, 78, 15, 7, 230, 189, 53, 216, 189, 163, 130, 1, 67, 48, 130, 1, 63, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 4, 48, 38, 6, 3, 85, 29, 37, 4, 31, 48, 29, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 2, 42, 3, 6, 3, 129, 11, 1, 48, 15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3, 1, 1, 255, 48, 13, 6, 3, 85, 29, 14, 4, 6, 4, 4, 1, 2, 3, 4, 48, 95, 6, 8, 43, 6, 1, 5, 5, 7, 1, 1, 4, 83, 48, 81, 48, 35, 6, 8, 43, 6, 1, 5, 5, 7, 48, 1, 134, 23, 104, 116, 116, 112, 58, 47, 47, 111, 99, 115, 112, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 42, 6, 8, 43, 6, 1, 5, 5, 7, 48, 2, 134, 30, 104, 116, 116, 112, 58, 47, 47, 99, 114, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 116, 48, 26, 6, 3, 85, 29, 17, 4, 19, 48, 17, 130, 15, 102, 111, 111, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 15, 6, 3, 85, 29, 32, 4, 8, 48, 6, 48, 4, 6, 2, 42, 3, 48, 87, 6, 3, 85, 29, 31, 4, 80, 48, 78, 48, 37, 160, 35, 160, 33, 134, 31, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 49, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 108, 48, 37, 160, 35, 160, 33, 134, 31, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 50, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 108, 48, 10, 6, 8, 42, 129, 28, 207, 85, 1, 131, 117, 3, 66, 0, 131, 46, 82, 7, 238, 174, 229, 35, 21, 9, 185, 1, 207, 0, 140, 155, 37, 5, 51, 144, 102, 3, 144, 159, 133, 0, 25, 187, 107, 235, 88, 78, 120, 10, 180, 88, 86, 170, 145, 143, 188, 203, 241, 77, 36, 181, 65, 77, 101, 184, 110, 46, 241, 7, 57, 140, 91, 148, 142, 69, 22, 227, 8, 201, 104}
		cert2 := []byte{48, 130, 2, 142, 48, 130, 2, 58, 160, 3, 2, 1, 2, 2, 1, 255, 48, 10, 6, 8, 42, 129, 28, 207, 85, 1, 131, 117, 48, 48, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12, 10, 206, 163, 32, 65, 99, 109, 101, 32, 67, 111, 49, 25, 48, 23, 6, 3, 85, 4, 3, 19, 16, 116, 101, 115, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 30, 23, 13, 50, 48, 48, 53, 49, 50, 49, 49, 49, 57, 49, 54, 90, 23, 13, 50, 51, 48, 55, 49, 51, 50, 49, 48, 53, 53, 54, 90, 48, 48, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12, 10, 206, 163, 32, 65, 99, 109, 101, 32, 67, 111, 49, 25, 48, 23, 6, 3, 85, 4, 3, 19, 16, 116, 101, 115, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 129, 28, 207, 85, 1, 130, 45, 3, 66, 0, 4, 94, 23, 17, 182, 205, 133, 80, 165, 229, 70, 111, 127, 8, 104, 181, 80, 121, 41, 203, 105, 194, 240, 252, 168, 79, 143, 148, 129, 110, 180, 10, 128, 142, 168, 167, 124, 61, 131, 201, 209, 99, 65, 172, 176, 55, 251, 234, 47, 125, 157, 74, 244, 99, 38, 222, 250, 57, 180, 8, 244, 15, 40, 251, 152, 163, 130, 1, 67, 48, 130, 1, 63, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 4, 48, 38, 6, 3, 85, 29, 37, 4, 31, 48, 29, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 2, 42, 3, 6, 3, 129, 11, 1, 48, 15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3, 1, 1, 255, 48, 13, 6, 3, 85, 29, 14, 4, 6, 4, 4, 1, 2, 3, 4, 48, 95, 6, 8, 43, 6, 1, 5, 5, 7, 1, 1, 4, 83, 48, 81, 48, 35, 6, 8, 43, 6, 1, 5, 5, 7, 48, 1, 134, 23, 104, 116, 116, 112, 58, 47, 47, 111, 99, 115, 112, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 42, 6, 8, 43, 6, 1, 5, 5, 7, 48, 2, 134, 30, 104, 116, 116, 112, 58, 47, 47, 99, 114, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 116, 48, 26, 6, 3, 85, 29, 17, 4, 19, 48, 17, 130, 15, 102, 111, 111, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 15, 6, 3, 85, 29, 32, 4, 8, 48, 6, 48, 4, 6, 2, 42, 3, 48, 87, 6, 3, 85, 29, 31, 4, 80, 48, 78, 48, 37, 160, 35, 160, 33, 134, 31, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 49, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 108, 48, 37, 160, 35, 160, 33, 134, 31, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 50, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 108, 48, 10, 6, 8, 42, 129, 28, 207, 85, 1, 131, 117, 3, 66, 0, 54, 1, 43, 195, 143, 59, 59, 1, 217, 61, 117, 20, 211, 235, 240, 170, 36, 249, 228, 206, 10, 160, 246, 47, 38, 23, 140, 33, 150, 164, 210, 130, 163, 224, 124, 78, 241, 143, 7, 36, 39, 218, 139, 125, 36, 68, 65, 212, 170, 159, 86, 100, 223, 212, 24, 109, 113, 24, 210, 220, 210, 190, 190, 240, 27}
		cert3 := []byte{48, 130, 2, 142, 48, 130, 2, 58, 160, 3, 2, 1, 2, 2, 1, 255, 48, 10, 6, 8, 42, 129, 28, 207, 85, 1, 131, 117, 48, 48, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12, 10, 206, 163, 32, 65, 99, 109, 101, 32, 67, 111, 49, 25, 48, 23, 6, 3, 85, 4, 3, 19, 16, 116, 101, 115, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 30, 23, 13, 50, 48, 48, 53, 49, 50, 49, 49, 49, 57, 49, 54, 90, 23, 13, 50, 51, 48, 55, 49, 51, 50, 49, 48, 53, 53, 54, 90, 48, 48, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12, 10, 206, 163, 32, 65, 99, 109, 101, 32, 67, 111, 49, 25, 48, 23, 6, 3, 85, 4, 3, 19, 16, 116, 101, 115, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 129, 28, 207, 85, 1, 130, 45, 3, 66, 0, 4, 27, 147, 29, 53, 2, 87, 232, 129, 242, 123, 206, 37, 99, 217, 140, 153, 177, 60, 164, 245, 37, 160, 102, 47, 94, 125, 83, 240, 133, 237, 255, 13, 202, 140, 234, 174, 85, 12, 159, 76, 238, 207, 33, 127, 114, 128, 106, 72, 164, 143, 176, 36, 145, 99, 146, 174, 65, 215, 196, 81, 104, 232, 155, 148, 163, 130, 1, 67, 48, 130, 1, 63, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 4, 48, 38, 6, 3, 85, 29, 37, 4, 31, 48, 29, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 2, 42, 3, 6, 3, 129, 11, 1, 48, 15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3, 1, 1, 255, 48, 13, 6, 3, 85, 29, 14, 4, 6, 4, 4, 1, 2, 3, 4, 48, 95, 6, 8, 43, 6, 1, 5, 5, 7, 1, 1, 4, 83, 48, 81, 48, 35, 6, 8, 43, 6, 1, 5, 5, 7, 48, 1, 134, 23, 104, 116, 116, 112, 58, 47, 47, 111, 99, 115, 112, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 42, 6, 8, 43, 6, 1, 5, 5, 7, 48, 2, 134, 30, 104, 116, 116, 112, 58, 47, 47, 99, 114, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 116, 48, 26, 6, 3, 85, 29, 17, 4, 19, 48, 17, 130, 15, 102, 111, 111, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 15, 6, 3, 85, 29, 32, 4, 8, 48, 6, 48, 4, 6, 2, 42, 3, 48, 87, 6, 3, 85, 29, 31, 4, 80, 48, 78, 48, 37, 160, 35, 160, 33, 134, 31, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 49, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 108, 48, 37, 160, 35, 160, 33, 134, 31, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 50, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 108, 48, 10, 6, 8, 42, 129, 28, 207, 85, 1, 131, 117, 3, 66, 0, 23, 99, 174, 106, 168, 143, 97, 153, 142, 22, 9, 195, 162, 11, 204, 116, 48, 40, 149, 188, 129, 27, 73, 87, 44, 255, 22, 78, 131, 126, 150, 132, 56, 217, 250, 135, 153, 217, 27, 154, 225, 182, 2, 128, 193, 77, 27, 112, 199, 26, 195, 78, 146, 192, 47, 101, 168, 118, 251, 254, 110, 238, 154, 61, 252}
		cert4 := []byte{48, 130, 2, 142, 48, 130, 2, 58, 160, 3, 2, 1, 2, 2, 1, 255, 48, 10, 6, 8, 42, 129, 28, 207, 85, 1, 131, 117, 48, 48, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12, 10, 206, 163, 32, 65, 99, 109, 101, 32, 67, 111, 49, 25, 48, 23, 6, 3, 85, 4, 3, 19, 16, 116, 101, 115, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 30, 23, 13, 50, 48, 48, 53, 49, 50, 49, 49, 49, 57, 49, 54, 90, 23, 13, 50, 51, 48, 55, 49, 51, 50, 49, 48, 53, 53, 54, 90, 48, 48, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12, 10, 206, 163, 32, 65, 99, 109, 101, 32, 67, 111, 49, 25, 48, 23, 6, 3, 85, 4, 3, 19, 16, 116, 101, 115, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 129, 28, 207, 85, 1, 130, 45, 3, 66, 0, 4, 153, 35, 119, 125, 134, 111, 216, 4, 133, 190, 87, 161, 38, 214, 56, 204, 125, 218, 120, 165, 214, 149, 138, 255, 120, 76, 167, 237, 157, 156, 123, 228, 148, 18, 91, 247, 95, 208, 50, 132, 144, 174, 81, 2, 2, 116, 66, 123, 159, 187, 7, 245, 158, 76, 155, 81, 4, 172, 105, 36, 114, 26, 68, 56, 163, 130, 1, 67, 48, 130, 1, 63, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 4, 48, 38, 6, 3, 85, 29, 37, 4, 31, 48, 29, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 2, 42, 3, 6, 3, 129, 11, 1, 48, 15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3, 1, 1, 255, 48, 13, 6, 3, 85, 29, 14, 4, 6, 4, 4, 1, 2, 3, 4, 48, 95, 6, 8, 43, 6, 1, 5, 5, 7, 1, 1, 4, 83, 48, 81, 48, 35, 6, 8, 43, 6, 1, 5, 5, 7, 48, 1, 134, 23, 104, 116, 116, 112, 58, 47, 47, 111, 99, 115, 112, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 42, 6, 8, 43, 6, 1, 5, 5, 7, 48, 2, 134, 30, 104, 116, 116, 112, 58, 47, 47, 99, 114, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 116, 48, 26, 6, 3, 85, 29, 17, 4, 19, 48, 17, 130, 15, 102, 111, 111, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 48, 15, 6, 3, 85, 29, 32, 4, 8, 48, 6, 48, 4, 6, 2, 42, 3, 48, 87, 6, 3, 85, 29, 31, 4, 80, 48, 78, 48, 37, 160, 35, 160, 33, 134, 31, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 49, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 108, 48, 37, 160, 35, 160, 33, 134, 31, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 50, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 99, 97, 49, 46, 99, 114, 108, 48, 10, 6, 8, 42, 129, 28, 207, 85, 1, 131, 117, 3, 66, 0, 73, 105, 46, 107, 12, 203, 248, 158, 67, 242, 104, 99, 83, 203, 126, 29, 111, 44, 140, 197, 57, 122, 49, 73, 25, 32, 96, 22, 151, 95, 174, 87, 52, 219, 117, 204, 227, 227, 32, 6, 11, 152, 89, 254, 173, 69, 140, 8, 156, 233, 7, 38, 117, 88, 223, 205, 150, 34, 231, 133, 66, 105, 110, 244, 46}*/
	strcert1 := "3082028e3082023aa0030201020201ff300a06082a811ccf55018375303031133011060355040a0c0acea32041636d6520436f3119301706035504031310746573742e6578616d706c652e636f6d301e170d3230303630313034313133385a170d3233303830323133353831385a303031133011060355040a0c0acea32041636d6520436f3119301706035504031310746573742e6578616d706c652e636f6d3059301306072a8648ce3d020106082a811ccf5501822d03420004bdf9699d20b4ebabe76e76260480e5492c87aaeda51b138bd22c6d66b69549313dc3eb8c96dc9a1cbbf3b347322c51c05afdd609622277444e0f07e6bd35d8bda38201433082013f300e0603551d0f0101ff04040302020430260603551d25041f301d06082b0601050507030206082b0601050507030106022a030603810b01300f0603551d130101ff040530030101ff300d0603551d0e0406040401020304305f06082b0601050507010104533051302306082b060105050730018617687474703a2f2f6f6373702e6578616d706c652e636f6d302a06082b06010505073002861e687474703a2f2f6372742e6578616d706c652e636f6d2f6361312e637274301a0603551d1104133011820f666f6f2e6578616d706c652e636f6d300f0603551d2004083006300406022a0330570603551d1f0450304e3025a023a021861f687474703a2f2f63726c312e6578616d706c652e636f6d2f6361312e63726c3025a023a021861f687474703a2f2f63726c322e6578616d706c652e636f6d2f6361312e63726c300a06082a811ccf550183750342008851ca997c3b35b6de11fa5e43d04dfb76cd4177c4517e60f72db9373fec1a3731c46b70b562240a1cbd98e22dec6e1fd857e6b88fee893897c39e61e9bb502c01"
	strcert2 := "3082028e3082023aa0030201020201ff300a06082a811ccf55018375303031133011060355040a0c0acea32041636d6520436f3119301706035504031310746573742e6578616d706c652e636f6d301e170d3230303630313034313134335a170d3233303830323133353832335a303031133011060355040a0c0acea32041636d6520436f3119301706035504031310746573742e6578616d706c652e636f6d3059301306072a8648ce3d020106082a811ccf5501822d034200045e1711b6cd8550a5e5466f7f0868b5507929cb69c2f0fca84f8f94816eb40a808ea8a77c3d83c9d16341acb037fbea2f7d9d4af46326defa39b408f40f28fb98a38201433082013f300e0603551d0f0101ff04040302020430260603551d25041f301d06082b0601050507030206082b0601050507030106022a030603810b01300f0603551d130101ff040530030101ff300d0603551d0e0406040401020304305f06082b0601050507010104533051302306082b060105050730018617687474703a2f2f6f6373702e6578616d706c652e636f6d302a06082b06010505073002861e687474703a2f2f6372742e6578616d706c652e636f6d2f6361312e637274301a0603551d1104133011820f666f6f2e6578616d706c652e636f6d300f0603551d2004083006300406022a0330570603551d1f0450304e3025a023a021861f687474703a2f2f63726c312e6578616d706c652e636f6d2f6361312e63726c3025a023a021861f687474703a2f2f63726c322e6578616d706c652e636f6d2f6361312e63726c300a06082a811ccf55018375034200626bafd3a7e8a296305bba2e097c340c48345fafd02eb305721c08c808cf9456728a64a8f2b5af08caa36c24b1f994c918ece5aa90efb859e81dc6dd4111591f03"
	strcert3 := "3082028e3082023aa0030201020201ff300a06082a811ccf55018375303031133011060355040a0c0acea32041636d6520436f3119301706035504031310746573742e6578616d706c652e636f6d301e170d3230303630313034313134345a170d3233303830323133353832345a303031133011060355040a0c0acea32041636d6520436f3119301706035504031310746573742e6578616d706c652e636f6d3059301306072a8648ce3d020106082a811ccf5501822d034200041b931d350257e881f27bce2563d98c99b13ca4f525a0662f5e7d53f085edff0dca8ceaae550c9f4ceecf217f72806a48a48fb024916392ae41d7c45168e89b94a38201433082013f300e0603551d0f0101ff04040302020430260603551d25041f301d06082b0601050507030206082b0601050507030106022a030603810b01300f0603551d130101ff040530030101ff300d0603551d0e0406040401020304305f06082b0601050507010104533051302306082b060105050730018617687474703a2f2f6f6373702e6578616d706c652e636f6d302a06082b06010505073002861e687474703a2f2f6372742e6578616d706c652e636f6d2f6361312e637274301a0603551d1104133011820f666f6f2e6578616d706c652e636f6d300f0603551d2004083006300406022a0330570603551d1f0450304e3025a023a021861f687474703a2f2f63726c312e6578616d706c652e636f6d2f6361312e63726c3025a023a021861f687474703a2f2f63726c322e6578616d706c652e636f6d2f6361312e63726c300a06082a811ccf550183750342000c17b347c9fe8d7721bcbebdbe111ebe9c41841a9dc87d2043efc45269c130878cb7dfb84804373070e1a8a19cd2a6d0b06b4db580e50c6030ea16232c814b5c01"
	strcert4 := "3082028e3082023aa0030201020201ff300a06082a811ccf55018375303031133011060355040a0c0acea32041636d6520436f3119301706035504031310746573742e6578616d706c652e636f6d301e170d3230303630313034313134345a170d3233303830323133353832345a303031133011060355040a0c0acea32041636d6520436f3119301706035504031310746573742e6578616d706c652e636f6d3059301306072a8648ce3d020106082a811ccf5501822d034200049923777d866fd80485be57a126d638cc7dda78a5d6958aff784ca7ed9d9c7be494125bf75fd0328490ae51020274427b9fbb07f59e4c9b5104ac6924721a4438a38201433082013f300e0603551d0f0101ff04040302020430260603551d25041f301d06082b0601050507030206082b0601050507030106022a030603810b01300f0603551d130101ff040530030101ff300d0603551d0e0406040401020304305f06082b0601050507010104533051302306082b060105050730018617687474703a2f2f6f6373702e6578616d706c652e636f6d302a06082b06010505073002861e687474703a2f2f6372742e6578616d706c652e636f6d2f6361312e637274301a0603551d1104133011820f666f6f2e6578616d706c652e636f6d300f0603551d2004083006300406022a0330570603551d1f0450304e3025a023a021861f687474703a2f2f63726c312e6578616d706c652e636f6d2f6361312e63726c3025a023a021861f687474703a2f2f63726c322e6578616d706c652e636f6d2f6361312e63726c300a06082a811ccf550183750342005eaa2519c0ef76a2243d08caa7b0306a11238d64b080d0b5d300e56aad312856fbef8394703b51e8faa7996cfa69923927253f6fe5e2ff7587f661f967ca7d3b01"
	cert1, _ := hex.DecodeString(strcert1)
	cert2, _ := hex.DecodeString(strcert2)
	cert3, _ := hex.DecodeString(strcert3)
	cert4, _ := hex.DecodeString(strcert4)
	var certList = [][]byte{cert1, cert2, cert3, cert4}
	coinbase := common.HexToAddress("0x9331cf34D0e3E43bce7de1bFd30a59d3EEc106B6")
	amount1, _ := new(big.Int).SetString("24000000000000000000000000", 10)
	return &Genesis{
		Config:     params.TestnetChainConfig,
		Nonce:      928,
		ExtraData:  hexutil.MustDecode("0x54727565436861696E20546573744E6574203035"),
		GasLimit:   20971520,
		Difficulty: big.NewInt(100000),
		Timestamp:  1537891200,
		Coinbase:   common.HexToAddress("0x0000000000000000000000000000000000000000"),
		Mixhash:    common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		ParentHash: common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		Alloc: map[common.Address]types.GenesisAccount{
			common.HexToAddress("0x9331cf34D0e3E43bce7de1bFd30a59d3EEc106B6"): {Balance: amount1},
		},
		Committee: []*types.CommitteeMember{
			&types.CommitteeMember{Coinbase: coinbase, Publickey: seedkey1, LocalCert: cert1},
			&types.CommitteeMember{Coinbase: coinbase, Publickey: seedkey2, LocalCert: cert2},
			&types.CommitteeMember{Coinbase: coinbase, Publickey: seedkey3, LocalCert: cert3},
			&types.CommitteeMember{Coinbase: coinbase, Publickey: seedkey4, LocalCert: cert4},
		},
		CertList: certList,
	}
}
