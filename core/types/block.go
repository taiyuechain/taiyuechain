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

// Package types contains data types related to taiyuechain consensus.
package types

import (
	//"crypto/ecdsa"
	//"crypto/ecdsa"
	"encoding/binary"
	"io"
	"math/big"
	"sort"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/taiyuechain/taiyuechain/crypto"

	"bytes"

	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/common/hexutil"
	"github.com/taiyuechain/taiyuechain/rlp"
)

var (
	EmptyRootHash  = DeriveSha(Transactions{})
	EmptyUncleHash = CalcUncleHash(nil)
	EmptySignHash  = CalcSignHash(nil)
)

// A BlockNonce is a 64-bit hash which proves (combined with the
// mix-hash) that a sufficient amount of computation has been carried
// out on a block.
type BlockNonce [8]byte

// EncodeNonce converts the given integer to a block nonce.
func EncodeNonce(i uint64) BlockNonce {
	var n BlockNonce
	binary.BigEndian.PutUint64(n[:], i)
	return n
}

// Uint64 returns the integer value of a block nonce.
func (n BlockNonce) Uint64() uint64 {
	return binary.BigEndian.Uint64(n[:])
}

// MarshalText encodes n as a hex string with 0x prefix.
func (n BlockNonce) MarshalText() ([]byte, error) {
	return hexutil.Bytes(n[:]).MarshalText()
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (n *BlockNonce) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedText("BlockNonce", input, n[:])
}

type writeCounter common.StorageSize

func (c *writeCounter) Write(b []byte) (int, error) {
	*c += writeCounter(len(b))
	return len(b), nil
}

func CalcUncleHash(uncles []*Header) common.Hash {
	return rlpHash(uncles)
}

func CalcSignHash(signs []*PbftSign) common.Hash {
	return rlpHash(signs)
}

type Blocks []*Block

type BlockBy func(b1, b2 *Block) bool

func (self BlockBy) Sort(blocks Blocks) {
	bs := blockSorter{
		blocks: blocks,
		by:     self,
	}
	sort.Sort(bs)
}

type blockSorter struct {
	blocks Blocks
	by     func(b1, b2 *Block) bool
}

func (self blockSorter) Len() int { return len(self.blocks) }
func (self blockSorter) Swap(i, j int) {
	self.blocks[i], self.blocks[j] = self.blocks[j], self.blocks[i]
}
func (self blockSorter) Less(i, j int) bool { return self.by(self.blocks[i], self.blocks[j]) }

func Number(b1, b2 *Block) bool { return b1.header.Number.Cmp(b2.header.Number) < 0 }

////////////////////////////////////////////////////////////////////////////////

// fast chain block structure
//go:generate gencodec -type Header -field-override headerMarshaling -out gen_header_json.go

// Header represents a block header in the true blockchain.
type Header struct {
	ParentHash    common.Hash    `json:"parentHash"       gencodec:"required"`
	Root          common.Hash    `json:"stateRoot"        gencodec:"required"`
	TxHash        common.Hash    `json:"transactionsRoot" gencodec:"required"`
	ReceiptHash   common.Hash    `json:"receiptsRoot"     gencodec:"required"`
	CommitteeHash common.Hash    `json:"committeeRoot"    gencodec:"required"`
	Proposer      common.Address `json:"maker"            gencodec:"required"`
	Bloom         Bloom          `json:"logsBloom"        gencodec:"required"`
	SnailHash     common.Hash    `json:"snailHash"        gencodec:"required"`
	SnailNumber   *big.Int       `json:"snailNumber"      gencodec:"required"`
	Number        *big.Int       `json:"number"           gencodec:"required"`
	GasLimit      uint64         `json:"gasLimit"         gencodec:"required"`
	GasUsed       uint64         `json:"gasUsed"          gencodec:"required"`
	Time          *big.Int       `json:"timestamp"        gencodec:"required"`
	Extra         []byte         `json:"extraData"        gencodec:"required"`
}

// field type overrides for gencodec
type headerMarshaling struct {
	SnailNumber *hexutil.Big
	Number      *hexutil.Big
	GasLimit    hexutil.Uint64
	GasUsed     hexutil.Uint64
	Time        *hexutil.Big
	Extra       hexutil.Bytes
	Hash        common.Hash `json:"hash"` // adds call to Hash() in MarshalJSON
}

// Hash returns the block hash of the header, which is simply the keccak256 hash of its
// RLP encoding.
func (h *Header) Hash() common.Hash {
	return rlpHash(h)
}

// SanityCheck checks a few basic things -- these checks are way beyond what
// any 'sane' production values should hold, and can mainly be used to prevent
// that the unbounded fields are stuffed with junk data to add processing
// overhead
func (h *Header) SanityCheck() error {
	if h.Number != nil && !h.Number.IsUint64() {
		//return fmt.Errorf("too large block number: bitlen %d", h.Number.BitLen())
	}

	if eLen := len(h.Extra); eLen > 100*1024 {
		//return fmt.Errorf("too large block extradata: size %d", eLen)
	}
	return nil
}

// Size returns the approximate memory used by all internal contents. It is used
// to approximate and limit the memory consumption of various caches.
func (h *Header) Size() common.StorageSize {
	return common.StorageSize(unsafe.Sizeof(*h)) + common.StorageSize(len(h.Extra)+
		(h.SnailNumber.BitLen()+h.Number.BitLen()+h.Time.BitLen())/8)
}

func rlpHash(x interface{}) (h common.Hash) {
	return crypto.RlpHash(x)
}

// Body is a simple (mutable, non-safe) data container for storing and moving
// a block's data contents (transactions and uncles) together.
type Body struct {
	Transactions []*Transaction
	Signs        []*PbftSign
	Infos        []*CommitteeMember
}

// Block represents an entire block in the taiyuechain blockchain.
type Block struct {
	header       *Header
	transactions Transactions

	signs PbftSigns
	infos CommitteeMembers
	// caches
	hash atomic.Value
	size atomic.Value

	// Td is used by package core to store the total difficulty
	// of the chain up to and including the block.
	// td *big.Int

	// These fields are used by package etrue to track
	// inter-peer block relay.
	ReceivedAt   time.Time
	ReceivedFrom interface{}
}

// NewBlock creates a new fast block. The input data is copied,
// changes to header and to the field values will not affect the
// block.
//
// The values of TxHash, ReceiptHash and Bloom in header
// are ignored and set to values derived from the given txs
// and receipts.
func NewBlock(header *Header, txs []*Transaction, receipts []*Receipt, signs []*PbftSign, infos []*CommitteeMember) *Block {
	b := &Block{
		header: CopyHeader(header),
	}

	// TODO: panic if len(txs) != len(receipts)
	if len(txs) == 0 {
		b.header.TxHash = EmptyRootHash
	} else {
		b.header.TxHash = DeriveSha(Transactions(txs))
		b.transactions = make(Transactions, len(txs))
		copy(b.transactions, txs)
	}

	if len(receipts) == 0 {
		b.header.ReceiptHash = EmptyRootHash
	} else {
		b.header.ReceiptHash = DeriveSha(Receipts(receipts))
		b.header.Bloom = CreateBloom(receipts)
	}

	if len(signs) != 0 {
		b.signs = make(PbftSigns, len(signs))
		copy(b.signs, signs)
	}
	if len(infos) != 0 {
		b.infos = make([]*CommitteeMember, len(infos))
		copy(b.infos, infos)
	}
	b.header.CommitteeHash = rlpHash(b.infos)
	return b
}

// SetLeaderSign keep the sign on the head for proposal
func (b *Body) SetLeaderSign(sign *PbftSign) {
	signP := *sign
	b.Signs = []*PbftSign{}
	b.Signs = append(b.Signs, &signP)
}

// GetLeaderSign get the sign for proposal
func (b *Body) GetLeaderSign() *PbftSign {
	if len(b.Signs) > 0 {
		return b.Signs[0]
	}
	return nil
}

// GetSwitchInfo get info for shift committee
func (b *Body) GetSwitchInfo() []*CommitteeMember {
	return b.Infos
}

// SetSwitchInfo set info for shift committee
func (b *Body) SetSwitchInfo(infos []*CommitteeMember) {
	b.Infos = infos
}

// NewBlockWithHeader creates a fast block with the given header data. The
// header data is copied, changes to header and to the field values
// will not affect the block.
func NewBlockWithHeader(header *Header) *Block {
	return &Block{header: CopyHeader(header)}
}

// CopyHeader creates a deep copy of a fast block header to prevent side effects from
// modifying a header variable.
func CopyHeader(h *Header) *Header {
	cpy := *h
	if cpy.Time = new(big.Int); h.Time != nil {
		cpy.Time.Set(h.Time)
	}
	if cpy.SnailNumber = new(big.Int); h.SnailNumber != nil {
		cpy.SnailNumber.Set(h.SnailNumber)
	}
	if cpy.Number = new(big.Int); h.Number != nil {
		cpy.Number.Set(h.Number)
	}
	if len(h.Extra) > 0 {
		cpy.Extra = make([]byte, len(h.Extra))
		copy(cpy.Extra, h.Extra)
	}
	return &cpy
}

// "external" block encoding. used for etrue protocol, etc.
type extblock struct {
	Header *Header
	Txs    []*Transaction
	Signs  []*PbftSign
	Infos  []*CommitteeMember
}

// DecodeRLP decodes the taiyuechain
func (b *Block) DecodeRLP(s *rlp.Stream) error {
	var eb extblock
	_, size, _ := s.Kind()
	if err := s.Decode(&eb); err != nil {
		return err
	}
	b.header, b.transactions, b.signs, b.infos = eb.Header, eb.Txs, eb.Signs, eb.Infos
	b.size.Store(common.StorageSize(rlp.ListSize(size)))
	return nil
}

// EncodeRLP serializes b into the taiyuechain RLP block format.
func (b *Block) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, extblock{
		Header: b.header,
		Txs:    b.transactions,
		Signs:  b.signs,
		Infos:  b.infos,
	})
}

func (b *Block) Transactions() Transactions { return b.transactions }
func (b *Block) SignedHash() common.Hash    { return rlpHash([]interface{}{b.header, b.transactions}) }
func (b *Block) Transaction(hash common.Hash) *Transaction {
	for _, transaction := range b.transactions {
		if transaction.Hash() == hash {
			return transaction
		}
	}
	return nil
}
func (b *Block) Number() *big.Int      { return new(big.Int).Set(b.header.Number) }
func (b *Block) GasLimit() uint64      { return b.header.GasLimit }
func (b *Block) GasUsed() uint64       { return b.header.GasUsed }
func (b *Block) SnailNumber() *big.Int { return new(big.Int).Set(b.header.SnailNumber) }
func (b *Block) Time() *big.Int        { return new(big.Int).Set(b.header.Time) }

func (b *Block) Proposer() common.Address        { return b.header.Proposer }
func (b *Block) NumberU64() uint64               { return b.header.Number.Uint64() }
func (b *Block) SnailHash() common.Hash          { return b.header.SnailHash }
func (b *Block) Bloom() Bloom                    { return b.header.Bloom }
func (b *Block) Coinbase() common.Address        { return common.Address{} }
func (b *Block) Root() common.Hash               { return b.header.Root }
func (b *Block) ParentHash() common.Hash         { return b.header.ParentHash }
func (b *Block) TxHash() common.Hash             { return b.header.TxHash }
func (b *Block) ReceiptHash() common.Hash        { return b.header.ReceiptHash }
func (b *Block) UncleHash() common.Hash          { return common.Hash{} }
func (b *Block) Extra() []byte                   { return common.CopyBytes(b.header.Extra) }
func (b *Block) Signs() []*PbftSign              { return b.signs }
func (b *Block) Header() *Header                 { return CopyHeader(b.header) }
func (b *Block) CommitteeHash() common.Hash      { return b.header.CommitteeHash }
func (b *Block) SwitchInfos() []*CommitteeMember { return b.infos }

// Body returns the non-header content of the block.
func (b *Block) Body() *Body { return &Body{b.transactions, b.signs, b.infos} }

func (b *Block) AppendSign(sign *PbftSign) {
	signP := CopyPbftSign(sign)
	b.signs = append(b.signs, signP)
}

func (b *Block) SetSign(signs []*PbftSign) {
	b.signs = append(make([]*PbftSign, 0), signs...)
}

func (b *Block) AppendSigns(signs []*PbftSign) {
	if len(b.signs) <= 0 {
		b.signs = signs
		return
	}

	signP := CopyPbftSign(b.signs[0])
	signN := make([]*PbftSign, 0, len(signs))
	signN = append(signN, signP)
	for _, sign := range signs {
		if bytes.Equal(sign.Sign, signP.Sign) {
			continue
		}
		signN = append(signN, sign)
	}

}

func (b *Block) GetLeaderSign() *PbftSign {
	if len(b.signs) > 0 {
		return b.signs[0]
	}
	return nil
}

func (b *Block) IsAward() bool {
	if b.SnailHash() != *new(common.Hash) && b.SnailNumber() != nil {
		return true
	}
	return false
}

func (b *Block) IsSwitch() bool {
	if b.infos != nil && len(b.infos) > 0 {
		return true
	}
	return false
}

//Condition when proposal block award or switch is not nil
func (b *Block) IsProposal() bool {
	if b.IsAward() || b.IsSwitch() {
		return true
	}
	return false
}

// Size returns the true RLP encoded storage size of the block, either by encoding
// and returning it, or returning a previsouly cached value.
func (b *Block) Size() common.StorageSize {
	if size := b.size.Load(); size != nil {
		return size.(common.StorageSize)
	}
	c := writeCounter(0)
	rlp.Encode(&c, b)
	b.size.Store(common.StorageSize(c))
	return common.StorageSize(c)
}

// WithSeal returns a new block with the data from b but the header replaced with
// the sealed one. fastchain not use
func (b *Block) WithSeal(header *Header) *Block {
	cpy := *header

	return &Block{
		header:       &cpy,
		transactions: b.transactions,
	}
}

// WithBody returns a new block with the given transaction contents.
func (b *Block) WithBody(transactions []*Transaction, signs []*PbftSign, infos []*CommitteeMember) *Block {
	block := &Block{
		header:       CopyHeader(b.header),
		transactions: make([]*Transaction, len(transactions)),
		signs:        make([]*PbftSign, len(signs)),
		infos:        make([]*CommitteeMember, len(infos)),
	}

	copy(block.transactions, transactions)
	copy(block.signs, signs)
	copy(block.infos, infos)
	b.header.CommitteeHash = rlpHash(b.infos)

	return block
}

// SanityCheck can be used to prevent that unbounded fields are
// stuffed with junk data to add processing overhead
func (b *Block) SanityCheck() error {
	return b.header.SanityCheck()
}

// Hash returns the keccak256 hash of b's header.
// The hash is computed on the first call and cached thereafter.
func (b *Block) Hash() common.Hash {
	if hash := b.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}
	v := b.header.Hash()
	b.hash.Store(v)
	return v
}
func CopyPbftSign(s *PbftSign) *PbftSign {
	cpy := *s
	if cpy.FastHeight = new(big.Int); s.FastHeight != nil {
		cpy.FastHeight.Set(s.FastHeight)
	}
	if len(s.Sign) > 0 {
		cpy.Sign = make([]byte, len(s.Sign))
		copy(cpy.Sign, s.Sign)
	}
	return &cpy
}

////////////////////////////////////////////////////////////////////////////////
