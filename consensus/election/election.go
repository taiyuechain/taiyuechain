// Copyright 2018 The TaiyueChain Authors
// This file is part of the taiyuechain library.
//
// The taiyuechain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The taiyuechain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the taiyuechain library. If not, see <http://www.gnu.org/licenses/>.

package election

import (
	"bytes"
	"fmt"
	"github.com/taiyuechain/taiyuechain/common/hexutil"

	"github.com/taiyuechain/taiyuechain/core/vm"

	//"crypto/ecdsa"
	//"github.com/taiyuechain/taiyuechain/crypto"

	//"crypto/ecdsa"
	"github.com/taiyuechain/taiyuechain/crypto"

	//"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"math/big"
	"sync"

	"crypto/ecdsa"

	lru "github.com/hashicorp/golang-lru"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/consensus"
	"github.com/taiyuechain/taiyuechain/core"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/log"

	//"github.com/taiyuechain/taiyuechain/etruedb"
	"github.com/taiyuechain/taiyuechain/event"
	"github.com/taiyuechain/taiyuechain/params"
)

const (
	chainHeadSize           = 256
	snailchainHeadSize      = 64
	committeeCacheLimit     = 256
	committeeMemberChanSize = 20
)

type ElectMode uint

const (
	// ElectModeEtrue for etrue
	ElectModeEtrue = iota
	// ElectModeFake for Test purpose
	ElectModeFake
)

var (
	// maxUint256 is a big integer representing 2^256-1
	maxUint256         = new(big.Int).Exp(big.NewInt(2), big.NewInt(256), big.NewInt(0))
	EpochSize          = uint64(1000)
	EpochElectionPoint = uint64(100) //相隔多少个块前需要通知
)

var (
	ErrCommittee     = errors.New("get committee failed")
	ErrInvalidMember = errors.New("invalid committee member")
	ErrInvalidSwitch = errors.New("invalid switch block info")
)

func GetEpochIDFromHeight(height *big.Int) *big.Int {
	return new(big.Int).Div(height, big.NewInt(int64(EpochSize)))
}
func GetEpochHeigth(eid *big.Int) (*big.Int, *big.Int) {
	begin := new(big.Int).Mul(eid, big.NewInt(int64(EpochSize)))
	return begin, new(big.Int).Add(begin, big.NewInt(int64(EpochSize-1)))
}

func (e *Election) removeCommitteeMember(removeCommitteeMember *types.CommitteeMember) {
	for i, member := range e.nextCommittee.members {
		if member.Coinbase == removeCommitteeMember.Coinbase {
			e.nextCommittee.members = append(e.nextCommittee.members[:i], e.nextCommittee.members[i+1:]...)
		}
	}
}

type candidateMember struct {
	coinbase   common.Address
	address    common.Address
	publickey  *ecdsa.PublicKey
	difficulty *big.Int
	upper      *big.Int
	lower      *big.Int
}

type committee struct {
	id                  *big.Int
	beginFastNumber     *big.Int // the first fast block proposed by this committee
	endFastNumber       *big.Int // the last fast block proposed by this committee
	firstElectionNumber *big.Int // the begin snailblock to elect members
	lastElectionNumber  *big.Int // the end snailblock to elect members
	switchCheckNumber   *big.Int // the snailblock that start switch next committee
	members             types.CommitteeMembers
	backupMembers       types.CommitteeMembers
	switches            []*big.Int // blocknumbers whose block include switchinfos
}

// Members returns dump of the committee members
func (c *committee) Members() []*types.CommitteeMember {
	members := make([]*types.CommitteeMember, len(c.members))
	copy(members, c.members)
	return members
}

// Members returns dump of the backup committee members
func (c *committee) BackupMembers() []*types.CommitteeMember {
	members := make([]*types.CommitteeMember, len(c.backupMembers))
	copy(members, c.backupMembers)
	return members
}

func (c *committee) setMemberState(pubkey []byte, flag uint32) {
	for i, m := range c.members {
		if bytes.Equal(m.Publickey, pubkey) {
			c.members[i] = &types.CommitteeMember{
				Coinbase:  m.Coinbase,
				Publickey: m.Publickey,
				Flag:      flag,
			}
			break
		}
	}
	for i, m := range c.backupMembers {
		if bytes.Equal(m.Publickey, pubkey) {
			c.backupMembers[i] = &types.CommitteeMember{
				Coinbase:  m.Coinbase,
				Publickey: m.Publickey,
				Flag:      flag,
			}
			break
		}
	}
}

type Election struct {
	genesisCommittee []*types.CommitteeMember
	defaultMembers   []*types.CommitteeMember

	commiteeCache *lru.Cache

	electionMode    ElectMode
	committee       *committee
	nextCommittee   *committee
	mu              sync.RWMutex
	testPrivateKeys []*ecdsa.PrivateKey
	startSwitchover bool //Flag bit for handling event switching
	singleNode      bool

	electionFeed event.Feed
	scope        event.SubscriptionScope

	prepare    bool
	switchNext chan struct{}

	chainHeadCh  chan types.FastChainHeadEvent
	chainHeadSub event.Subscription

	committeeMemberCh  chan types.CommitteeMemberEvent
	committeeMemberSub event.Subscription

	fastchain *core.BlockChain
	engine    consensus.Engine
}

// SnailLightChain encapsulates functions required to synchronise a light chain.
type SnailLightChain interface {
	// CurrentHeader retrieves the head header from the local chain.
	CurrentHeader() *types.SnailHeader
}

type Config interface {
	GetNodeType() bool
}

// NewElection create election processor and load genesis committee
func NewElection(fastBlockChain *core.BlockChain, config Config) *Election {
	// init
	election := &Election{
		fastchain: fastBlockChain,
		//snailchain:        snailBlockChain,
		//snailChainEventCh: make(chan types.SnailChainEvent, snailchainHeadSize),

		chainHeadCh: make(chan types.FastChainHeadEvent, chainHeadSize),

		prepare:           false,
		switchNext:        make(chan struct{}),
		singleNode:        config.GetNodeType(),
		electionMode:      ElectModeEtrue,
		committeeMemberCh: make(chan types.CommitteeMemberEvent, committeeMemberChanSize),
	}
	//subscrib handle committeeMember event
	election.subScribeEvent()

	// get genesis committee
	election.genesisCommittee = election.getGenesisCommittee()
	if len(election.genesisCommittee) == 0 {
		log.Error("Election creation get no genesis committee members")
	}

	//election.snailChainEventSub = election.snailchain.SubscribeChainEvent(election.snailChainEventCh)
	election.commiteeCache, _ = lru.New(committeeCacheLimit)

	if election.singleNode {
		committeeMember := election.getGenesisCommittee()
		if committeeMember == nil {
			log.Error("genesis block committee member is nil.")
		}
		election.genesisCommittee = election.getGenesisCommittee()[:1]
	}
	if !election.singleNode && len(election.genesisCommittee) < 4 {
		log.Error("Election creation get insufficient genesis committee members")
	}
	for _, m := range election.genesisCommittee {
		var member = *m
		member.Flag = types.StateUnusedFlag
		election.defaultMembers = append(election.defaultMembers, &member)
	}

	return election
}

func (e *Election) subScribeEvent() {
	e.chainHeadSub = e.fastchain.SubscribeChainHeadEvent(e.chainHeadCh)
	//election.committeeMemberSub = election.*.SubscribeCommitteeMemberEvent(election.committeeMemberCh)
}

func (e *Election) stop() {
	e.chainHeadSub.Unsubscribe()
}

// NewFakeElection create fake mode election only for testing
func NewFakeElection() *Election {
	var priKeys []*ecdsa.PrivateKey
	var members []*types.CommitteeMember

	for i := 0; i < params.MinimumCommitteeNumber; i++ {
		priKey, err := crypto.GenerateKey()
		priKeys = append(priKeys, priKey)
		if err != nil {
			log.Error("initMembers", "error", err)
		}
		coinbase := crypto.PubkeyToAddress(priKey.PublicKey)

		m := &types.CommitteeMember{Coinbase: coinbase, CommitteeBase: coinbase, Publickey: crypto.FromECDSAPub(&priKey.PublicKey), Flag: types.StateUsedFlag, MType: types.TypeFixed}
		members = append(members, m)
	}

	// Backup members are empty in FakeMode Election
	elected := &committee{
		id:                  new(big.Int).Set(common.Big0),
		beginFastNumber:     new(big.Int).Set(common.Big1),
		endFastNumber:       new(big.Int).Set(common.Big0),
		firstElectionNumber: new(big.Int).Set(common.Big0),
		lastElectionNumber:  new(big.Int).Set(common.Big0),
		switchCheckNumber:   params.ElectionPeriodNumber,
		members:             members,
	}

	election := &Election{
		fastchain: nil,
		//snailchain:        nil,
		//snailChainEventCh: make(chan types.SnailChainEvent, snailchainHeadSize),
		singleNode:      false,
		committee:       elected,
		electionMode:    ElectModeFake,
		testPrivateKeys: priKeys,
	}
	return election
}

func (e *Election) GenerateFakeSigns(fb *types.Block) ([]*types.PbftSign, error) {
	var signs []*types.PbftSign

	for _, privateKey := range e.testPrivateKeys {
		voteSign := &types.PbftSign{
			Result:     types.VoteAgree,
			FastHeight: fb.Header().Number,
			FastHash:   fb.Hash(),
		}
		var err error
		signHash := voteSign.HashWithNoSign().Bytes()
		voteSign.Sign, err = crypto.Sign(signHash, privateKey)

		if err != nil {
			log.Error("fb GenerateSign error ", "err", err)
		}
		signs = append(signs, voteSign)
	}
	return signs, nil
}

func (e *Election) GetGenesisCommittee() []*types.CommitteeMember {
	return e.genesisCommittee
}

func (e *Election) GetCurrentCommittee() *committee {
	return e.committee
}

// GetMemberByPubkey returns committeeMember specified by public key bytes
func (e *Election) GetMemberByPubkey(members []*types.CommitteeMember, pubKey []byte) *types.CommitteeMember {
	if len(members) == 0 {
		log.Error("GetMemberByPubKey method len(members)= 0")
		return nil
	}
	for _, member := range members {
		if bytes.Equal(pubKey, member.Publickey) {
			return member
		}
	}
	return nil
}

// IsCommitteeMember reports whether the provided public key is in committee
func (e *Election) GetMemberFlag(members []*types.CommitteeMember, publickey []byte) uint32 {
	if len(members) == 0 {
		log.Error("IsCommitteeMember method len(members)= 0")
		return 0
	}
	for _, member := range members {
		if bytes.Equal(publickey, member.Publickey) {
			return member.Flag
		}
	}
	return 0
}

func (e *Election) IsCommitteeMember(members []*types.CommitteeMember, publickey []byte) bool {
	flag := e.GetMemberFlag(members, publickey)
	return flag == types.StateUsedFlag
}

// VerifyPublicKey get the committee member by public key
func (e *Election) VerifyPublicKey(fastHeight *big.Int, pubKeyByte []byte) (*types.CommitteeMember, error) {
	members := e.GetCommittee(fastHeight)
	if members == nil {
		log.Info("GetCommittee members is nil", "fastHeight", fastHeight)
		return nil, ErrCommittee
	}
	member := e.GetMemberByPubkey(members, pubKeyByte)
	/*if member == nil {
		return nil, ErrInvalidMember
	}*/
	return member, nil
}

// VerifySign lookup the pbft sign and return the committee member who signs it
func (e *Election) VerifySign(sign *types.PbftSign) (*types.CommitteeMember, error) {
	pubkey, err := crypto.SigToPub(sign.HashWithNoSign().Bytes(), sign.Sign)
	if err != nil {
		return nil, err
	}
	pubkeyByte := crypto.FromECDSAPub(pubkey)
	member, err := e.VerifyPublicKey(sign.FastHeight, pubkeyByte)
	return member, err
}

// VerifySigns verify signatures of bft committee in batches
func (e *Election) VerifySigns(signs []*types.PbftSign) ([]*types.CommitteeMember, []error) {

	members := make([]*types.CommitteeMember, len(signs))
	errs := make([]error, len(signs))

	if len(signs) == 0 {
		log.Warn("Veriry signs get nil pbftsigns")
		return nil, nil
	}
	// All signs should have the same fastblock height
	committeeMembers := e.GetCommittee(signs[0].FastHeight)
	if len(committeeMembers) == 0 {
		log.Error("Election get none committee for verify pbft signs")
		for i := range errs {
			errs[i] = ErrCommittee
		}
		return members, errs
	}

	//todo ignore singlenode model sign validate
	/*if e.singleNode {
		return committeeMembers, nil
	}*/

	for i, sign := range signs {
		pubkey, _ := crypto.SigToPub(sign.HashWithNoSign().Bytes(), sign.Sign)
		pubBytes := crypto.FromECDSAPub(pubkey)
		member := e.GetMemberByPubkey(committeeMembers, pubBytes)
		fmt.Println("member index ", i, " len ", len(sign.Sign), " pub ", hexutil.Encode(pubBytes), " member ", member)
		if member == nil {
			errs[i] = ErrInvalidMember
		} else {
			members[i] = member
		}
	}
	return members, errs
}

// VerifySwitchInfo verify committee members and it's state
func (e *Election) VerifySwitchInfo(fastNumber *big.Int, info []*types.CommitteeMember) error {
	if e.singleNode == true {
		return nil
	}
	eid := GetEpochIDFromHeight(fastNumber)
	begin, _ := GetEpochHeigth(eid)
	m, b := e.getValidators(eid)
	if m == nil {
		log.Error("Failed to fetch elected committee", "fast", fastNumber)
		return ErrCommittee
	}

	// Committee begin block must include members info
	if begin.Cmp(fastNumber) == 0 {
		members := m
		if b != nil {
			members = append(members, b...)
		}
		if len(members) != len(info) {
			log.Error("SwitchInfo members invalid", "num", fastNumber)
			return ErrInvalidSwitch
		}
		for i := range info {
			if !info[i].Compared(members[i]) {
				log.Error("SwitchInfo members invalid", "num", fastNumber)
				return ErrInvalidSwitch
			}
		}
		return nil
	}
	return nil
}

func (e *Election) getGenesisCommittee() []*types.CommitteeMember {
	block := e.fastchain.GetBlockByNumber(0)
	if block != nil {
		return block.SwitchInfos()
	}
	return nil
}

func (e *Election) getCommitteeByContract() *committee {
	//TODO get new one
	return &committee{
		id:                  new(big.Int).Set(common.Big0),
		beginFastNumber:     new(big.Int).Set(common.Big1),
		endFastNumber:       new(big.Int).Set(common.Big0),
		firstElectionNumber: new(big.Int).Set(common.Big0),
		lastElectionNumber:  new(big.Int).Set(common.Big0),
		switchCheckNumber:   params.ElectionPeriodNumber,
		members:             e.genesisCommittee,
	}
}

// GetCommittee gets committee members propose this fast block
func (e *Election) GetCommittee(fastNumber *big.Int) []*types.CommitteeMember {
	eid := GetEpochIDFromHeight(fastNumber)
	m, _ := e.getValidators(eid)
	if m == nil {
		log.Error("Failed to fetch elected committee", "fast", fastNumber)
		return nil
	}
	return m
}

// GetCommitteeById return committee info sepecified by Committee ID
func (e *Election) GetCommitteeById(id *big.Int) map[string]interface{} {
	if id.Sign() <= 0 {
		id = big.NewInt(0)
	}
	info := make(map[string]interface{})
	m, b := e.getValidators(id)
	if m == nil {
		return nil
	}
	begin, end := GetEpochHeigth(id)
	info["id"] = id.Uint64()
	info["members"] = membersDisplay(m)
	if b != nil {
		info["memberCount"] = len(b) + len(b)
		info["backups"] = membersDisplay(b)
	} else {
		info["memberCount"] = len(b)
	}
	info["beginNumber"] = begin.Uint64()
	info["endNumber"] = end.Uint64()
	return info
}
func (e *Election) getValidators(eid *big.Int) ([]*types.CommitteeMember, []*types.CommitteeMember) {
	e.mu.RLock()
	currentCommittee := e.committee
	e.mu.RUnlock()
	if eid.Sign() < 0 {
		eid = big.NewInt(0)
	}
	if eid.Cmp(currentCommittee.id) < 0 {
		if eid.Sign() == 0 {
			return e.genesisCommittee, nil
		}
		begin, _ := GetEpochHeigth(eid)
		// Read committee from block body
		block := e.fastchain.GetBlockByNumber(begin.Uint64())
		if block == nil {
			log.Error("getValidators Failed,block is nil", "number", begin.Uint64(), "eid", eid)
			return nil, nil
		}
		var (
			members []*types.CommitteeMember
			backups []*types.CommitteeMember
		)
		for _, m := range block.SwitchInfos() {
			if m.Flag == types.StateUsedFlag {
				members = append(members, m)
			}
			if m.Flag == types.StateUnusedFlag {
				backups = append(backups, m)
			}
		}
		committee := &types.ElectionCommittee{Members: members, Backups: backups}
		return committee.Members, committee.Backups
	} else if eid.Cmp(currentCommittee.id) == 0 {
		return currentCommittee.Members(), currentCommittee.BackupMembers()
	} else {
		return nil, nil
	}
}
func membersDisplay(members []*types.CommitteeMember) []map[string]interface{} {
	var attrs []map[string]interface{}
	for _, member := range members {
		attrs = append(attrs, map[string]interface{}{
			"coinbase": member.Coinbase,
			"PKey":     hex.EncodeToString(member.Publickey),
			"flag":     member.Flag,
			"type":     member.MType,
		})
	}
	return attrs
}

// filterWithSwitchInfo return committee members which are applied all switchinfo changes
func (e *Election) filterWithSwitchInfo(c *committee) (members, backups []*types.CommitteeMember) {
	members = c.Members()
	backups = c.BackupMembers()
	if len(c.switches) == 0 {
		log.Info("Committee filter get no switch infos", "id", c.id)
		return
	}

	// Apply all committee state switches for latest block
	states := make(map[common.Address]uint32)
	for _, num := range c.switches {
		b := e.fastchain.GetBlockByNumber(num.Uint64())
		for _, s := range b.SwitchInfos() {
			switch s.Flag {
			case types.StateAppendFlag:
				states[s.CommitteeBase] = types.StateAppendFlag
			case types.StateRemovedFlag:
				states[s.CommitteeBase] = types.StateRemovedFlag
			}
		}
	}
	for k, flag := range states {
		enums := map[uint32]string{
			types.StateAppendFlag:  "add",
			types.StateRemovedFlag: "drop",
		}
		log.Info("Committee switch transition", "bftkey", k, "state", enums[flag], "committee", c.id)
	}

	for i, m := range members {
		if flag, ok := states[m.CommitteeBase]; ok {
			if flag == types.StateRemovedFlag {
				// Update the committee member state
				var switched = *m
				switched.Flag = types.StateRemovedFlag
				members[i] = &switched
			}
		}
	}
	for i, m := range backups {
		if flag, ok := states[m.CommitteeBase]; ok {
			if flag == types.StateAppendFlag {
				// Update the committee member state
				var switched = *m
				switched.Flag = types.StateUsedFlag
				backups[i] = &switched
			}
			if flag == types.StateRemovedFlag {
				// Update the committee member state
				var switched = *m
				switched.Flag = types.StateRemovedFlag
				backups[i] = &switched
			}
		}
	}
	return
}

// Start load current committ and starts election processing
func (e *Election) Start() error {
	// get current committee info
	if EpochSize < EpochElectionPoint*3 {
		return errors.New(fmt.Sprint("EpochSize:", EpochSize, " less than 100"))
	}
	fastHeadNumber := e.fastchain.CurrentBlock().Number()
	curEpochID := GetEpochIDFromHeight(fastHeadNumber)
	currentCommittee := e.getCommitteeByContract()
	if curEpochID.Cmp(common.Big0) > 0 {
		currentCommittee = e.getCommitteeInfoByCommitteeId(curEpochID)
	}
	e.committee = currentCommittee

	if currentCommittee.endFastNumber.Cmp(common.Big0) > 0 {
		if e.committee.endFastNumber.Cmp(fastHeadNumber) == 0 {
			// committee has finish their work, start the new committee
			e.committee = e.getCommitteeInfoByCommitteeId(new(big.Int).Add(curEpochID, common.Big1))
			e.nextCommittee = nil
			e.startSwitchover = false
		} else if new(big.Int).Sub(e.committee.endFastNumber, fastHeadNumber).Uint64() == (EpochSize - EpochElectionPoint) {
			e.prepare = true
		}
	}

	// send event to the subscripber
	go func(e *Election) {
		printCommittee(e.committee)
		members, backups := e.filterWithSwitchInfo(e.committee)
		e.electionFeed.Send(types.ElectionEvent{
			Option:           types.CommitteeSwitchover,
			CommitteeID:      e.committee.id,
			CommitteeMembers: members,
			BackupMembers:    backups,
			BeginFastNumber:  e.committee.beginFastNumber,
		})
		e.electionFeed.Send(types.ElectionEvent{
			Option:           types.CommitteeStart,
			CommitteeID:      e.committee.id,
			CommitteeMembers: members,
			BackupMembers:    backups,
			BeginFastNumber:  e.committee.beginFastNumber,
		})
	}(e)

	// Start the event loop and return
	go e.loop()

	return nil
}

// Monitor both chains and trigger elections at the same time
func (e *Election) loop() {
	defer e.stop()
	// Elect next committee on start
	if e.prepare {
		next := new(big.Int).Add(e.committee.id, common.Big1)
		log.Info("Election calc next committee on start", "committee", next)
		e.nextCommittee = e.getCommitteeInfoByCommitteeId(next)
		e.startSwitchover = true
		e.electionFeed.Send(types.ElectionEvent{
			Option:           types.CommitteeOver,
			CommitteeID:      e.committee.id,
			CommitteeMembers: e.committee.Members(),
			BackupMembers:    e.committee.BackupMembers(),
			BeginFastNumber:  e.committee.beginFastNumber,
			EndFastNumber:    e.committee.endFastNumber,
		})
		e.electionFeed.Send(types.ElectionEvent{
			Option:           types.CommitteeSwitchover,
			CommitteeID:      e.nextCommittee.id,
			CommitteeMembers: e.nextCommittee.Members(),
			BackupMembers:    e.nextCommittee.BackupMembers(),
			BeginFastNumber:  e.nextCommittee.beginFastNumber,
		})
		log.Info("Election switchover next on start", "id", e.nextCommittee.id, "startNumber", e.nextCommittee.beginFastNumber)
	}

	// Calculate commitee and switchover via fast and snail event
	for {
		select {
		case fastHead := <-e.chainHeadCh:
			if new(big.Int).Sub(e.committee.endFastNumber, fastHead.Block.Number()).Uint64() == (EpochSize - EpochElectionPoint) {
				//send CommitteeOver event to pbftAgent to notify currentCommittee endFastNumber
				e.electionFeed.Send(types.ElectionEvent{
					Option:           types.CommitteeOver,
					CommitteeID:      e.committee.id,
					CommitteeMembers: e.committee.Members(),
					BeginFastNumber:  e.committee.beginFastNumber,
					EndFastNumber:    e.committee.endFastNumber,
				})
				log.Info("Election BFT committee election start..", "endfast", e.committee.endFastNumber)

				//calculate nextCommittee
				nextCommittee := e.getCommitteeInfoByCommitteeId(e.committee.id)

				//reset committee and nextCommittee
				e.mu.Lock()
				e.nextCommittee = nextCommittee
				e.startSwitchover = true
				e.mu.Unlock()
				printCommittee(e.nextCommittee)

				//send CommitteeSwitchover event to pbftAgent
				e.electionFeed.Send(types.ElectionEvent{
					Option:           types.CommitteeSwitchover,
					CommitteeID:      e.nextCommittee.id,
					CommitteeMembers: e.nextCommittee.Members(),
					BeginFastNumber:  e.nextCommittee.beginFastNumber,
					EndFastNumber:    e.nextCommittee.endFastNumber,
				})
				log.Info("Election BFT committee CommitteeSwitchover", "beginFastNumber", e.committee.beginFastNumber, "endFastNumber", e.committee.endFastNumber)
			}
			if e.committee.endFastNumber.Cmp(fastHead.Block.Number()) == 0 {
				log.Info("Election stop committee..", "id", e.committee.id)
				e.electionFeed.Send(types.ElectionEvent{
					Option:           types.CommitteeStop,
					CommitteeID:      e.committee.id,
					CommitteeMembers: e.committee.Members(),
					BackupMembers:    e.committee.BackupMembers(),
					BeginFastNumber:  e.committee.beginFastNumber,
					EndFastNumber:    e.committee.endFastNumber,
				})

				e.mu.Lock()
				e.committee = e.nextCommittee
				e.nextCommittee = nil
				e.mu.Unlock()
				e.startSwitchover = false

				log.Info("Election start new BFT committee", "id", e.committee.id)
				e.electionFeed.Send(types.ElectionEvent{
					Option:           types.CommitteeStart,
					CommitteeID:      e.committee.id,
					CommitteeMembers: e.committee.Members(),
					BackupMembers:    e.committee.BackupMembers(),
					BeginFastNumber:  e.committee.beginFastNumber,
				})
			}
		}
	}
}

// SubscribeElectionEvent adds a channel to feed on committee change event
func (e *Election) SubscribeElectionEvent(ch chan<- types.ElectionEvent) event.Subscription {
	return e.scope.Track(e.electionFeed.Subscribe(ch))
}

func (e *Election) getCACertList() *vm.CACertList {
	caCertList := vm.NewCACertList()
	stateDB, err := e.fastchain.State()
	if err != nil {
		log.Error("election fastHead event", "err", err)
		return nil
	}
	err = caCertList.LoadCACertList(stateDB, types.CACertListAddress)
	return caCertList
}

func (e *Election) assignmentCommitteeMember(caCertList *vm.CACertList, committeeId *big.Int) []*types.CommitteeMember {
	caCertMap := caCertList.GetCACertMapByEpoch(committeeId.Uint64())
	members := make([]*types.CommitteeMember, len(caCertMap.CACert))
	for i, caCert := range caCertMap.CACert {
		log.Error("assignmentCommitteeMember", "caCertMap", len(caCertMap.CACert), "caCert", hex.EncodeToString(caCert))

		pub, err := crypto.GetPubByteFromCert(caCert)
		if err != nil {
			log.Warn("assignmentCommitteeMember", "GetPubByteFromCert err", err)
			continue
		}
		pubkey, err := crypto.UnmarshalPubkey(pub)
		if err != nil {
			log.Warn("assignmentCommitteeMember", "UnmarshalPubkey err", err)
			continue
		}
		address := crypto.PubkeyToAddress(*pubkey)

		members[i] = &types.CommitteeMember{
			CommitteeBase: address,
			Coinbase:      address,
			LocalCert:     caCert,
			Publickey:     pub,
			Flag:          types.StateUsedFlag,
			MType:         types.TypeWorked,
		}
	}
	return members
}

func (e *Election) getCommitteeInfoByCommitteeId(committeeId *big.Int) *committee {
	begin, end := GetEpochHeigth(committeeId)
	committee := &committee{
		id:              new(big.Int).Add(committeeId, common.Big1),
		beginFastNumber: new(big.Int).Set(begin),
		endFastNumber:   new(big.Int).Set(end),
	}
	caCertPubkeyList := e.getCACertList()
	committee.members = e.assignmentCommitteeMember(caCertPubkeyList, committeeId)
	return committee
}

// SetEngine set election backend consesus
func (e *Election) SetEngine(engine consensus.Engine) {
	e.engine = engine
}

func printCommittee(c *committee) {
	log.Info("Committee Info", "ID", c.id, "count", len(c.members), "start", c.beginFastNumber)
	for _, member := range c.members {
		log.Info("Committee member: ", "PKey", hex.EncodeToString(member.Publickey), "coinbase", member.Coinbase)
	}
	for _, member := range c.backupMembers {
		log.Info("Committee backup: ", "PKey", hex.EncodeToString(member.Publickey), "coinbase", member.Coinbase)
	}
}
