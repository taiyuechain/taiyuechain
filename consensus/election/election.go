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

	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/core"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/log"

	"github.com/taiyuechain/taiyuechain/event"
)

const (
	// chain buffer size
	chainHeadSize           = 256
	committeeMemberChanSize = 20
)

var (
	ErrCommittee     = errors.New("get committee failed")
	ErrInvalidMember = errors.New("invalid committee member")
	ErrInvalidSwitch = errors.New("invalid switch block info")
)

type committee struct {
	id              *big.Int
	beginFastNumber *big.Int // the first fast block proposed by this committee
	endFastNumber   *big.Int // the last fast block proposed by this committee
	members         types.CommitteeMembers
	backupMembers   types.CommitteeMembers
	switches        []*big.Int // blocknumbers whose block include switchinfos
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

type Election struct {
	genesisCommittee []*types.CommitteeMember
	defaultMembers   []*types.CommitteeMember

	committee       *committee
	nextCommittee   *committee
	mu              sync.RWMutex
	testPrivateKeys []*ecdsa.PrivateKey
	singleNode      bool
	prepare         bool

	electionFeed       event.Feed
	scope              event.SubscriptionScope
	chainHeadCh        chan types.FastChainHeadEvent
	chainHeadSub       event.Subscription
	committeeMemberCh  chan types.CommitteeMemberEvent
	committeeMemberSub event.Subscription

	fastchain     *core.BlockChain
	currentHeight *big.Int
}

type Config interface {
	GetNodeType() bool
}

// NewElection create election processor and load genesis committee
func NewElection(fastBlockChain *core.BlockChain, config Config) *Election {
	// init
	election := &Election{
		fastchain:         fastBlockChain,
		chainHeadCh:       make(chan types.FastChainHeadEvent, chainHeadSize),
		prepare:           false,
		singleNode:        config.GetNodeType(),
		committeeMemberCh: make(chan types.CommitteeMemberEvent, committeeMemberChanSize),
		currentHeight:     big.NewInt(0),
	}
	//subscrib handle committeeMember event
	election.subScribeEvent()

	// get genesis committee
	election.genesisCommittee = election.getGenesisCommittee()
	if len(election.genesisCommittee) == 0 {
		log.Error("Election creation get no genesis committee members")
	}

	if election.singleNode {
		committeeMember := election.genesisCommittee
		if committeeMember == nil {
			log.Error("genesis block committee member is nil.")
		}
		election.genesisCommittee = committeeMember[:1]
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
}

func (e *Election) stop() {
	e.chainHeadSub.Unsubscribe()
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
	if member == nil {
		return nil, ErrInvalidMember
	}
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
		pubkey, err := crypto.SigToPub(sign.HashWithNoSign().Bytes(), sign.Sign)
		if err != nil {
			log.Warn("VerifySigns", "err", err, "sign", hex.EncodeToString(sign.Sign))
		}
		pubBytes := crypto.FromECDSAPub(pubkey)
		member := e.GetMemberByPubkey(committeeMembers, pubBytes)
		if member == nil {
			errs[i] = ErrInvalidMember
		} else {
			members[i] = member
		}
	}
	log.Debug("VerifySigns", "height", signs[0].FastHeight, "member", members)
	return members, errs
}

// VerifySwitchInfo verify committee members and it's state
func (e *Election) VerifySwitchInfo(fastNumber *big.Int, info []*types.CommitteeMember) error {
	if e.singleNode == true {
		return nil
	}
	eid := types.GetEpochIDFromHeight(fastNumber)
	begin, _ := types.GetEpochHeigth(eid)
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

func (e *Election) getCommitteeByGenesis() *committee {
	begin, end := types.GetEpochHeigth(new(big.Int).Set(common.Big0))
	return &committee{
		id:              new(big.Int).Set(common.Big0),
		beginFastNumber: begin,
		endFastNumber:   end,
		members:         e.genesisCommittee,
	}
}

// GetCommittee gets committee members propose this fast block
func (e *Election) GetCommittee(fastNumber *big.Int) []*types.CommitteeMember {
	eid := types.GetEpochIDFromHeight(fastNumber)
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
	if id.Cmp(e.committee.id) > 0 {
		return nil
	}

	info := make(map[string]interface{})
	m, b := e.getValidators(id)
	if m == nil {
		return nil
	}
	begin, end := types.GetEpochHeigth(id)
	info["id"] = id.Uint64()
	info["members"] = membersDisplay(m)
	if b != nil {
		info["memberCount"] = len(m) + len(b)
		info["backups"] = membersDisplay(b)
	} else {
		info["memberCount"] = len(m)
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
		begin, _ := types.GetEpochHeigth(eid)
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
		//reset committee and nextCommittee
		currentCommittee = e.getCommitteeInfoByCommitteeId(eid)

		e.mu.Lock()
		e.committee = currentCommittee
		e.nextCommittee = nil
		e.mu.Unlock()
		return currentCommittee.Members(), currentCommittee.BackupMembers()
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
	if types.EpochSize < types.EpochElectionPoint*3 {
		return errors.New(fmt.Sprint("EpochSize:", types.EpochSize, " less than 100"))
	}
	fastHeadNumber := e.fastchain.CurrentBlock().Number()
	e.currentHeight = fastHeadNumber
	curEpochID := types.GetEpochIDFromHeight(fastHeadNumber)
	currentCommittee := e.getCommitteeByGenesis()
	log.Info("Election start", "curEpochID", curEpochID, "fastHeadNumber", fastHeadNumber, "currentCommittee", currentCommittee)
	if curEpochID.Cmp(common.Big0) > 0 {
		currentCommittee = e.getCommitteeInfoByCommitteeId(curEpochID)
	}
	e.committee = currentCommittee

	if currentCommittee.endFastNumber.Cmp(common.Big0) > 0 {
		if e.committee.endFastNumber.Cmp(fastHeadNumber) == 0 {
			// committee has finish their work, start the new committee
			e.committee = e.getCommitteeInfoByCommitteeId(new(big.Int).Add(curEpochID, common.Big1))
			e.nextCommittee = nil
		} else if new(big.Int).Sub(e.committee.endFastNumber, fastHeadNumber).Uint64() <= types.EpochElectionPoint {
			e.prepare = true
		}
	}

	// send event to the subscripber
	go func(e *Election) {
		printCommittee(e.committee, "start")
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
		log.Info("Election prepare calc next committee on start", "committee", next)
		e.nextCommittee = e.getCommitteeInfoByCommitteeId(next)
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
			if new(big.Int).Sub(e.committee.endFastNumber, fastHead.Block.Number()).Uint64() == types.EpochElectionPoint {
				e.electValidatorNotifyAgent(fastHead.Block.Number())
			}
			if e.committee.endFastNumber.Cmp(fastHead.Block.Number()) == 0 {
				e.validatorSwitchNotifyAgent(fastHead.Block.Number())
			}
			space := new(big.Int).Sub(fastHead.Block.Number(), e.currentHeight).Uint64()
			if space > types.EpochElectionPoint/20 {
				log.Info("chainHead", "space", space, "current", e.currentHeight)
				// todo
			}
			e.currentHeight = fastHead.Block.Number()
		}
	}
}

func (e *Election) electValidatorNotifyAgent(height *big.Int) {
	//send CommitteeOver event to pbftAgent to notify currentCommittee endFastNumber
	e.electionFeed.Send(types.ElectionEvent{
		Option:           types.CommitteeOver,
		CommitteeID:      e.committee.id,
		CommitteeMembers: e.committee.Members(),
		BeginFastNumber:  e.committee.beginFastNumber,
		EndFastNumber:    e.committee.endFastNumber,
	})
	log.Info("Election BFT committee election start..", "endfast", e.committee.endFastNumber, "height", height)

	epoch := types.GetEpochIDFromHeight(height)
	//calculate nextCommittee
	nextCommittee := e.getCommitteeInfoByCommitteeId(new(big.Int).Add(epoch, common.Big1))

	//reset committee and nextCommittee
	e.mu.Lock()
	e.nextCommittee = nextCommittee
	e.mu.Unlock()
	printCommittee(e.nextCommittee, "chainHead")

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

func (e *Election) validatorSwitchNotifyAgent(height *big.Int) {
	log.Info("Election stop committee..", "id", e.committee.id)
	e.electionFeed.Send(types.ElectionEvent{
		Option:           types.CommitteeStop,
		CommitteeID:      e.committee.id,
		CommitteeMembers: e.committee.Members(),
		BackupMembers:    e.committee.BackupMembers(),
		BeginFastNumber:  e.committee.beginFastNumber,
		EndFastNumber:    e.committee.endFastNumber,
	})

	if e.nextCommittee == nil {
		epoch := types.GetEpochIDFromHeight(height)
		//calculate nextCommittee
		e.nextCommittee = e.getCommitteeInfoByCommitteeId(new(big.Int).Add(epoch, common.Big1))
		log.Info("validatorSwitchNotifyAgent", "current", e.currentHeight, "remote", height)
	}

	e.mu.Lock()
	e.committee = e.nextCommittee
	e.nextCommittee = nil
	e.mu.Unlock()

	log.Info("Election start new BFT committee", "id", e.committee.id)
	e.electionFeed.Send(types.ElectionEvent{
		Option:           types.CommitteeStart,
		CommitteeID:      e.committee.id,
		CommitteeMembers: e.committee.Members(),
		BackupMembers:    e.committee.BackupMembers(),
		BeginFastNumber:  e.committee.beginFastNumber,
	})
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
		log.Info("assignmentCommitteeMember", "committeeId", committeeId, "caCertMap", len(caCertMap.CACert), "caCert", caCert)

		pub,ok := caCertMap.Pubky[types.RlpHash(caCert)]
		if !ok {
			log.Warn("assignmentCommitteeMember pub not exist")
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
			Publickey:     pub,
			Flag:          types.StateUsedFlag,
			MType:         types.TypeWorked,
		}
	}
	return members
}

func (e *Election) getCommitteeInfoByCommitteeId(committeeId *big.Int) *committee {
	begin, end := types.GetEpochHeigth(committeeId)
	committee := &committee{
		id:              committeeId,
		beginFastNumber: new(big.Int).Set(begin),
		endFastNumber:   new(big.Int).Set(end),
	}
	caCertPubkeyList := e.getCACertList()
	committee.members = e.assignmentCommitteeMember(caCertPubkeyList, committeeId)
	return committee
}

func printCommittee(c *committee, flag string) {
	log.Info("Committee Info", "flag", flag, "ID", c.id, "count", len(c.members), "start", c.beginFastNumber)
	for _, member := range c.members {
		log.Info("Committee member: ", "PKey", hex.EncodeToString(member.Publickey), "coinbase", member.Coinbase)
	}
	for _, member := range c.backupMembers {
		log.Info("Committee backup: ", "PKey", hex.EncodeToString(member.Publickey), "coinbase", member.Coinbase)
	}
}
