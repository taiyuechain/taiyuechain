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

package enode

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"github.com/taiyuechain/taiyuechain/crypto"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

var keytestID = HexID("51232b8d7821617d2b29b54b81cdefb9b3e9c37d7fd5f63270bcc9e1a6f6a439")

func TestDBNodeKey(t *testing.T) {
	enc := nodeKey(keytestID)
	want := []byte{
		'n', ':',
		0x51, 0x23, 0x2b, 0x8d, 0x78, 0x21, 0x61, 0x7d, // node id
		0x2b, 0x29, 0xb5, 0x4b, 0x81, 0xcd, 0xef, 0xb9, //
		0xb3, 0xe9, 0xc3, 0x7d, 0x7f, 0xd5, 0xf6, 0x32, //
		0x70, 0xbc, 0xc9, 0xe1, 0xa6, 0xf6, 0xa4, 0x39, //
		':', 'v', '4',
	}
	if !bytes.Equal(enc, want) {
		t.Errorf("wrong encoded key:\ngot  %q\nwant %q", enc, want)
	}
	id, _ := splitNodeKey(enc)
	if id != keytestID {
		t.Errorf("wrong ID from splitNodeKey")
	}
}

func TestDBNodeItemKey(t *testing.T) {
	wantIP := net.IP{127, 0, 0, 3}
	wantField := "foobar"
	enc := nodeItemKey(keytestID, wantIP, wantField)
	want := []byte{
		'n', ':',
		0x51, 0x23, 0x2b, 0x8d, 0x78, 0x21, 0x61, 0x7d, // node id
		0x2b, 0x29, 0xb5, 0x4b, 0x81, 0xcd, 0xef, 0xb9, //
		0xb3, 0xe9, 0xc3, 0x7d, 0x7f, 0xd5, 0xf6, 0x32, //
		0x70, 0xbc, 0xc9, 0xe1, 0xa6, 0xf6, 0xa4, 0x39, //
		':', 'v', '4', ':',
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // IP
		0x00, 0x00, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x03, //
		':', 'f', 'o', 'o', 'b', 'a', 'r',
	}
	if !bytes.Equal(enc, want) {
		t.Errorf("wrong encoded key:\ngot  %q\nwant %q", enc, want)
	}
	id, ip, field := splitNodeItemKey(enc)
	if id != keytestID {
		t.Errorf("splitNodeItemKey returned wrong ID: %v", id)
	}
	if !ip.Equal(wantIP) {
		t.Errorf("splitNodeItemKey returned wrong IP: %v", ip)
	}
	if field != wantField {
		t.Errorf("splitNodeItemKey returned wrong field: %q", field)
	}
}

var nodeDBInt64Tests = []struct {
	key   []byte
	value int64
}{
	{key: []byte{0x01}, value: 1},
	{key: []byte{0x02}, value: 2},
	{key: []byte{0x03}, value: 3},
}

func TestDBInt64(t *testing.T) {
	db, _ := OpenDB("")
	defer db.Close()

	tests := nodeDBInt64Tests
	for i := 0; i < len(tests); i++ {
		// Insert the next value
		if err := db.storeInt64(tests[i].key, tests[i].value); err != nil {
			t.Errorf("test %d: failed to store value: %v", i, err)
		}
		// Check all existing and non existing values
		for j := 0; j < len(tests); j++ {
			num := db.fetchInt64(tests[j].key)
			switch {
			case j <= i && num != tests[j].value:
				t.Errorf("test %d, item %d: value mismatch: have %v, want %v", i, j, num, tests[j].value)
			case j > i && num != 0:
				t.Errorf("test %d, item %d: value mismatch: have %v, want %v", i, j, num, 0)
			}
		}
	}
}

func TestDBFetchStore(t *testing.T) {
	node := NewV4(
		generateHexPub(),
		net.IP{192, 168, 0, 1},
		30303,
		30303,
	)
	inst := time.Now()
	num := 314

	db, _ := OpenDB("")
	defer db.Close()

	// Check fetch/store operations on a node ping object
	if stored := db.LastPingReceived(node.ID(), node.IP()); stored.Unix() != 0 {
		t.Errorf("ping: non-existing object: %v", stored)
	}
	if err := db.UpdateLastPingReceived(node.ID(), node.IP(), inst); err != nil {
		t.Errorf("ping: failed to update: %v", err)
	}
	if stored := db.LastPingReceived(node.ID(), node.IP()); stored.Unix() != inst.Unix() {
		t.Errorf("ping: value mismatch: have %v, want %v", stored, inst)
	}
	// Check fetch/store operations on a node pong object
	if stored := db.LastPongReceived(node.ID(), node.IP()); stored.Unix() != 0 {
		t.Errorf("pong: non-existing object: %v", stored)
	}
	if err := db.UpdateLastPongReceived(node.ID(), node.IP(), inst); err != nil {
		t.Errorf("pong: failed to update: %v", err)
	}
	if stored := db.LastPongReceived(node.ID(), node.IP()); stored.Unix() != inst.Unix() {
		t.Errorf("pong: value mismatch: have %v, want %v", stored, inst)
	}
	// Check fetch/store operations on a node findnode-failure object
	if stored := db.FindFails(node.ID(), node.IP()); stored != 0 {
		t.Errorf("find-node fails: non-existing object: %v", stored)
	}
	if err := db.UpdateFindFails(node.ID(), node.IP(), num); err != nil {
		t.Errorf("find-node fails: failed to update: %v", err)
	}
	if stored := db.FindFails(node.ID(), node.IP()); stored != num {
		t.Errorf("find-node fails: value mismatch: have %v, want %v", stored, num)
	}
	// Check fetch/store operations on an actual node object
	if stored := db.Node(node.ID()); stored != nil {
		t.Errorf("node: non-existing object: %v", stored)
	}
	if err := db.UpdateNode(node); err != nil {
		t.Errorf("node: failed to update: %v", err)
	}
	if stored := db.Node(node.ID()); stored == nil {
		t.Errorf("node: not found")
	} else if !reflect.DeepEqual(stored, node) {
		t.Errorf("node: data mismatch: have %v, want %v", stored, node)
	}
}

func generateHexPub() *ecdsa.PublicKey {
	priv, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	return &priv.PublicKey
}

var nodeDBSeedQueryNodes = []struct {
	node *Node
	pong time.Time
}{
	// This one should not be in the result set because its last
	// pong time is too far in the past.
	{
		node: NewV4(
			generateHexPub(),
			net.IP{127, 0, 0, 3},
			30303,
			30303,
		),
		pong: time.Now().Add(-3 * time.Hour),
	},
	// This one shouldn't be in the result set because its
	// nodeID is the local node's ID.
	{
		node: NewV4(
			generateHexPub(),
			net.IP{127, 0, 0, 3},
			30303,
			30303,
		),
		pong: time.Now().Add(-4 * time.Second),
	},

	// These should be in the result set.
	{
		node: NewV4(
			generateHexPub(),
			net.IP{127, 0, 0, 1},
			30303,
			30303,
		),
		pong: time.Now().Add(-2 * time.Second),
	},
	{
		node: NewV4(
			generateHexPub(),
			net.IP{127, 0, 0, 2},
			30303,
			30303,
		),
		pong: time.Now().Add(-3 * time.Second),
	},
	{
		node: NewV4(
			generateHexPub(),
			net.IP{127, 0, 0, 3},
			30303,
			30303,
		),
		pong: time.Now().Add(-1 * time.Second),
	},
	{
		node: NewV4(
			generateHexPub(),
			net.IP{127, 0, 0, 3},
			30303,
			30303,
		),
		pong: time.Now().Add(-2 * time.Second),
	},
	{
		node: NewV4(
			generateHexPub(),
			net.IP{127, 0, 0, 3},
			30303,
			30303,
		),
		pong: time.Now().Add(-2 * time.Second),
	},
}

func TestDBSeedQuery(t *testing.T) {
	// Querying seeds uses seeks an might not find all nodes
	// every time when the database is small. Run the test multiple
	// times to avoid flakes.
	const attempts = 15
	var err error
	for i := 0; i < attempts; i++ {
		if err = testSeedQuery(); err == nil {
			return
		}
	}
	if err != nil {
		t.Errorf("no successful run in %d attempts: %v", attempts, err)
	}
}

func testSeedQuery() error {
	db, _ := OpenDB("")
	defer db.Close()

	// Insert a batch of nodes for querying
	for i, seed := range nodeDBSeedQueryNodes {
		if err := db.UpdateNode(seed.node); err != nil {
			return fmt.Errorf("node %d: failed to insert: %v", i, err)
		}
		if err := db.UpdateLastPongReceived(seed.node.ID(), seed.node.IP(), seed.pong); err != nil {
			return fmt.Errorf("node %d: failed to insert bondTime: %v", i, err)
		}
	}

	// Retrieve the entire batch and check for duplicates
	seeds := db.QuerySeeds(len(nodeDBSeedQueryNodes)*2, time.Hour)
	have := make(map[ID]struct{})
	for _, seed := range seeds {
		have[seed.ID()] = struct{}{}
	}
	want := make(map[ID]struct{})
	for _, seed := range nodeDBSeedQueryNodes[1:] {
		want[seed.node.ID()] = struct{}{}
	}
	if len(seeds) != len(want) {
		return fmt.Errorf("seed count mismatch: have %v, want %v", len(seeds), len(want))
	}
	for id := range have {
		if _, ok := want[id]; !ok {
			return fmt.Errorf("extra seed: %v", id)
		}
	}
	for id := range want {
		if _, ok := have[id]; !ok {
			return fmt.Errorf("missing seed: %v", id)
		}
	}
	return nil
}

func TestDBPersistency(t *testing.T) {
	root, err := ioutil.TempDir("", "nodedb-")
	if err != nil {
		t.Fatalf("failed to create temporary data folder: %v", err)
	}
	defer os.RemoveAll(root)

	var (
		testKey = []byte("somekey")
		testInt = int64(314)
	)

	// Create a persistent database and store some values
	db, err := OpenDB(filepath.Join(root, "database"))
	if err != nil {
		t.Fatalf("failed to create persistent database: %v", err)
	}
	if err := db.storeInt64(testKey, testInt); err != nil {
		t.Fatalf("failed to store value: %v.", err)
	}
	db.Close()

	// Reopen the database and check the value
	db, err = OpenDB(filepath.Join(root, "database"))
	if err != nil {
		t.Fatalf("failed to open persistent database: %v", err)
	}
	if val := db.fetchInt64(testKey); val != testInt {
		t.Fatalf("value mismatch: have %v, want %v", val, testInt)
	}
	db.Close()
}

var nodeDBExpirationNodes = []struct {
	node      *Node
	pong      time.Time
	storeNode bool
	exp       bool
}{
	// Node has new enough pong time and isn't expired:
	{
		node: NewV4(
			generateHexPub(),
			net.IP{127, 0, 0, 1},
			30303,
			30303,
		),
		storeNode: true,
		pong:      time.Now().Add(-dbNodeExpiration + time.Minute),
		exp:       false,
	},
	// Node with pong time before expiration is removed:
	{
		node: NewV4(
			generateHexPub(),
			net.IP{127, 0, 0, 2},
			30303,
			30303,
		),
		storeNode: true,
		pong:      time.Now().Add(-dbNodeExpiration - time.Minute),
		exp:       true,
	},
	// Just pong time, no node stored:
	{
		node: NewV4(
			generateHexPub(),
			net.IP{127, 0, 0, 3},
			30303,
			30303,
		),
		storeNode: false,
		pong:      time.Now().Add(-dbNodeExpiration - time.Minute),
		exp:       true,
	},
	// Node with multiple pong times, all older than expiration.
	{
		node: NewV4(
			generateHexPub(),
			net.IP{127, 0, 0, 4},
			30303,
			30303,
		),
		storeNode: true,
		pong:      time.Now().Add(-dbNodeExpiration - time.Minute),
		exp:       true,
	},
	{
		node: NewV4(
			generateHexPub(),
			net.IP{127, 0, 0, 5},
			30303,
			30303,
		),
		storeNode: false,
		pong:      time.Now().Add(-dbNodeExpiration - 2*time.Minute),
		exp:       true,
	},
	// Node with multiple pong times, one newer, one older than expiration.
	{
		node: NewV4(
			generateHexPub(),
			net.IP{127, 0, 0, 6},
			30303,
			30303,
		),
		storeNode: true,
		pong:      time.Now().Add(-dbNodeExpiration + time.Minute),
		exp:       false,
	},
	{
		node: NewV4(
			generateHexPub(),
			net.IP{127, 0, 0, 7},
			30303,
			30303,
		),
		storeNode: false,
		pong:      time.Now().Add(-dbNodeExpiration - time.Minute),
		exp:       true,
	},
}

func TestDBExpiration(t *testing.T) {
	db, _ := OpenDB("")
	defer db.Close()

	// Add all the test nodes and set their last pong time.
	for i, seed := range nodeDBExpirationNodes {
		if seed.storeNode {
			if err := db.UpdateNode(seed.node); err != nil {
				t.Fatalf("node %d: failed to insert: %v", i, err)
			}
		}
		if err := db.UpdateLastPongReceived(seed.node.ID(), seed.node.IP(), seed.pong); err != nil {
			t.Fatalf("node %d: failed to update bondTime: %v", i, err)
		}
	}

	db.expireNodes()

	// Check that expired entries have been removed.
	unixZeroTime := time.Unix(0, 0)
	for i, seed := range nodeDBExpirationNodes {
		node := db.Node(seed.node.ID())
		pong := db.LastPongReceived(seed.node.ID(), seed.node.IP())
		if seed.exp {
			if seed.storeNode && node != nil {
				t.Errorf("node %d (%s) shouldn't be present after expiration", i, seed.node.ID().TerminalString())
			}
			if !pong.Equal(unixZeroTime) {
				t.Errorf("pong time %d (%s %v) shouldn't be present after expiration", i, seed.node.ID().TerminalString(), seed.node.IP())
			}
		} else {
			if seed.storeNode && node == nil {
				t.Errorf("node %d (%s) should be present after expiration", i, seed.node.ID().TerminalString())
			}
			if !pong.Equal(seed.pong.Truncate(1 * time.Second)) {
				t.Errorf("pong time %d (%s) should be %v after expiration, but is %v", i, seed.node.ID().TerminalString(), seed.pong, pong)
			}
		}
	}
}
