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

package yuedb

import (
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/taiyuechain/taiyuechain/common"
)

/*
 * This is a test memory database. Do not use for any production it does not get persisted
 */
type MemDatabase struct {
	db   map[string][]byte
	lock sync.RWMutex
}

func (db *MemDatabase) Stat(property string) (string, error) {
	return db.Stat(property)
}

func (db *MemDatabase) Compact(start []byte, limit []byte) error {
	return db.Compact(start, limit)
}

func (db *MemDatabase) HasAncient(kind string, number uint64) (bool, error) {
	return db.HasAncient(kind, number)
}

func (db *MemDatabase) Ancient(kind string, number uint64) ([]byte, error) {
	return db.Ancient(kind, number)
}

func (db *MemDatabase) Ancients() (uint64, error) {
	return db.Ancients()
}

func (db *MemDatabase) AncientSize(kind string) (uint64, error) {
	return db.AncientSize(kind)
}

func (db *MemDatabase) AppendAncient(number uint64, hash, header, body, receipt, td []byte) error {
	return db.AppendAncient(number, hash, header, body, receipt, td)
}

func (db *MemDatabase) TruncateAncients(n uint64) error {
	return db.TruncateAncients(n)
}

func (db *MemDatabase) Sync() error {
	return db.Sync()
}

// NewIterator creates a binary-alphabetical iterator over the entire keyspace
// contained within the memory database.
func (db *MemDatabase) NewIterator() Iterator {
	return db.NewIteratorWithStart(nil)
}

// NewIteratorWithStart creates a binary-alphabetical iterator over a subset of
// database content starting at a particular initial key (or after, if it does
// not exist).
func (db *MemDatabase) NewIteratorWithStart(start []byte) Iterator {
	db.lock.RLock()
	defer db.lock.RUnlock()

	var (
		st     = string(start)
		keys   = make([]string, 0, len(db.db))
		values = make([][]byte, 0, len(db.db))
	)
	// Collect the keys from the memory database corresponding to the given start
	for key := range db.db {
		if key >= st {
			keys = append(keys, key)
		}
	}
	// Sort the items and retrieve the associated values
	sort.Strings(keys)
	for _, key := range keys {
		values = append(values, db.db[key])
	}
	return &iterator{
		keys:   keys,
		values: values,
	}
}

// NewIteratorWithPrefix creates a binary-alphabetical iterator over a subset
// of database content with a particular key prefix.
func (db *MemDatabase) NewIteratorWithPrefix(prefix []byte) Iterator {
	db.lock.RLock()
	defer db.lock.RUnlock()

	var (
		pr     = string(prefix)
		keys   = make([]string, 0, len(db.db))
		values = make([][]byte, 0, len(db.db))
	)
	// Collect the keys from the memory database corresponding to the given prefix
	for key := range db.db {
		if strings.HasPrefix(key, pr) {
			keys = append(keys, key)
		}
	}
	// Sort the items and retrieve the associated values
	sort.Strings(keys)
	for _, key := range keys {
		values = append(values, db.db[key])
	}
	return &iterator{
		keys:   keys,
		values: values,
	}
}

// iterator can walk over the (potentially partial) keyspace of a memory key
// value store. Internally it is a deep copy of the entire iterated state,
// sorted by keys.
type iterator struct {
	inited bool
	keys   []string
	values [][]byte
}

// Next moves the iterator to the next key/value pair. It returns whether the
// iterator is exhausted.
func (it *iterator) Next() bool {
	// If the iterator was not yet initialized, do it now
	if !it.inited {
		it.inited = true
		return len(it.keys) > 0
	}
	// Iterator already initialize, advance it
	if len(it.keys) > 0 {
		it.keys = it.keys[1:]
		it.values = it.values[1:]
	}
	return len(it.keys) > 0
}

// Error returns any accumulated error. Exhausting all the key/value pairs
// is not considered to be an error. A memory iterator cannot encounter errors.
func (it *iterator) Error() error {
	return nil
}

// Key returns the key of the current key/value pair, or nil if done. The caller
// should not modify the contents of the returned slice, and its contents may
// change on the next call to Next.
func (it *iterator) Key() []byte {
	if len(it.keys) > 0 {
		return []byte(it.keys[0])
	}
	return nil
}

// Value returns the value of the current key/value pair, or nil if done. The
// caller should not modify the contents of the returned slice, and its contents
// may change on the next call to Next.
func (it *iterator) Value() []byte {
	if len(it.values) > 0 {
		return it.values[0]
	}
	return nil
}

// Release releases associated resources. Release should always succeed and can
// be called multiple times without causing error.
func (it *iterator) Release() {
	it.keys, it.values = nil, nil
}

func NewMemDatabase() *MemDatabase {
	return &MemDatabase{
		db: make(map[string][]byte),
	}
}

func NewMemDatabaseWithCap(size int) *MemDatabase {
	return &MemDatabase{
		db: make(map[string][]byte, size),
	}
}

func (db *MemDatabase) Put(key []byte, value []byte) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	db.db[string(key)] = common.CopyBytes(value)
	return nil
}

func (db *MemDatabase) Has(key []byte) (bool, error) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	_, ok := db.db[string(key)]
	return ok, nil
}

func (db *MemDatabase) Get(key []byte) ([]byte, error) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	if entry, ok := db.db[string(key)]; ok {
		return common.CopyBytes(entry), nil
	}
	return nil, errors.New("not found")
}

func (db *MemDatabase) Keys() [][]byte {
	db.lock.RLock()
	defer db.lock.RUnlock()

	keys := [][]byte{}
	for key := range db.db {
		keys = append(keys, []byte(key))
	}
	return keys
}

func (db *MemDatabase) Delete(key []byte) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	delete(db.db, string(key))
	return nil
}

func (db *MemDatabase) Close() {}

func (db *MemDatabase) NewBatch() Batch {
	return &memBatch{db: db}
}

func (db *MemDatabase) Len() int { return len(db.db) }

type kv struct{ k, v []byte }

type memBatch struct {
	db     *MemDatabase
	writes []kv
	size   int
}

func (b *memBatch) NewIterator() Iterator {
	return b.NewIterator()
}

func (b *memBatch) NewIteratorWithStart(start []byte) Iterator {
	return b.NewIteratorWithStart(start)
}

func (b *memBatch) NewIteratorWithPrefix(prefix []byte) Iterator {
	return b.NewIteratorWithPrefix(prefix)
}

func (b *memBatch) Has(key []byte) (bool, error) {
	return b.Has(key)
}

func (b *memBatch) Get(key []byte) ([]byte, error) {
	return b.Get(key)
}

func (b *memBatch) Replay(w KeyValueWriter) error {
	return b.Replay(w)
}

func (b *memBatch) Put(key, value []byte) error {
	b.writes = append(b.writes, kv{common.CopyBytes(key), common.CopyBytes(value)})
	b.size += len(value)
	return nil
}

func (b *memBatch) Delete(key []byte) error {
	b.writes = append(b.writes, kv{common.CopyBytes(key), nil})
	return nil
}

func (b *memBatch) Write() error {
	b.db.lock.Lock()
	defer b.db.lock.Unlock()

	for _, kv := range b.writes {
		if kv.v == nil {
			delete(b.db.db, string(kv.k))
			continue
		}
		b.db.db[string(kv.k)] = kv.v
	}
	return nil
}

func (b *memBatch) ValueSize() int {
	return b.size
}

func (b *memBatch) Reset() {
	b.writes = b.writes[:0]
	b.size = 0
}
