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

package etruedb

import (
	"errors"
	"sync"

	"github.com/ethereum/go-ethereum/common"
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

func (db *MemDatabase) NewIterator() Iterator {
	return db.NewIterator()
}

func (db *MemDatabase) NewIteratorWithStart(start []byte) Iterator {
	return db.NewIteratorWithStart(start)
}

func (db *MemDatabase) NewIteratorWithPrefix(prefix []byte) Iterator {
	return db.NewIteratorWithPrefix(prefix)
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
