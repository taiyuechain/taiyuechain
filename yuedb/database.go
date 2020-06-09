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
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/taiyuechain/taiyuechain/log"
	"github.com/taiyuechain/taiyuechain/metrics"
)

const (
	writeDelayNThreshold       = 200
	writeDelayThreshold        = 350 * time.Millisecond
	writeDelayWarningThrottler = 1 * time.Minute
)

var OpenFileLimit = 64

// AncientReader contains the methods required to read from immutable ancient data.
type AncientReader interface {
	// HasAncient returns an indicator whether the specified data exists in the
	// ancient store.
	HasAncient(kind string, number uint64) (bool, error)

	// Ancient retrieves an ancient binary blob from the append-only immutable files.
	Ancient(kind string, number uint64) ([]byte, error)

	// Ancients returns the ancient item numbers in the ancient store.
	Ancients() (uint64, error)

	// AncientSize returns the ancient size of the specified category.
	AncientSize(kind string) (uint64, error)
}

//caoliang add
/*// AncientReader contains the methods required to read from immutable ancient data.
type AncientReader interface {
	// HasAncient returns an indicator whether the specified data exists in the
	// ancient store.
	HasAncient(kind string, number uint64) (bool, error)

	// Ancient retrieves an ancient binary blob from the append-only immutable files.
	Ancient(kind string, number uint64) ([]byte, error)

	// Ancients returns the ancient item numbers in the ancient store.
	Ancients() (uint64, error)

	// AncientSize returns the ancient size of the specified category.
	AncientSize(kind string) (uint64, error)
}*/

// AncientWriter contains the methods required to write to immutable ancient data.
type AncientWriter interface {
	// AppendAncient injects all binary blobs belong to block at the end of the
	// append-only immutable table files.
	AppendAncient(number uint64, hash, header, body, receipt, td []byte) error

	// TruncateAncients discards all but the first n ancient data from the ancient store.
	TruncateAncients(n uint64) error

	// Sync flushes all in-memory ancient store data to disk.
	Sync() error
}

// Reader contains the methods required to read data from both key-value as well as
// immutable ancient data.
type Reader interface {
	KeyValueReader
	AncientReader
}

// Writer contains the methods required to write data to both key-value as well as
// immutable ancient data.
type Writer interface {
	KeyValueWriter
	AncientWriter
}

//caoliang add
type LDBDatabase struct {
	fn string      // filename for reporting
	db *leveldb.DB // LevelDB instance

	compTimeMeter    metrics.Meter // Meter for measuring the total time spent in database compaction
	compReadMeter    metrics.Meter // Meter for measuring the data read during compaction
	compWriteMeter   metrics.Meter // Meter for measuring the data written during compaction
	writeDelayNMeter metrics.Meter // Meter for measuring the write delay number due to database compaction
	writeDelayMeter  metrics.Meter // Meter for measuring the write delay duration due to database compaction
	diskReadMeter    metrics.Meter // Meter for measuring the effective amount of data read
	diskWriteMeter   metrics.Meter // Meter for measuring the effective amount of data written

	quitLock sync.Mutex      // Mutex protecting the quit channel access
	quitChan chan chan error // Quit channel to stop the metrics collection before closing the database
	log      log.Logger      // Contextual logger tracking the database path
}

func (db *LDBDatabase) NewIteratorWithPrefix(prefix []byte) Iterator {
	return db.NewIteratorWithPrefix(prefix)
}

func (db *LDBDatabase) NewIterator() Iterator {
	return db.NewIterator()
}

/*func (db *LDBDatabase) NewIteratorWithPrefix(prefix []byte) Iterator {
	panic("implement me")
}*/

// NewIteratorWithStart creates a binary-alphabetical iterator over a subset of
// database content starting at a particular initial key (or after, if it does
// not exist).
func (db *LDBDatabase) NewIteratorWithStart(start []byte) Iterator {
	return db.NewIteratorWithStart(start)
}

// NewIteratorWithPrefix creates a binary-alphabetical iterator over a subset
// of database content with a particular key prefix.

func (db *LDBDatabase) Stat(property string) (string, error) {
	return db.Stat(property)
}

func (db *LDBDatabase) Compact(start []byte, limit []byte) error {
	return db.Compact(start, limit)
}

func (db *LDBDatabase) HasAncient(kind string, number uint64) (bool, error) {
	return db.HasAncient(kind, number)
}

func (db *LDBDatabase) Ancient(kind string, number uint64) ([]byte, error) {
	return db.Ancient(kind, number)
}

func (db *LDBDatabase) Ancients() (uint64, error) {
	return db.Ancients()
}

func (db *LDBDatabase) AncientSize(kind string) (uint64, error) {
	return db.AncientSize(kind)
}

func (db *LDBDatabase) AppendAncient(number uint64, hash, header, body, receipt, td []byte) error {
	return db.AppendAncient(number, hash, header, body, receipt, td)
}

func (db *LDBDatabase) TruncateAncients(n uint64) error {
	return db.TruncateAncients(n)
}

func (db *LDBDatabase) Sync() error {
	return db.Sync()
}

// NewLDBDatabase returns a LevelDB wrapped object.
func NewLDBDatabase(file string, cache int, handles int) (*LDBDatabase, error) {
	logger := log.New("database", file)

	// Ensure we have some minimal caching and file guarantees
	if cache < 16 {
		cache = 16
	}
	if handles < 16 {
		handles = 16
	}
	logger.Info("Allocated cache and file handles", "cache", cache, "handles", handles)

	// Open the db and recover any potential corruptions
	db, err := leveldb.OpenFile(file, &opt.Options{
		OpenFilesCacheCapacity: handles,
		BlockCacheCapacity:     cache / 2 * opt.MiB,
		WriteBuffer:            cache / 4 * opt.MiB, // Two of these are used internally
		Filter:                 filter.NewBloomFilter(10),
	})
	if _, corrupted := err.(*errors.ErrCorrupted); corrupted {
		db, err = leveldb.RecoverFile(file, nil)
	}
	// (Re)check for errors and abort if opening of the db failed
	if err != nil {
		return nil, err
	}
	return &LDBDatabase{
		fn:  file,
		db:  db,
		log: logger,
	}, nil
}

// Path returns the path to the database directory.
func (db *LDBDatabase) Path() string {
	return db.fn
}

// Put puts the given key / value to the queue
func (db *LDBDatabase) Put(key []byte, value []byte) error {
	return db.db.Put(key, value, nil)
}

func (db *LDBDatabase) Has(key []byte) (bool, error) {
	return db.db.Has(key, nil)
}

// Get returns the given key if it's present.
func (db *LDBDatabase) Get(key []byte) ([]byte, error) {
	dat, err := db.db.Get(key, nil)
	if err != nil {
		return nil, err
	}
	return dat, nil
}

// Delete deletes the key from the queue and database
func (db *LDBDatabase) Delete(key []byte) error {
	return db.db.Delete(key, nil)
}

/*func (db *LDBDatabase) NewIterator() iterator.Iterator {
	return db.db.NewIterator(nil, nil)
}*/

// NewIteratorWithPrefix returns a iterator to iterate over subset of database content with a particular prefix.
/*func (db *LDBDatabase) NewIteratorWithPrefix(prefix []byte) iterator.Iterator {
	return db.db.NewIterator(util.BytesPrefix(prefix), nil)
}*/

func (db *LDBDatabase) Close() {
	// Stop the metrics collection to avoid internal database races
	db.quitLock.Lock()
	defer db.quitLock.Unlock()

	if db.quitChan != nil {
		errc := make(chan error)
		db.quitChan <- errc
		if err := <-errc; err != nil {
			db.log.Error("Metrics collection failed", "err", err)
		}
		db.quitChan = nil
	}
	err := db.db.Close()
	if err == nil {
		db.log.Info("Database closed")
	} else {
		db.log.Error("Failed to close database", "err", err)
	}
}

func (db *LDBDatabase) LDB() *leveldb.DB {
	return db.db
}

// Meter configures the database metrics collectors and
func (db *LDBDatabase) Meter(prefix string) {
	if metrics.Enabled {
		// Initialize all the metrics collector at the requested prefix
		db.compTimeMeter = metrics.NewRegisteredMeter(prefix+"compact/time", nil)
		db.compReadMeter = metrics.NewRegisteredMeter(prefix+"compact/input", nil)
		db.compWriteMeter = metrics.NewRegisteredMeter(prefix+"compact/output", nil)
		db.diskReadMeter = metrics.NewRegisteredMeter(prefix+"disk/read", nil)
		db.diskWriteMeter = metrics.NewRegisteredMeter(prefix+"disk/write", nil)
	}
	// Initialize write delay metrics no matter we are in metric mode or not.
	db.writeDelayMeter = metrics.NewRegisteredMeter(prefix+"compact/writedelay/duration", nil)
	db.writeDelayNMeter = metrics.NewRegisteredMeter(prefix+"compact/writedelay/counter", nil)

	// Create a quit channel for the periodic collector and run it
	db.quitLock.Lock()
	db.quitChan = make(chan chan error)
	db.quitLock.Unlock()

	go db.meter(3 * time.Second)
}

// meter periodically retrieves internal leveldb counters and reports them to
// the metrics subsystem.
//
// This is how a stats table look like (currently):
//   Compactions
//    Level |   Tables   |    Size(MB)   |    Time(sec)  |    Read(MB)   |   Write(MB)
//   -------+------------+---------------+---------------+---------------+---------------
//      0   |          0 |       0.00000 |       1.27969 |       0.00000 |      12.31098
//      1   |         85 |     109.27913 |      28.09293 |     213.92493 |     214.26294
//      2   |        523 |    1000.37159 |       7.26059 |      66.86342 |      66.77884
//      3   |        570 |    1113.18458 |       0.00000 |       0.00000 |       0.00000
//
// This is how the write delay look like (currently):
// DelayN:5 Delay:406.604657ms Paused: false
//
// This is how the iostats look like (currently):
// Read(MB):3895.04860 Write(MB):3654.64712
func (db *LDBDatabase) meter(refresh time.Duration) {
	// Create the counters to store current and previous compaction values
	compactions := make([][]float64, 2)
	for i := 0; i < 2; i++ {
		compactions[i] = make([]float64, 3)
	}
	// Create storage for iostats.
	var iostats [2]float64

	// Create storage and warning log tracer for write delay.
	var (
		delaystats      [2]int64
		lastWriteDelay  time.Time
		lastWriteDelayN time.Time
		lastWritePaused time.Time
	)

	var (
		errc chan error
		merr error
	)

	// Iterate ad infinitum and collect the stats
	for i := 1; errc == nil && merr == nil; i++ {
		// Retrieve the database stats
		stats, err := db.db.GetProperty("leveldb.stats")
		if err != nil {
			db.log.Error("Failed to read database stats", "err", err)
			merr = err
			continue
		}
		// Find the compaction table, skip the header
		lines := strings.Split(stats, "\n")
		for len(lines) > 0 && strings.TrimSpace(lines[0]) != "Compactions" {
			lines = lines[1:]
		}
		if len(lines) <= 3 {
			db.log.Error("Compaction table not found")
			merr = errors.New("compaction table not found")
			continue
		}
		lines = lines[3:]

		// Iterate over all the table rows, and accumulate the entries
		for j := 0; j < len(compactions[i%2]); j++ {
			compactions[i%2][j] = 0
		}
		for _, line := range lines {
			parts := strings.Split(line, "|")
			if len(parts) != 6 {
				break
			}
			for idx, counter := range parts[3:] {
				value, err := strconv.ParseFloat(strings.TrimSpace(counter), 64)
				if err != nil {
					db.log.Error("Compaction entry parsing failed", "err", err)
					merr = err
					continue
				}
				compactions[i%2][idx] += value
			}
		}
		// Update all the requested meters
		if db.compTimeMeter != nil {
			db.compTimeMeter.Mark(int64((compactions[i%2][0] - compactions[(i-1)%2][0]) * 1000 * 1000 * 1000))
		}
		if db.compReadMeter != nil {
			db.compReadMeter.Mark(int64((compactions[i%2][1] - compactions[(i-1)%2][1]) * 1024 * 1024))
		}
		if db.compWriteMeter != nil {
			db.compWriteMeter.Mark(int64((compactions[i%2][2] - compactions[(i-1)%2][2]) * 1024 * 1024))
		}

		// Retrieve the write delay statistic
		writedelay, err := db.db.GetProperty("leveldb.writedelay")
		if err != nil {
			db.log.Error("Failed to read database write delay statistic", "err", err)
			merr = err
			continue
		}
		var (
			delayN        int64
			delayDuration string
			duration      time.Duration
			paused        bool
		)
		if n, err := fmt.Sscanf(writedelay, "DelayN:%d Delay:%s Paused:%t", &delayN, &delayDuration, &paused); n != 3 || err != nil {
			db.log.Error("Write delay statistic not found")
			merr = err
			continue
		}
		duration, err = time.ParseDuration(delayDuration)
		if err != nil {
			db.log.Error("Failed to parse delay duration", "err", err)
			merr = err
			continue
		}
		if db.writeDelayNMeter != nil {
			db.writeDelayNMeter.Mark(delayN - delaystats[0])
			// If the write delay number been collected in the last minute exceeds the predefined threshold,
			// print a warning log here.
			// If a warning that db performance is laggy has been displayed,
			// any subsequent warnings will be withhold for 1 minute to don't overwhelm the user.
			if int(db.writeDelayNMeter.Rate1()) > writeDelayNThreshold &&
				time.Now().After(lastWriteDelayN.Add(writeDelayWarningThrottler)) {
				db.log.Warn("Write delay number exceeds the threshold (200 per second) in the last minute")
				lastWriteDelayN = time.Now()
			}
		}
		if db.writeDelayMeter != nil {
			db.writeDelayMeter.Mark(duration.Nanoseconds() - delaystats[1])
			// If the write delay duration been collected in the last minute exceeds the predefined threshold,
			// print a warning log here.
			// If a warning that db performance is laggy has been displayed,
			// any subsequent warnings will be withhold for 1 minute to don't overwhelm the user.
			if int64(db.writeDelayMeter.Rate1()) > writeDelayThreshold.Nanoseconds() &&
				time.Now().After(lastWriteDelay.Add(writeDelayWarningThrottler)) {
				db.log.Warn("Write delay duration exceeds the threshold (35% of the time) in the last minute")
				lastWriteDelay = time.Now()
			}
		}
		// If a warning that db is performing compaction has been displayed, any subsequent
		// warnings will be withheld for one minute not to overwhelm the user.
		if paused && delayN-delaystats[0] == 0 && duration.Nanoseconds()-delaystats[1] == 0 &&
			time.Now().After(lastWritePaused.Add(writeDelayWarningThrottler)) {
			db.log.Warn("Database compacting, degraded performance")
			lastWritePaused = time.Now()
		}

		delaystats[0], delaystats[1] = delayN, duration.Nanoseconds()

		// Retrieve the database iostats.
		ioStats, err := db.db.GetProperty("leveldb.iostats")
		if err != nil {
			db.log.Error("Failed to read database iostats", "err", err)
			merr = err
			continue
		}
		var nRead, nWrite float64
		parts := strings.Split(ioStats, " ")
		if len(parts) < 2 {
			db.log.Error("Bad syntax of ioStats", "ioStats", ioStats)
			merr = fmt.Errorf("bad syntax of ioStats %s", ioStats)
			continue
		}
		if n, err := fmt.Sscanf(parts[0], "Read(MB):%f", &nRead); n != 1 || err != nil {
			db.log.Error("Bad syntax of read entry", "entry", parts[0])
			merr = err
			continue
		}
		if n, err := fmt.Sscanf(parts[1], "Write(MB):%f", &nWrite); n != 1 || err != nil {
			db.log.Error("Bad syntax of write entry", "entry", parts[1])
			merr = err
			continue
		}
		if db.diskReadMeter != nil {
			db.diskReadMeter.Mark(int64((nRead - iostats[0]) * 1024 * 1024))
		}
		if db.diskWriteMeter != nil {
			db.diskWriteMeter.Mark(int64((nWrite - iostats[1]) * 1024 * 1024))
		}
		iostats[0], iostats[1] = nRead, nWrite

		// Sleep a bit, then repeat the stats collection
		select {
		case errc = <-db.quitChan:
			// Quit requesting, stop hammering the database
		case <-time.After(refresh):
			// Timeout, gather a new set of stats
		}
	}

	if errc == nil {
		errc = <-db.quitChan
	}
	errc <- merr
}

func (db *LDBDatabase) NewBatch() Batch {
	return &ldbBatch{db: db.db, b: new(leveldb.Batch)}
}

type ldbBatch struct {
	db   *leveldb.DB
	b    *leveldb.Batch
	size int
}

func (b *ldbBatch) NewIterator() Iterator {
	return b.NewIterator()
}

func (b *ldbBatch) NewIteratorWithStart(start []byte) Iterator {
	return b.NewIteratorWithStart(start)
}

func (b *ldbBatch) NewIteratorWithPrefix(prefix []byte) Iterator {
	return b.NewIteratorWithPrefix(prefix)
}

func (b *ldbBatch) Has(key []byte) (bool, error) {
	return b.Has(key)
}

func (b *ldbBatch) Get(key []byte) ([]byte, error) {
	return b.Get(key)
}

func (b *ldbBatch) Replay(w KeyValueWriter) error {
	return b.Replay(w)
}

func (b *ldbBatch) Put(key, value []byte) error {
	b.b.Put(key, value)
	b.size += len(value)
	return nil
}

func (b *ldbBatch) Delete(key []byte) error {
	b.b.Delete(key)
	b.size += 1
	return nil
}

func (b *ldbBatch) Write() error {
	return b.db.Write(b.b, nil)
}

func (b *ldbBatch) ValueSize() int {
	return b.size
}

func (b *ldbBatch) Reset() {
	b.b.Reset()
	b.size = 0
}

type table struct {
	db     Database
	prefix string
}

func (dt *table) Stat(property string) (string, error) {
	return dt.Stat(property)
}

func (dt *table) Compact(start []byte, limit []byte) error {
	return dt.Compact(start, limit)
}

func (dt *table) HasAncient(kind string, number uint64) (bool, error) {
	return dt.HasAncient(kind, number)
}

func (dt *table) Ancient(kind string, number uint64) ([]byte, error) {
	return dt.Ancient(kind, number)
}

func (dt *table) Ancients() (uint64, error) {
	return dt.Ancients()
}

func (dt *table) AncientSize(kind string) (uint64, error) {
	return dt.AncientSize(kind)
}

func (dt *table) AppendAncient(number uint64, hash, header, body, receipt, td []byte) error {
	return dt.AppendAncient(number, hash, header, body, receipt, td)
}

func (dt *table) TruncateAncients(n uint64) error {
	return dt.TruncateAncients(n)
}

func (dt *table) Sync() error {
	return dt.Sync()
}

func (dt *table) NewIterator() Iterator {
	return dt.NewIterator()
}

func (dt *table) NewIteratorWithStart(start []byte) Iterator {
	return dt.NewIteratorWithStart(start)
}

func (dt *table) NewIteratorWithPrefix(prefix []byte) Iterator {
	return dt.NewIteratorWithPrefix(prefix)
}

// NewTable returns a Database object that prefixes all keys with a given
// string.
func NewTable(db Database, prefix string) Database {
	return &table{
		db:     db,
		prefix: prefix,
	}
}

func (dt *table) Put(key []byte, value []byte) error {
	return dt.db.Put(append([]byte(dt.prefix), key...), value)
}

func (dt *table) Has(key []byte) (bool, error) {
	return dt.db.Has(append([]byte(dt.prefix), key...))
}

func (dt *table) Get(key []byte) ([]byte, error) {
	return dt.db.Get(append([]byte(dt.prefix), key...))
}

func (dt *table) Delete(key []byte) error {
	return dt.db.Delete(append([]byte(dt.prefix), key...))
}

func (dt *table) Close() {
	// Do nothing; don't close the underlying DB.
}

type tableBatch struct {
	batch  Batch
	prefix string
}

func (tb *tableBatch) NewIterator() Iterator {
	return tb.NewIterator()
}

func (tb *tableBatch) NewIteratorWithStart(start []byte) Iterator {
	return tb.NewIteratorWithStart(start)
}

func (tb *tableBatch) NewIteratorWithPrefix(prefix []byte) Iterator {
	return tb.NewIteratorWithPrefix(prefix)
}

func (tb *tableBatch) Has(key []byte) (bool, error) {
	return tb.Has(key)
}

func (tb *tableBatch) Get(key []byte) ([]byte, error) {
	return tb.Get(key)
}

func (tb *tableBatch) Replay(w KeyValueWriter) error {
	return tb.Replay(w)
}

// NewTableBatch returns a Batch object which prefixes all keys with a given string.
func NewTableBatch(db Database, prefix string) Batch {
	return &tableBatch{db.NewBatch(), prefix}
}

func (dt *table) NewBatch() Batch {
	return &tableBatch{dt.db.NewBatch(), dt.prefix}
}

func (tb *tableBatch) Put(key, value []byte) error {
	return tb.batch.Put(append([]byte(tb.prefix), key...), value)
}

func (tb *tableBatch) Delete(key []byte) error {
	return tb.batch.Delete(append([]byte(tb.prefix), key...))
}

func (tb *tableBatch) Write() error {
	return tb.batch.Write()
}

func (tb *tableBatch) ValueSize() int {
	return tb.batch.ValueSize()
}

func (tb *tableBatch) Reset() {
	tb.batch.Reset()
}
