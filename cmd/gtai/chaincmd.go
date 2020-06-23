package main

import (
	"encoding/json"
	"fmt"
	"os"
	"io/ioutil"
	"runtime"
	"strconv"
	"sync/atomic"
	"encoding/hex"
	"time"
	"errors"

	"github.com/syndtr/goleveldb/leveldb/util"
	"github.com/taiyuechain/taiyuechain/cmd/utils"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/console"
	"github.com/taiyuechain/taiyuechain/core"
	"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/event"
	"github.com/taiyuechain/taiyuechain/log"
	"github.com/taiyuechain/taiyuechain/params"
	"github.com/taiyuechain/taiyuechain/trie"
	"github.com/taiyuechain/taiyuechain/yue/downloader"
	"github.com/taiyuechain/taiyuechain/yuedb"
	cli "gopkg.in/urfave/cli.v1"
)

var (
	initCommand = cli.Command{
		Action:    utils.MigrateFlags(initGenesis),
		Name:      "init",
		Usage:     "Bootstrap and initialize a new genesis block",
		ArgsUsage: "<genesisPath> <certPath>",
		Flags: []cli.Flag{
			utils.DataDirFlag,
			//utils.LightModeFlag,
		},
		Category: "BLOCKCHAIN COMMANDS",
		Description: `
The init command initializes a new genesis block and definition for the network.
This is a destructive action and changes the network in which you will be
participating.

It expects the genesis file as argument.`,
	}
	enodeCommand = cli.Command{
		Action:    utils.MigrateFlags(localEnode),
		Name:      "enode",
		Usage:     "make a enode string from nodekey",
		ArgsUsage: "<nodekey> <type>",
		Flags: []cli.Flag{
		},
		Category: "BLOCKCHAIN COMMANDS",
		Description: `make a enode string from nodekey.`,
	}
	importCommand = cli.Command{
		Action:    utils.MigrateFlags(importChain),
		Name:      "import",
		Usage:     "Import a blockchain file",
		ArgsUsage: "<filename> (<filename 2> ... <filename N>) ",
		Flags: []cli.Flag{
			utils.DataDirFlag,
			utils.CacheFlag,
			//utils.LightModeFlag,
			utils.GCModeFlag,
			utils.CacheDatabaseFlag,
			utils.CacheGCFlag,
		},
		Category: "BLOCKCHAIN COMMANDS",
		Description: `
The import command imports blocks from an RLP-encoded form. The form can be one file
with several RLP-encoded blocks, or several files can be used.

If only one file is used, import error will result in failure. If several files are used,
processing will proceed even if an individual RLP-file import failure occurs.`,
	}
	exportCommand = cli.Command{
		Action:    utils.MigrateFlags(exportChain),
		Name:      "export",
		Usage:     "Export blockchain into file",
		ArgsUsage: "<filename> <type> [<blockNumFirst> <blockNumLast>]",
		Flags: []cli.Flag{
			utils.DataDirFlag,
			utils.CacheFlag,
			//utils.LightModeFlag,
		},
		Category: "BLOCKCHAIN COMMANDS",
		Description: `
Requires a first argument of the file to write to.
Optional second and third arguments control the first and
last block to write. In this mode, the file will be appended
if already existing.`,
	}
	importPreimagesCommand = cli.Command{
		Action:    utils.MigrateFlags(importPreimages),
		Name:      "import-preimages",
		Usage:     "Import the preimage database from an RLP stream",
		ArgsUsage: "<datafile>",
		Flags: []cli.Flag{
			utils.DataDirFlag,
			utils.CacheFlag,
			//utils.LightModeFlag,
		},
		Category: "BLOCKCHAIN COMMANDS",
		Description: `
	The import-preimages command imports hash preimages from an RLP encoded stream.`,
	}
	exportPreimagesCommand = cli.Command{
		Action:    utils.MigrateFlags(exportPreimages),
		Name:      "export-preimages",
		Usage:     "Export the preimage database into an RLP stream",
		ArgsUsage: "<dumpfile>",
		Flags: []cli.Flag{
			utils.DataDirFlag,
			utils.CacheFlag,
			//utils.LightModeFlag,
		},
		Category: "BLOCKCHAIN COMMANDS",
		Description: `
The export-preimages command export hash preimages to an RLP encoded stream`,
	}
	copydbCommand = cli.Command{
		Action:    utils.MigrateFlags(copyDb),
		Name:      "copydb",
		Usage:     "Create a local chain from a target chaindata folder",
		ArgsUsage: "<sourceChaindataDir>",
		Flags: []cli.Flag{
			utils.DataDirFlag,
			utils.CacheFlag,
			utils.SyncModeFlag,
			utils.FakePoWFlag,
			utils.TestnetFlag,
			utils.DevnetFlag,
		},
		Category: "BLOCKCHAIN COMMANDS",
		Description: `
The first argument must be the directory containing the blockchain to download from`,
	}
	removedbCommand = cli.Command{
		Action:    utils.MigrateFlags(removeDB),
		Name:      "removedb",
		Usage:     "Remove blockchain and state databases",
		ArgsUsage: " ",
		Flags: []cli.Flag{
			utils.DataDirFlag,
			//utils.LightModeFlag,
		},
		Category: "BLOCKCHAIN COMMANDS",
		Description: `
Remove blockchain and state databases`,
	}
	dumpCommand = cli.Command{
		Action:    utils.MigrateFlags(dump),
		Name:      "dump",
		Usage:     "Dump a specific block from storage",
		ArgsUsage: "[<blockHash> | <blockNum>]...",
		Flags: []cli.Flag{
			utils.DataDirFlag,
			utils.CacheFlag,
			//utils.LightModeFlag,
		},
		Category: "BLOCKCHAIN COMMANDS",
		Description: `
The arguments are interpreted as block numbers or hashes.
Use "taiyuechain dump 0" to dump the genesis block.`,
	}
)

// initGenesis will initialise the given JSON format genesis file and writes it as
// the zero'd block (i.e. genesis) or will fail hard if it can't succeed.
func initGenesis(ctx *cli.Context) error {
	// Make sure we have a valid genesis JSON
	genesisPath := ctx.Args().First()
	certPath := ctx.Args().Get(1)
	if len(genesisPath) == 0 || len(certPath) == 0 {
		utils.Fatalf("Must supply path to genesis JSON file or cert path")
	}
	genesis := makeGenesis0(genesisPath,certPath)
	params.ParseExtraDataFromGenesis(genesis.ExtraData)
	// Open an initialise both full and light databases
	stack := makeFullNode(ctx)
	for _, name := range []string{"chaindata", "lightchaindata"} {
		chaindb, err := stack.OpenDatabase(name, 0, 0)
		if err != nil {
			utils.Fatalf("Failed to open database: %v", err)
		}
		_, fastHash, genesisErr := core.SetupGenesisBlock(chaindb, genesis)
		if genesisErr != nil {
			utils.Fatalf("Failed to write fast genesis block: %v", genesisErr)
		}
		log.Info("Successfully wrote genesis state", "database", name, "fastHash", fastHash)
	}
	return nil
}
func makeGenesis0(genesisPath,certPath string) *core.Genesis {
	file, err := os.Open(genesisPath)
	if err != nil {
		utils.Fatalf("Failed to read genesis file: %v", err)
	}
	defer file.Close()

	genesis := new(core.Genesis)
	if err := json.NewDecoder(file).Decode(genesis); err != nil {
		utils.Fatalf("invalid genesis file: %v", err)
	}
	if err := setCertForGenesis(certPath,genesis); err != nil {
		utils.Fatalf("invalid genesis file: %v", err)
	}
	return genesis
}
func setCertForGenesis(certPath string,genesis *core.Genesis) error {
	names,err := getAllFile(certPath)
	if err != nil || len(names) == 0 {
		return errors.New("node ca files or err:" + err.Error())
	}
	certs :=[][]byte{}
	for _,v :=range names {
		if data, err := crypto.ReadPemFileByPath(v); err == nil {
			certs = append(certs,data)
		}
	}
	if len(certs) == 0 {
		return errors.New("wrong CA files")
	}
	genesis.CertList = certs
	return nil
}
func getAllFile(pathname string) ([]string,error) {
	s := []string{}
	rd, err := ioutil.ReadDir(pathname)
	if err != nil {
		return s, err
	}
	for _, fi := range rd {
		if !fi.IsDir() {
			fullName := pathname + "/" + fi.Name()
			s = append(s, fullName)
		}
	}
	return s, nil
}
func importChain(ctx *cli.Context) error {
	if len(ctx.Args()) < 1 {
		utils.Fatalf("This command requires an argument.")
	}
	stack := makeFullNode(ctx)
	fchain, chainDb := utils.MakeChain(ctx, stack)
	defer chainDb.Close()

	// Start periodically gathering memory profiles
	var peakMemAlloc, peakMemSys uint64
	go func() {
		stats := new(runtime.MemStats)
		for {
			runtime.ReadMemStats(stats)
			if atomic.LoadUint64(&peakMemAlloc) < stats.Alloc {
				atomic.StoreUint64(&peakMemAlloc, stats.Alloc)
			}
			if atomic.LoadUint64(&peakMemSys) < stats.Sys {
				atomic.StoreUint64(&peakMemSys, stats.Sys)
			}
			time.Sleep(5 * time.Second)
		}
	}()
	// Import the chain
	start := time.Now()

	if len(ctx.Args()) == 1 {
		if err := utils.ImportChain(fchain, ctx.Args().First()); err != nil {
			log.Error("Import fast error", "err", err)
		}
		/*if err := utils.ImportSnailChain(schain, ctx.Args().First()); err != nil {
			log.Error("Import snail error", "err", err)
		}*/

	} else {
		for _, arg := range ctx.Args() {
			if err := utils.ImportChain(fchain, arg); err != nil {
				log.Error("Import fast error", "file", arg, "err", err)
			}
			/*if err := utils.ImportSnailChain(schain, arg); err != nil {
				log.Error("Import snail error", "file", arg, "err", err)
			}*/
		}
	}
	fchain.Stop()
	//schain.Stop()

	fmt.Printf("Import done in %v.\n\n", time.Since(start))

	// Output pre-compaction stats mostly to see the import trashing
	db := chainDb.(*yuedb.LDBDatabase)

	stats, err := db.LDB().GetProperty("leveldb.stats")
	if err != nil {
		utils.Fatalf("Failed to read database stats: %v", err)
	}
	fmt.Println(stats)

	ioStats, err := db.LDB().GetProperty("leveldb.iostats")
	if err != nil {
		utils.Fatalf("Failed to read database iostats: %v", err)
	}
	fmt.Println(ioStats)

	fmt.Printf("Trie cache misses:  %d\n", trie.CacheMisses())
	fmt.Printf("Trie cache unloads: %d\n\n", trie.CacheUnloads())

	// Print the memory statistics used by the importing
	mem := new(runtime.MemStats)
	runtime.ReadMemStats(mem)

	fmt.Printf("Object memory: %.3f MB current, %.3f MB peak\n", float64(mem.Alloc)/1024/1024, float64(atomic.LoadUint64(&peakMemAlloc))/1024/1024)
	fmt.Printf("System memory: %.3f MB current, %.3f MB peak\n", float64(mem.Sys)/1024/1024, float64(atomic.LoadUint64(&peakMemSys))/1024/1024)
	fmt.Printf("Allocations:   %.3f million\n", float64(mem.Mallocs)/1000000)
	fmt.Printf("GC pause:      %v\n\n", time.Duration(mem.PauseTotalNs))

	if ctx.GlobalIsSet(utils.NoCompactionFlag.Name) {
		return nil
	}

	// Compact the entire database to more accurately measure disk io and print the stats
	start = time.Now()
	fmt.Println("Compacting entire database...")
	if err = db.LDB().CompactRange(util.Range{}); err != nil {
		utils.Fatalf("Compaction failed: %v", err)
	}
	fmt.Printf("Compaction done in %v.\n\n", time.Since(start))

	stats, err = db.LDB().GetProperty("leveldb.stats")
	if err != nil {
		utils.Fatalf("Failed to read database stats: %v", err)
	}
	fmt.Println(stats)

	ioStats, err = db.LDB().GetProperty("leveldb.iostats")
	if err != nil {
		utils.Fatalf("Failed to read database iostats: %v", err)
	}
	fmt.Println(ioStats)

	return nil
}
func exportChain(ctx *cli.Context) error {
	if len(ctx.Args()) < 2 {
		utils.Fatalf("This command requires an argument.")
	}
	stack := makeFullNode(ctx)
	fchain, _ := utils.MakeChain(ctx, stack)
	start := time.Now()

	fmt.Println(ctx.Args())
	var err error

	if ctx.Args().Get(1) == "fast" {

		fp := ctx.Args().First()
		if len(ctx.Args()) < 3 {
			err = utils.ExportChain(fchain, fp)
		} else {
			// This can be improved to allow for numbers larger than 9223372036854775807
			first, ferr := strconv.ParseInt(ctx.Args().Get(2), 10, 64)
			last, lerr := strconv.ParseInt(ctx.Args().Get(3), 10, 64)
			if ferr != nil || lerr != nil {
				utils.Fatalf("Export error in parsing parameters: block number not an integer\n")
			}
			if first < 0 || last < 0 {
				utils.Fatalf("Export error: block number must be greater than 0\n")
			}
			err = utils.ExportAppendChain(fchain, fp, uint64(first), uint64(last))
		}

	} else {

		//fp := ctx.Args().First()
		if len(ctx.Args()) < 3 {
			//err = utils.ExportSnailChain(schain, fp)
		} else {
			// This can be improved to allow for numbers larger than 9223372036854775807
			first, ferr := strconv.ParseInt(ctx.Args().Get(2), 10, 64)
			last, lerr := strconv.ParseInt(ctx.Args().Get(3), 10, 64)
			if ferr != nil || lerr != nil {
				utils.Fatalf("Export error in parsing parameters: block number not an integer\n")
			}
			if first < 0 || last < 0 {
				utils.Fatalf("Export error: block number must be greater than 0\n")
			}
			//err = utils.ExportAppendSnailChain(schain, fp, uint64(first), uint64(last))
		}

	}

	if err != nil {
		utils.Fatalf("Export error: %v\n", err)
	}
	fmt.Printf("Export done in %v\n", time.Since(start))
	return nil
}
// importPreimages imports preimage data from the specified file.
func importPreimages(ctx *cli.Context) error {
	if len(ctx.Args()) < 1 {
		utils.Fatalf("This command requires an argument.")
	}
	stack := makeFullNode(ctx)
	diskdb := utils.MakeChainDatabase(ctx, stack).(*yuedb.LDBDatabase)

	start := time.Now()
	if err := utils.ImportPreimages(diskdb, ctx.Args().First()); err != nil {
		utils.Fatalf("Export error: %v\n", err)
	}
	fmt.Printf("Export done in %v\n", time.Since(start))
	return nil
}

// exportPreimages dumps the preimage data to specified json file in streaming way.
func exportPreimages(ctx *cli.Context) error {
	if len(ctx.Args()) < 1 {
		utils.Fatalf("This command requires an argument.")
	}
	stack := makeFullNode(ctx)
	diskdb := utils.MakeChainDatabase(ctx, stack).(*yuedb.LDBDatabase)

	start := time.Now()
	if err := utils.ExportPreimages(diskdb, ctx.Args().First()); err != nil {
		utils.Fatalf("Export error: %v\n", err)
	}
	fmt.Printf("Export done in %v\n", time.Since(start))
	return nil
}

func copyDb(ctx *cli.Context) error {
	// Ensure we have a source chain directory to copy
	if len(ctx.Args()) < 1 {
		utils.Fatalf("Source chaindata directory path argument missing")
	}

	// Initialize a new chain for the running node to sync into
	stack := makeFullNode(ctx)
	defer stack.Close()

	chain, chainDb := utils.MakeChain(ctx, stack)
	syncMode := *utils.GlobalTextMarshaler(ctx, utils.SyncModeFlag.Name).(*downloader.SyncMode)

	var syncBloom *trie.SyncBloom
	if syncMode == downloader.FastSync {
		syncBloom = trie.NewSyncBloom(uint64(ctx.GlobalInt(utils.CacheFlag.Name)/2), chainDb)
	}
	dl := downloader.New(0, chainDb, syncBloom, new(event.TypeMux), chain, nil, nil)

	// Create a source peer to satisfy downloader requests from
	db, err := yuedb.NewLDBDatabase(ctx.Args().First(), ctx.GlobalInt(utils.CacheFlag.Name), 256)
	if err != nil {
		return err
	}

	hc, err := core.NewHeaderChain(db, chain.Config(), chain.Engine(), func() bool { return false })
	if err != nil {
		return err
	}
	peer := downloader.NewFakePeer("local", db, hc, dl)
	if err = dl.RegisterPeer("local", 63, peer); err != nil {
		return err
	}
	// Synchronise with the simulated peer
	start := time.Now()

	currentHeader := hc.CurrentHeader()
	if err = dl.Synchronise("local", currentHeader.Hash(), currentHeader.Number, syncMode); err != nil {
		return err
	}
	for dl.Synchronising() {
		time.Sleep(10 * time.Millisecond)
	}
	fmt.Printf("Database copy done in %v\n", time.Since(start))

	// Compact the entire database to remove any sync overhead
	start = time.Now()
	fmt.Println("Compacting entire database...")
	//TODO
	if err = chainDb.(*yuedb.LDBDatabase).LDB().CompactRange(util.Range{}); err != nil {
		utils.Fatalf("Compaction failed: %v", err)
	}
	fmt.Printf("Compaction done in %v.\n\n", time.Since(start))
	return nil
}

func removeDB(ctx *cli.Context) error {
	stack, _ := makeConfigNode(ctx)

	for _, name := range []string{"chaindata", "lightchaindata"} {
		// Ensure the database exists in the first place
		logger := log.New("database", name)

		dbdir := stack.ResolvePath(name)
		if !common.FileExist(dbdir) {
			logger.Info("Database doesn't exist, skipping", "path", dbdir)
			continue
		}
		// Confirm removal and execute
		fmt.Println(dbdir)
		confirm, err := console.Stdin.PromptConfirm("Remove this database?")
		switch {
		case err != nil:
			utils.Fatalf("%v", err)
		case !confirm:
			logger.Warn("Database deletion aborted")
		default:
			start := time.Now()
			os.RemoveAll(dbdir)
			logger.Info("Database successfully deleted", "elapsed", common.PrettyDuration(time.Since(start)))
		}
	}
	return nil
}

func dump(ctx *cli.Context) error {
	return nil
	// stack := makeFullNode(ctx)
	// _, chainDb := utils.MakeChain(ctx, stack)
	// chainDb.Close()
	// return nil
}
func localEnode(ctx *cli.Context) error {
	privStr := ctx.Args().First()
	ct := ctx.Args().Get(1)
	if len(privStr) == 0 {
		utils.Fatalf("Must supply nodekey")
	}
	ct0 := 2
	if len(ct) > 0 {
		if ct1,err := strconv.Atoi(ct); err != nil {
			utils.Fatalf("strconv.Atoi error:%v\n",err)
		} else {
			if ct1>=0 && ct1<=2 {
				ct0 = ct1
			}
		}
	}
	params.KindOfCrypto = byte(ct0)
	
	key, err := hex.DecodeString(privStr)
	if err != nil {
		utils.Fatalf("DecodeString error: %v\n", err)
	}
	if priv, err := crypto.ToECDSA(key); err != nil {
		utils.Fatalf("ToECDSA error: %v\n", err)
	} else {
		str := fmt.Sprintf("enode://%x@127.0.0.1:30303",crypto.FromECDSAPub(&priv.PublicKey)[1:])
		fmt.Println(str)
	}
	return nil
}
// hashish returns true for strings that look like hashes.
func hashish(x string) bool {
	_, err := strconv.Atoi(x)
	return err != nil
}
