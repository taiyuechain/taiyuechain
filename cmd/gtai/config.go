package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"unicode"

	"github.com/taiyuechain/taiyuechain/crypto"

	cli "gopkg.in/urfave/cli.v1"

	"github.com/naoina/toml"
	"github.com/taiyuechain/taiyuechain/cmd/utils"

	//"github.com/taiyuechain/taiyuechain/dashboard"
	"github.com/taiyuechain/taiyuechain/node"
	"github.com/taiyuechain/taiyuechain/params"
	"github.com/taiyuechain/taiyuechain/yue"
)

var (
	dumpConfigCommand = cli.Command{
		Action:      utils.MigrateFlags(dumpConfig),
		Name:        "dumpconfig",
		Usage:       "Show configuration values",
		ArgsUsage:   "",
		Flags:       append(append(nodeFlags, rpcFlags...)),
		Category:    "MISCELLANEOUS COMMANDS",
		Description: `The dumpconfig command shows configuration values.`,
	}

	configFileFlag = cli.StringFlag{
		Name:  "config",
		Usage: "TOML configuration file",
	}
)

// These settings ensure that TOML keys use the same names as Go struct fields.
var tomlSettings = toml.Config{
	NormFieldName: func(rt reflect.Type, key string) string {
		return key
	},
	FieldToKey: func(rt reflect.Type, field string) string {
		return field
	},
	MissingField: func(rt reflect.Type, field string) error {
		link := ""
		if unicode.IsUpper(rune(rt.Name()[0])) && rt.PkgPath() != "main" {
			link = fmt.Sprintf(", see https://godoc.org/%s#%s for available fields", rt.PkgPath(), rt.Name())
		}
		return fmt.Errorf("field '%s' is not defined in %s%s", field, rt.String(), link)
	},
}

type etruestatsConfig struct {
	URL string `toml:",omitempty"`
}

type gethConfig struct {
	Etrue      yue.Config
	Node       node.Config
	Etruestats etruestatsConfig
	//Dashboard  dashboard.Config
}

func loadConfig(file string, cfg *gethConfig) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	err = tomlSettings.NewDecoder(bufio.NewReader(f)).Decode(cfg)
	// Add file name to errors that have a line number.
	if _, ok := err.(*toml.LineError); ok {
		err = errors.New(file + ", " + err.Error())
	}
	return err
}

func defaultNodeConfig() node.Config {
	cfg := node.DefaultConfig
	cfg.Name = clientIdentifier
	cfg.Version = params.VersionWithCommit(gitCommit)
	//cfg.HTTPModules = append(cfg.HTTPModules, "etrue", "eth", "shh")
	cfg.HTTPModules = append(cfg.HTTPModules, "yue", "eth", "shh", "etrue")
	cfg.WSModules = append(cfg.WSModules, "yue")
	cfg.IPCPath = "gtai.ipc"
	return cfg
}

func makeConfigNode(ctx *cli.Context) (*node.Node, gethConfig) {
	// Load defaults.
	cfg := gethConfig{
		Etrue: yue.DefaultConfig,
		Node:  defaultNodeConfig(),
		//Dashboard: dashboard.DefaultConfig,
	}

	if ctx.GlobalBool(utils.SingleNodeFlag.Name) {
		//prikey, _ := crypto.HexToECDSA("c1581e25937d9ab91421a3e1a2667c85b0397c75a195e643109938e987acecfc")
		prikey, _ := crypto.HexToECDSA("7631a11e9d28563cdbcf96d581e4b9a19e53ad433a53c25a9f18c74ddf492f75")
		cfg.Etrue.CommitteeKey = crypto.FromECDSA(prikey)

		//cfg.Etrue.MineFruit = true
		cfg.Etrue.NetworkId = 400
		//set node config
		cfg.Node.HTTPPort = 8888
		cfg.Node.HTTPHost = "127.0.0.1"
		cfg.Node.HTTPModules = []string{"db", "etrue", "net", "web3", "personal", "admin", "miner", "eth"}

		ctx.GlobalSet("datadir", "./data")
	}

	// Load config file.
	if file := ctx.GlobalString(configFileFlag.Name); file != "" {
		if err := loadConfig(file, &cfg); err != nil {
			utils.Fatalf("%v", err)
		}
	}

	// Apply flags.
	utils.SetNodeConfig(ctx, &cfg.Node)
	stack, err := node.New(&cfg.Node)
	if err != nil {
		utils.Fatalf("Failed to create the protocol stack: %v", err)
	}
	utils.SetTaichainConfig(ctx, stack, &cfg.Etrue)
	if ctx.GlobalIsSet(utils.EtrueStatsURLFlag.Name) {
		cfg.Etruestats.URL = ctx.GlobalString(utils.EtrueStatsURLFlag.Name)
	}

	//utils.SetDashboardConfig(ctx, &cfg.Dashboard)

	return stack, cfg
}

func makeFullNode(ctx *cli.Context) *node.Node {
	stack, cfg := makeConfigNode(ctx)

	utils.RegisterEtrueService(stack, &cfg.Etrue)

	/*if ctx.GlobalBool(utils.DashboardEnabledFlag.Name) {
		utils.RegisterDashboardService(stack, &cfg.Dashboard, gitCommit)
	}*/

	// Add the Taiyuechain Stats daemon if requested.
	if cfg.Etruestats.URL != "" {
		utils.RegisterEtrueStatsService(stack, cfg.Etruestats.URL)
	}
	return stack
}

// dumpConfig is the dumpconfig command.
func dumpConfig(ctx *cli.Context) error {
	_, cfg := makeConfigNode(ctx)
	comment := ""

	if cfg.Etrue.Genesis != nil {
		cfg.Etrue.Genesis = nil
		comment += "# Note: this config doesn't contain the genesis block.\n\n"
	}

	out, err := tomlSettings.Marshal(&cfg)
	if err != nil {
		return err
	}
	io.WriteString(os.Stdout, comment)
	os.Stdout.Write(out)
	return nil
}
