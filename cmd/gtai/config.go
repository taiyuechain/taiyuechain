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
	"encoding/hex"
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

		strcert1 := "3082028e3082023aa0030201020201ff300a06082a811ccf55018375303031133011060355040a0c0acea32041636d6520436f3119301706035504031310746573742e6578616d706c652e636f6d301e170d3230303630313034313133385a170d3233303830323133353831385a303031133011060355040a0c0acea32041636d6520436f3119301706035504031310746573742e6578616d706c652e636f6d3059301306072a8648ce3d020106082a811ccf5501822d03420004bdf9699d20b4ebabe76e76260480e5492c87aaeda51b138bd22c6d66b69549313dc3eb8c96dc9a1cbbf3b347322c51c05afdd609622277444e0f07e6bd35d8bda38201433082013f300e0603551d0f0101ff04040302020430260603551d25041f301d06082b0601050507030206082b0601050507030106022a030603810b01300f0603551d130101ff040530030101ff300d0603551d0e0406040401020304305f06082b0601050507010104533051302306082b060105050730018617687474703a2f2f6f6373702e6578616d706c652e636f6d302a06082b06010505073002861e687474703a2f2f6372742e6578616d706c652e636f6d2f6361312e637274301a0603551d1104133011820f666f6f2e6578616d706c652e636f6d300f0603551d2004083006300406022a0330570603551d1f0450304e3025a023a021861f687474703a2f2f63726c312e6578616d706c652e636f6d2f6361312e63726c3025a023a021861f687474703a2f2f63726c322e6578616d706c652e636f6d2f6361312e63726c300a06082a811ccf550183750342008851ca997c3b35b6de11fa5e43d04dfb76cd4177c4517e60f72db9373fec1a3731c46b70b562240a1cbd98e22dec6e1fd857e6b88fee893897c39e61e9bb502c01"
		cert1, _ := hex.DecodeString(strcert1)
		cfg.Etrue.NodeCert = cert1

		cfg.Etrue.P2PNodeCert = cert1
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
