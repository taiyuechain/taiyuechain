package main

import (
	"fmt"
	"github.com/taiyuechain/taiyuechain/cmd/utils"
	"gopkg.in/urfave/cli.v1"
	"os"
	"path/filepath"
	"sort"
)

var (
	// The app that holds all commands and flags.
	app *cli.App

	// Flags needed by abigen
	KeyFlag = cli.StringFlag{
		Name:  "key",
		Usage: "Private key file path",
		Value: "",
	}
	KeyStoreFlag = cli.StringFlag{
		Name:  "keystore",
		Usage: "Keystore file path",
	}
	CertKeyFlag = cli.StringFlag{
		Name:  "certpath",
		Usage: "Obtain cert for send tx",
		Value: "",
	}
	TrueValueFlag = cli.Uint64Flag{
		Name:  "value",
		Usage: "Staking value units one true",
		Value: 0,
	}
	AddressFlag = cli.StringFlag{
		Name:  "address",
		Usage: "Transfer address",
		Value: "",
	}
	TxHashFlag = cli.StringFlag{
		Name:  "txhash",
		Usage: "Input transaction hash",
		Value: "",
	}
	BftCertFlag = cli.StringFlag{
		Name:  "bftcert",
		Usage: "Obtain cert for multi proposal",
		Value: "",
	}
	ProposalCertFlag = cli.StringFlag{
		Name:  "proposalcert",
		Usage: "Obtain cert for proposal validator",
		Value: "",
	}
	ProposalFlags = []cli.Flag{
		KeyFlag,
		KeyStoreFlag,
		utils.RPCListenAddrFlag,
		utils.RPCPortFlag,
		TrueValueFlag,
		BftCertFlag,
		ProposalCertFlag,
	}
)

func init() {
	app = cli.NewApp()
	app.Usage = "taiyuechain Multi Proposal tool"
	app.Name = filepath.Base(os.Args[0])
	app.Version = "1.0.0"
	app.Copyright = "Copyright 2020-2021 The taiyuechain Authors"
	app.Flags = []cli.Flag{
		KeyFlag,
		KeyStoreFlag,
		utils.RPCListenAddrFlag,
		utils.RPCPortFlag,
		TrueValueFlag,
		AddressFlag,
		TxHashFlag,
		CertKeyFlag,
		BftCertFlag,
		ProposalCertFlag,
	}
	app.Action = utils.MigrateFlags(proposal)
	app.CommandNotFound = func(ctx *cli.Context, cmd string) {
		fmt.Fprintf(os.Stderr, "No such command: %s\n", cmd)
		os.Exit(1)
	}
	// Add subcommands.
	app.Commands = []cli.Command{
		queryAmountCommand,
		sendCommand,
		deleteCommand,
		queryTxCommand,
	}
	cli.CommandHelpTemplate = utils.CommandHelpTemplate
	sort.Sort(cli.CommandsByName(app.Commands))
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
