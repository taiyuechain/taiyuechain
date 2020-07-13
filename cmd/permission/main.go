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
	GroupFlag = cli.StringFlag{
		Name:  "group",
		Usage: "Group address",
		Value: "",
	}
	GroupNameFlag = cli.StringFlag{
		Name:  "groupname",
		Usage: "Group name",
		Value: "",
	}
	ContractFlag = cli.StringFlag{
		Name:  "contract",
		Usage: "Group address",
		Value: "",
	}
	MemberFlag = cli.StringFlag{
		Name:  "member",
		Usage: "Member address",
		Value: "",
	}
	PermissionFlag = cli.Uint64Flag{
		Name:  "permission",
		Usage: "Permission value",
		Value: 0,
	}
	PKFlag = cli.StringFlag{
		Name:  "pk",
		Usage: "Cert pub",
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
		GroupFlag,
		MemberFlag,
		PermissionFlag,
		ContractFlag,
		GroupNameFlag,
		PKFlag,
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
		BftCertFlag,
		ProposalCertFlag,
		GroupFlag,
		MemberFlag,
		PermissionFlag,
		ContractFlag,
		GroupNameFlag,
		PKFlag,
	}
	app.Action = utils.MigrateFlags(proposal)
	app.CommandNotFound = func(ctx *cli.Context, cmd string) {
		fmt.Fprintf(os.Stderr, "No such command: %s\n", cmd)
		os.Exit(1)
	}
	// Add subcommands.
	app.Commands = []cli.Command{
		queryCAAmountCommand,
		grantTxPermissionCommand,
		revokeTxPermissionCommand,
		grantContractPermissionCommand,
		revokeContractPermissionCommand,
		createCommand,
		deleteCommand,
		sendCommand,
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
