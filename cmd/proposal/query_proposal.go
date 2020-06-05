package main

import (
	"github.com/taiyuechain/taiyuechain/cmd/utils"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/core/types"
	"gopkg.in/urfave/cli.v1"
	"math/big"
)

var queryStakingCommand = cli.Command{
	Name:   "querystaking",
	Usage:  "Query staking info, can cancel info and can withdraw info",
	Action: utils.MigrateFlags(queryStakingImpawn),
	Flags:  append(ProposalFlags, AddressFlag),
}

func queryStakingImpawn(ctx *cli.Context) error {
	loadPrivate(ctx)
	conn, url := dialConn(ctx)
	printBaseInfo(conn, url)

	queryStakingInfo(conn, true)
	return nil
}

var sendCommand = cli.Command{
	Name:   "send",
	Usage:  "Send general transaction",
	Action: utils.MigrateFlags(sendTX),
	Flags:  append(ProposalFlags, AddressFlag),
}

func sendTX(ctx *cli.Context) error {
	loadPrivate(ctx)
	conn, url := dialConn(ctx)
	printBaseInfo(conn, url)
	PrintBalance(conn, from)

	address := ctx.GlobalString(AddressFlag.Name)
	if !common.IsHexAddress(address) {
		printError("Must input correct address")
	}

	value := trueToWei(ctx, false)
	txHash := sendContractTransaction(conn, from, common.HexToAddress(address), value, priKey, nil, cert)
	getResult(conn, txHash, false, false)
	return nil
}

var depositDCommand = cli.Command{
	Name:   "deposit",
	Usage:  "Deposit staking on a validator address",
	Action: utils.MigrateFlags(delegateImpawn),
	Flags:  append(ProposalFlags, AddressFlag),
}

var withdrawDCommand = cli.Command{
	Name:   "withdraw",
	Usage:  "Call this will instant receive your deposit money",
	Action: utils.MigrateFlags(withdrawDImpawn),
	Flags:  append(ProposalFlags, AddressFlag),
}

var delegateCommand = cli.Command{
	Name:  "delegate",
	Usage: "Delegate staking on a validator address",
	Subcommands: []cli.Command{
		depositDCommand,
		withdrawDCommand,
	},
}

func delegateImpawn(ctx *cli.Context) error {
	loadPrivate(ctx)
	conn, url := dialConn(ctx)
	printBaseInfo(conn, url)

	PrintBalance(conn, from)

	value := trueToWei(ctx, false)

	address := ctx.GlobalString(AddressFlag.Name)
	if !common.IsHexAddress(address) {
		printError("Must input correct address")
	}
	holder = common.HexToAddress(address)

	input := packInput("delegate", holder, value)
	txHash := sendContractTransaction(conn, from, types.CACertListAddress, nil, priKey, input, cert)

	getResult(conn, txHash, true, true)
	return nil
}

func withdrawDImpawn(ctx *cli.Context) error {
	loadPrivate(ctx)
	conn, url := dialConn(ctx)
	printBaseInfo(conn, url)
	PrintBalance(conn, from)

	value := trueToWei(ctx, false)

	address := ctx.GlobalString(AddressFlag.Name)
	if !common.IsHexAddress(address) {
		printError("Must input correct address")
	}
	holder = common.HexToAddress(address)
	input := packInput("withdrawDelegate", holder, value)

	txHash := sendContractTransaction(conn, from, types.CACertListAddress, new(big.Int).SetInt64(0), priKey, input, cert)

	getResult(conn, txHash, true, true)
	PrintBalance(conn, from)
	return nil
}

var queryTxCommand = cli.Command{
	Name:   "querytx",
	Usage:  "Query tx hash, get transaction result",
	Action: utils.MigrateFlags(queryTxImpawn),
	Flags:  append(ProposalFlags, TxHashFlag),
}

func queryTxImpawn(ctx *cli.Context) error {
	conn, url := dialConn(ctx)
	printBaseInfo(conn, url)

	txhash := ctx.GlobalString(TxHashFlag.Name)
	if txhash == "" {
		printError("Must input tx hash")
	}
	queryTx(conn, common.HexToHash(txhash), true)
	return nil
}
