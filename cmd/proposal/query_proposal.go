package main

import (
	"context"
	"github.com/taiyuechain/taiyuechain/cmd/utils"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/core/vm"
	"gopkg.in/urfave/cli.v1"
	"log"
	"math/big"
)

var queryCAAmountCommand = cli.Command{
	Name:   "queryamount",
	Usage:  "Query staking info, can cancel info and can withdraw info",
	Action: utils.MigrateFlags(queryCAAmount),
	Flags:  append(ProposalFlags, AddressFlag),
}

func queryCAAmount(ctx *cli.Context) error {
	loadPrivate(ctx)
	conn, url := dialConn(ctx)
	printBaseInfo(conn, url)

	queryCertAmount(conn, true)
	return nil
}

var grantTxPermissionCommand = cli.Command{
	Name:   "granttx",
	Usage:  "grant address tx permission",
	Action: utils.MigrateFlags(grantTxPermission),
	Flags:  append(ProposalFlags, AddressFlag),
}

func grantTxPermission(ctx *cli.Context) error {
	loadPrivate(ctx)
	conn, url := dialConn(ctx)
	printBaseInfo(conn, url)

	PrintBalance(conn, from)

	var group common.Address
	if ctx.GlobalIsSet(GroupFlag.Name) {
		groupstr := ctx.GlobalString(GroupFlag.Name)
		if !common.IsHexAddress(groupstr) {
			printError("Must input correct member address")
		}
		group = common.HexToAddress(groupstr)
	}
	member := ctx.GlobalString(MemberFlag.Name)
	if !common.IsHexAddress(member) {
		printError("Must input correct member address")
	}
	to := common.HexToAddress(member)

	if !ctx.GlobalIsSet(PermissionFlag.Name) {
		printError("Must input correct member address")
	}
	permission := ctx.GlobalUint64(PermissionFlag.Name)
	if trueValue > uint64(vm.PerminType_AccessContract) && trueValue < uint64(vm.ModifyPerminType_AddSendTxPerm) {
		printError("Permission must bigger than 0")
	}

	input := packPermissionInput("grantPermission", common.Address{}, to, group, permission, true)
	txHash := sendContractTransaction(conn, from, types.PermiTableAddress, nil, priKey, input, cert)

	getResult(conn, txHash, true, true)
	return nil
}

var revokeTxPermissionCommand = cli.Command{
	Name:   "revoketx",
	Usage:  "revoke address tx permission",
	Action: utils.MigrateFlags(revokeTxPermission),
	Flags:  append(ProposalFlags, AddressFlag),
}

func revokeTxPermission(ctx *cli.Context) error {
	loadPrivate(ctx)
	conn, url := dialConn(ctx)
	printBaseInfo(conn, url)

	PrintBalance(conn, from)

	var group common.Address
	if ctx.GlobalIsSet(GroupFlag.Name) {
		groupstr := ctx.GlobalString(GroupFlag.Name)
		if !common.IsHexAddress(groupstr) {
			printError("Must input correct member address")
		}
		group = common.HexToAddress(groupstr)
	}
	member := ctx.GlobalString(MemberFlag.Name)
	if !common.IsHexAddress(member) {
		printError("Must input correct member address")
	}
	to := common.HexToAddress(member)

	if !ctx.GlobalIsSet(PermissionFlag.Name) {
		printError("Must input correct member address")
	}
	permission := ctx.GlobalUint64(PermissionFlag.Name)
	if trueValue > uint64(vm.PerminType_AccessContract) && trueValue < uint64(vm.ModifyPerminType_AddSendTxPerm) {
		printError("Permission must bigger than 0")
	}

	input := packPermissionInput("revokePermission", common.Address{}, to, group, permission, true)
	txHash := sendContractTransaction(conn, from, types.PermiTableAddress, nil, priKey, input, cert)

	getResult(conn, txHash, true, true)
	return nil
}

var grantContractPermissionCommand = cli.Command{
	Name:   "grantcontract",
	Usage:  "grant address contract permission",
	Action: utils.MigrateFlags(grantContractPermission),
	Flags:  append(ProposalFlags, AddressFlag),
}

func grantContractPermission(ctx *cli.Context) error {
	loadPrivate(ctx)
	conn, url := dialConn(ctx)
	printBaseInfo(conn, url)

	PrintBalance(conn, from)

	var contract common.Address
	if ctx.GlobalIsSet(ContractFlag.Name) {
		groupstr := ctx.GlobalString(ContractFlag.Name)
		if !common.IsHexAddress(groupstr) {
			printError("Must input correct member address")
		}
		contract = common.HexToAddress(groupstr)
	}
	member := ctx.GlobalString(MemberFlag.Name)
	if !common.IsHexAddress(member) {
		printError("Must input correct member address")
	}
	to := common.HexToAddress(member)

	if !ctx.GlobalIsSet(PermissionFlag.Name) {
		printError("Must input correct member address")
	}
	permission := ctx.GlobalUint64(PermissionFlag.Name)
	if trueValue > uint64(vm.PerminType_AccessContract) && trueValue < uint64(vm.ModifyPerminType_AddSendTxPerm) {
		printError("Permission must bigger than 0")
	}

	input := packPermissionInput("grantPermission", contract, to, common.Address{}, permission, true)
	txHash := sendContractTransaction(conn, from, types.PermiTableAddress, nil, priKey, input, cert)

	getResult(conn, txHash, true, true)
	return nil
}

var revokeContractPermissionCommand = cli.Command{
	Name:   "revokecontract",
	Usage:  "revoke address contract permission",
	Action: utils.MigrateFlags(revokeContractPermission),
	Flags:  append(ProposalFlags, AddressFlag),
}

func revokeContractPermission(ctx *cli.Context) error {
	loadPrivate(ctx)
	conn, url := dialConn(ctx)
	printBaseInfo(conn, url)

	PrintBalance(conn, from)

	var contract common.Address
	if ctx.GlobalIsSet(ContractFlag.Name) {
		groupstr := ctx.GlobalString(ContractFlag.Name)
		if !common.IsHexAddress(groupstr) {
			printError("Must input correct member address")
		}
		contract = common.HexToAddress(groupstr)
	}
	member := ctx.GlobalString(MemberFlag.Name)
	if !common.IsHexAddress(member) {
		printError("Must input correct member address")
	}
	to := common.HexToAddress(member)

	if !ctx.GlobalIsSet(PermissionFlag.Name) {
		printError("Must input correct member address")
	}
	permission := ctx.GlobalUint64(PermissionFlag.Name)
	if trueValue > uint64(vm.PerminType_AccessContract) && trueValue < uint64(vm.ModifyPerminType_AddSendTxPerm) {
		printError("Permission must bigger than 0")
	}

	input := packPermissionInput("revokePermission", contract, to, common.Address{}, permission, true)
	txHash := sendContractTransaction(conn, from, types.PermiTableAddress, nil, priKey, input, cert)

	getResult(conn, txHash, true, true)
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
	value := new(big.Int).SetUint64(0)
	data,err  :=conn.GetChainBaseParams(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	if checkUseCoin(data) {
		value = trueToWei(ctx, true)
	} else {
		useCoin = false
	}

	txHash := sendContractTransaction(conn, from, common.HexToAddress(address), value, priKey, nil, cert)
	getResult(conn, txHash, false, false)
	return nil
}

func checkUseCoin(data []byte) bool {
	if len(data) == 5 && data[1] == 0 {
		return false
	}
	return true
}

var deleteCommand = cli.Command{
	Name:   "delete",
	Usage:  "Delete a validator",
	Action: utils.MigrateFlags(deleteCert),
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
		withdrawDCommand,
	},
}

func deleteCert(ctx *cli.Context) error {
	loadPrivate(ctx)
	conn, url := dialConn(ctx)
	printBaseInfo(conn, url)

	PrintBalance(conn, from)

	if !ctx.GlobalIsSet(BftCertFlag.Name) {
		printError("Must specify --bftcert for multi proposal")
	}
	if !ctx.GlobalIsSet(ProposalCertFlag.Name) {
		printError("Must specify --proposalcert for proposal validator")
	}
	bftfile := ctx.GlobalString(BftCertFlag.Name)
	bftByte, _ := getPubFromFile(bftfile)
	proposalfile := ctx.GlobalString(ProposalCertFlag.Name)
	proposalByte, _ := getPubFromFile(proposalfile)

	input := packInput("multiProposal", bftByte, proposalByte, false)
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
