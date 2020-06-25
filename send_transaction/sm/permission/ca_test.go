package test

import (
	"fmt"
	"github.com/taiyuechain/taiyuechain/cim"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/core/vm"
	"github.com/taiyuechain/taiyuechain/crypto"
	"math/big"
	"os"
	"testing"

	"github.com/taiyuechain/taiyuechain/core"
	"github.com/taiyuechain/taiyuechain/core/state"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/log"
)

func init() {
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlInfo, log.StreamHandler(os.Stderr, log.TerminalFormat(false))))
}

//neo test cacert contract
func TestGrantPermission(t *testing.T) {
	// Create a helper to check if a gas allowance results in an executable transaction
	executable := func(number uint64, gen *core.BlockGen, fastChain *core.BlockChain, header *types.Header, statedb *state.StateDB, cimList *cim.CimList) {
		sendTranction(number, gen, statedb, saddr1, saddr2, new(big.Int).SetUint64(16000000000000000000), priKey, signer, nil, header, pbft1Byte, cimList)
		sendTranction(number-1, gen, statedb, saddr2, paddr4, new(big.Int).SetUint64(10000000000000000000), prikey2, signer, nil, header, pbft2Byte, cimList)
		sendGrantPermissionTranscation(number, gen, saddr2, paddr4, common.Address{}, new(big.Int).SetInt64(int64(vm.ModifyPerminType_AddSendTxPerm)), prikey2, signer, statedb, fastChain, abiCA, nil, pbft2Byte)
		sendTranction(number-16, gen, statedb, paddr4, paddr3, big.NewInt(5000000000000000000), pkey4, signer, nil, header, p2p4Byte, cimList)

		sendGrantPermissionTranscation(number-2, gen, saddr2, paddr4, common.Address{}, new(big.Int).SetInt64(int64(vm.ModifyPerminType_AddSendTxManagerPerm)), prikey2, signer, statedb, fastChain, abiCA, nil, pbft2Byte)
		//27
		sendGrantPermissionTranscation(number-3, gen, paddr4, paddr3, common.Address{}, new(big.Int).SetInt64(int64(vm.ModifyPerminType_AddSendTxPerm)), pkey4, signer, statedb, fastChain, abiCA, nil, p2p4Byte)
		sendTranction(number-19, gen, statedb, paddr3, saddr2, big.NewInt(1000000000000000000), pkey3, signer, nil, header, p2p3Byte, cimList)

		sendRevokePermissionTranscation(number, gen, saddr2, paddr4, new(big.Int).SetInt64(int64(vm.ModifyPerminType_DelSendTxPerm)), prikey2, signer, statedb, fastChain, abiCA, nil, pbft2Byte)
		sendTranction(number-40, gen, statedb, paddr4, saddr2, big.NewInt(1000000000000000000), pkey4, signer, nil, header, p2p4Byte, cimList)
	}
	newTestPOSManager(6, executable)
}

//neo test cacert contract
func TestCreateGroupPermission(t *testing.T) {
	//ModifyPerminType_AddCrtContractPerm
	gropAddr := crypto.CreateGroupkey(paddr4, 3)
	// Create a helper to check if a gas allowance results in an executable transaction
	executable := func(number uint64, gen *core.BlockGen, fastChain *core.BlockChain, header *types.Header, statedb *state.StateDB, cimList *cim.CimList) {
		sendTranction(number, gen, statedb, saddr1, saddr2, big.NewInt(6000000000000000000), priKey, signer, nil, header, pbft1Byte, cimList)
		sendTranction(number, gen, statedb, saddr1, paddr3, big.NewInt(6000000000000000000), priKey, signer, nil, header, pbft1Byte, cimList)
		sendTranction(number-1, gen, statedb, saddr2, paddr4, big.NewInt(5000000000000000000), prikey2, signer, nil, header, pbft2Byte, cimList)
		sendGrantPermissionTranscation(number, gen, saddr2, paddr4, common.Address{}, new(big.Int).SetInt64(int64(vm.ModifyPerminType_AddSendTxPerm)), prikey2, signer, statedb, fastChain, abiCA, nil, pbft2Byte)

		sendCreateGroupPermissionTranscation(number-1, gen, paddr4, "CA", pkey4, signer, statedb, fastChain, abiCA, nil, p2p4Byte)
		sendGrantPermissionTranscation(number-2, gen, saddr2, gropAddr, common.Address{}, new(big.Int).SetInt64(int64(vm.ModifyPerminType_AddSendTxPerm)), prikey2, signer, statedb, fastChain, abiCA, nil, pbft2Byte)
		sendGrantPermissionTranscation(number-3, gen, paddr4, paddr3, gropAddr, new(big.Int).SetInt64(int64(vm.ModifyPerminType_AddGropMemberPerm)), pkey4, signer, statedb, fastChain, abiCA, nil, p2p4Byte)
		sendTranction(number-19, gen, statedb, paddr3, paddr4, big.NewInt(1000000000000000000), pkey3, signer, nil, header, p2p3Byte, cimList)

		sendDelGroupPermissionTranscation(number, gen, paddr4, gropAddr, pkey4, signer, statedb, fastChain, abiCA, nil, p2p4Byte)
	}
	newTestPOSManager(6, executable)
}

//neo test cacert contract
func TestContractPermission(t *testing.T) {
	// Create a helper to check if a gas allowance results in an executable transaction
	executable := func(number uint64, gen *core.BlockGen, fastChain *core.BlockChain, header *types.Header, statedb *state.StateDB, cimList *cim.CimList) {
		sendTranction(number, gen, statedb, saddr1, saddr2, new(big.Int).SetUint64(16000000000000000000), priKey, signer, nil, header, pbft1Byte, cimList)
		sendTranction(number-1, gen, statedb, saddr2, paddr4, new(big.Int).SetUint64(10000000000000000000), prikey2, signer, nil, header, pbft2Byte, cimList)
		sendGrantPermissionTranscation(number, gen, saddr2, paddr4, common.Address{}, new(big.Int).SetInt64(int64(vm.ModifyPerminType_AddSendTxPerm)), prikey2, signer, statedb, fastChain, abiCA, nil, pbft2Byte)
		sendGrantPermissionTranscation(number, gen, saddr2, paddr4, common.Address{}, new(big.Int).SetInt64(int64(vm.ModifyPerminType_AddCrtContractPerm)), prikey2, signer, statedb, fastChain, abiCA, nil, pbft2Byte)
		if number == 26 {
			checkBaseCrtContractPermission(paddr4, t, true, loadPermissionTable(statedb))
		}

		sendGrantPermissionTranscation(number-1, gen, saddr2, paddr4, common.Address{}, new(big.Int).SetInt64(int64(vm.ModifyPerminType_AddCrtContractManagerPerm)), prikey2, signer, statedb, fastChain, abiCA, nil, pbft2Byte)
		if number == 27 {
			checkBaseCrtManagerContractPermission(paddr4, t, true, loadPermissionTable(statedb))
		}
		sendGrantPermissionTranscation(number-2, gen, paddr4, paddr3, common.Address{}, new(big.Int).SetInt64(int64(vm.ModifyPerminType_AddCrtContractPerm)), pkey4, signer, statedb, fastChain, abiCA, nil, p2p4Byte)
		if number == 28 {
			checkBaseCrtContractPermission(paddr3, t, true, loadPermissionTable(statedb))
		}

		sendRevokePermissionTranscation(number, gen, paddr4, paddr3, new(big.Int).SetInt64(int64(vm.ModifyPerminType_DelCrtContractPerm)), pkey4, signer, statedb, fastChain, abiCA, nil, p2p4Byte)
		if number == 41 {
			checkBaseCrtContractPermission(paddr3, t, false, loadPermissionTable(statedb))
		}
		sendRevokePermissionTranscation(number-1, gen, saddr2, paddr4, new(big.Int).SetInt64(int64(vm.ModifyPerminType_DelCrtContractManagerPerm)), prikey2, signer, statedb, fastChain, abiCA, nil, pbft2Byte)
		if number == 42 {
			checkBaseCrtContractPermission(paddr4, t, true, loadPermissionTable(statedb))
		}
		sendRevokePermissionTranscation(number-1-1, gen, saddr2, paddr4, new(big.Int).SetInt64(int64(vm.ModifyPerminType_DelCrtContractPerm)), prikey2, signer, statedb, fastChain, abiCA, nil, pbft2Byte)
		if number == 43 {
			checkBaseCrtContractPermission(paddr4, t, false, loadPermissionTable(statedb))
		}
	}
	newTestPOSManager(2, executable)
}

func TestAccessContractPermission(t *testing.T) {
	// Create a helper to check if a gas allowance results in an executable transaction
	executable := func(number uint64, gen *core.BlockGen, fastChain *core.BlockChain, header *types.Header, statedb *state.StateDB, cimList *cim.CimList) {
		sendTranction(number, gen, statedb, saddr1, saddr2, new(big.Int).SetUint64(16000000000000000000), priKey, signer, nil, header, pbft1Byte, cimList)
		sendTranction(number-1, gen, statedb, saddr2, paddr4, new(big.Int).SetUint64(10000000000000000000), prikey2, signer, nil, header, pbft2Byte, cimList)
		sendGrantPermissionTranscation(number, gen, saddr2, paddr4, common.Address{}, new(big.Int).SetInt64(int64(vm.ModifyPerminType_AddSendTxPerm)), prikey2, signer, statedb, fastChain, abiCA, nil, pbft2Byte)
		sendGrantPermissionTranscation(number, gen, saddr2, paddr4, common.Address{}, new(big.Int).SetInt64(int64(vm.ModifyPerminType_AddCrtContractPerm)), prikey2, signer, statedb, fastChain, abiCA, nil, pbft2Byte)
		if number == 26 {
			checkBaseCrtContractPermission(paddr4, t, true, loadPermissionTable(statedb))
		}

		sendGrantPermissionTranscation(number-1, gen, saddr2, paddr4, common.Address{}, new(big.Int).SetInt64(int64(vm.ModifyPerminType_AddCrtContractManagerPerm)), prikey2, signer, statedb, fastChain, abiCA, nil, pbft2Byte)
		if number == 27 {
			checkBaseCrtManagerContractPermission(paddr4, t, true, loadPermissionTable(statedb))
		}
		sendGrantPermissionTranscation(number-2, gen, paddr4, paddr3, common.Address{}, new(big.Int).SetInt64(int64(vm.ModifyPerminType_AddCrtContractPerm)), pkey4, signer, statedb, fastChain, abiCA, nil, p2p4Byte)
		if number == 28 {
			checkBaseCrtContractPermission(paddr3, t, true, loadPermissionTable(statedb))
		}

		sendRevokePermissionTranscation(number, gen, paddr4, paddr3, new(big.Int).SetInt64(int64(vm.ModifyPerminType_DelCrtContractPerm)), pkey4, signer, statedb, fastChain, abiCA, nil, p2p4Byte)
		if number == 41 {
			checkBaseCrtContractPermission(paddr3, t, false, loadPermissionTable(statedb))
		}
		sendRevokePermissionTranscation(number-1, gen, saddr2, paddr4, new(big.Int).SetInt64(int64(vm.ModifyPerminType_DelCrtContractManagerPerm)), prikey2, signer, statedb, fastChain, abiCA, nil, pbft2Byte)
		if number == 42 {
			checkBaseCrtContractPermission(paddr4, t, true, loadPermissionTable(statedb))
		}
		sendRevokePermissionTranscation(number-1-1, gen, saddr2, paddr4, new(big.Int).SetInt64(int64(vm.ModifyPerminType_DelCrtContractPerm)), prikey2, signer, statedb, fastChain, abiCA, nil, pbft2Byte)
		if number == 43 {
			checkBaseCrtContractPermission(paddr4, t, false, loadPermissionTable(statedb))
		}
	}
	newTestPOSManager(2, executable)
}


func TestGetAddress(t *testing.T) {
	fmt.Println("saddr1", crypto.AddressToHex(saddr1), "saddr2", crypto.AddressToHex(saddr2), "\n saddr3", crypto.AddressToHex(saddr3), "saddr4 ", crypto.AddressToHex(saddr4))
	fmt.Println("paddr3", crypto.AddressToHex(paddr3), "paddr4", crypto.AddressToHex(paddr4))
}
