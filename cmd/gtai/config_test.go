package main

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/taiyuechain/taiyuechain/crypto"
)

func TestConfigTomlFile(t *testing.T) {

	cfg := gethConfig{}
	file := "./config.toml"
	if err := loadConfig(file, &cfg); err != nil {
		fmt.Println(err)
		t.Fatalf("load config fale")
	}
	pubk, err := crypto.GetPubByteFromCert(cfg.Etrue.NodeCert)
	if err != nil {
		fmt.Println(err)
		t.Fatalf("cer1")
	}
	fmt.Println(hex.EncodeToString(pubk))

	fmt.Println("---the commite")
	fmt.Println(hex.EncodeToString(cfg.Etrue.CommitteeKey))
	fmt.Println(hex.EncodeToString(cfg.Etrue.CommitteeBase[:]))
	//fmt.Println(cfg.Etrue.Genesis.Alloc["0xbD1edee3bdD812BB5058Df1F1392dDdd99dE58cc"])
}
func TestInitGenesis(t *testing.T) {
	certPath := "E:\\work\\seven\\truechain\\src\\github.com\\taiyuechain\\taiyuechain\\cim\\testdata\\testcert"
	genesisPath := "./genesis.json"
	// genesisPath,certPath := "./genesis.json","../../cmd/testdata/testcert"
	genesis := makeGenesis0(genesisPath,certPath)
	if genesis == nil {
		fmt.Println("error")
	}
}
