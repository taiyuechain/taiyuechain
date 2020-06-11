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
	pubk, err := crypto.GetPubByteFromCert(cfg.Etrue.Genesis.CertList[0])
	if err != nil {
		fmt.Println(err)
		t.Fatalf("cer1")
	}
	fmt.Println(hex.EncodeToString(pubk))

	fmt.Println("---the commite")
	fmt.Println(hex.EncodeToString(cfg.Etrue.Genesis.Committee[0].Coinbase[:]))
	fmt.Println(hex.EncodeToString(cfg.Etrue.Genesis.Committee[1].Coinbase[:]))
	//fmt.Println(cfg.Etrue.Genesis.Alloc["0xbD1edee3bdD812BB5058Df1F1392dDdd99dE58cc"])
}
