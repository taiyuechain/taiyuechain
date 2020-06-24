package main

import (
	"fmt"
	"encoding/hex"
	"github.com/taiyuechain/taiyuechain/cmd/utils"
	"github.com/taiyuechain/taiyuechain/crypto"
	"gopkg.in/urfave/cli.v1"
)

var commandGenerate = cli.Command{
	Name:      "generate",
	Usage:     "generate new key item",
	ArgsUsage: "",
	Description: `
Generate a new key item.
`,
	Flags: []cli.Flag{
		cli.IntFlag{
			Name:  "sum",
			Usage: "key info count",
			Value: 1,
		},
		cli.IntFlag{
			Name:  "type",
			Usage: "crypto type[1,2,3],default:2",
			Value: 2,
		},
	},
	Action: func(ctx *cli.Context) error {
		ct := ctx.GlobalInt("type")
		count := ctx.GlobalInt("sum")
		if count <= 0 || count > 100 {
			count = 100
		}
		crypto.SetCrtptoType(uint8(ct))

		for i:=0;i<count;i++ {
			if priv, err := crypto.GenerateKey(); err != nil {
				utils.Fatalf("Error GenerateKey: %v", err)
			} else {
				fmt.Println("privkey:",hex.EncodeToString(crypto.FromECDSA(priv)))
				fmt.Println("pubkey:",hex.EncodeToString(crypto.FromECDSAPub(&priv.PublicKey)))
				fmt.Println("address:",crypto.PubkeyToAddress(priv.PublicKey))
				fmt.Println("-------------------------------------------------------")
			}
			
		}
		return nil
	},
}
