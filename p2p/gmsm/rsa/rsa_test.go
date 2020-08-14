/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package rsa

import (
	"encoding/hex"
	"fmt"
	taicert "github.com/taiyuechain/taiyuechain/cert"
	"github.com/taiyuechain/taiyuechain/cim"
	"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/p2p/gmsm/sm2"
	"log"
	"strconv"
	"testing"
)

func TestSm2ToCA(t *testing.T) {
	var (
		p2p1PrivString = "d5939c73167cd3a815530fd8b4b13f1f5492c1c75e4eafb5c07e8fb7f4b09c7c"
		p2p2PrivString = "ea4297749d514cc476fe971a7fe20100cbd29f010864341b3e624e8744d46cec"
		p2p3PrivString = "86937006ac1e6e2c846e160d93f86c0d63b0fcefc39a46e9eaeb65188909fbdc"
		p2p4PrivString = "cbddcbecd252a8586a4fd759babb0cc77f119d55f38bc7f80a708e75964dd801"
	)
	p2pPrivArr := []string{p2p1PrivString, p2p2PrivString, p2p3PrivString, p2p4PrivString}
	for i, priv := range p2pPrivArr {
		j := int64(i + 1)
		privEsda, err := crypto.HexToECDSA(priv)
		priv := sm2.ToSm2privatekey(privEsda)
		if err != nil {
			log.Fatal(err)
		}
		if i == 0 {
			fmt.Printf("%v\n", priv.Curve.IsOnCurve(priv.X, priv.Y)) // 验证是否为sm2的曲线
		}

		ok, err := sm2.WritePrivateKeytoPem("p2p"+strconv.FormatInt(j, 10)+".key", priv, nil) // 生成密钥文件
		if ok != true {
			log.Fatal(err)
		}
	}
}

func TestSm2RootToCA(t *testing.T) {
	var (
		pbft1PrivString = "7631a11e9d28563cdbcf96d581e4b9a19e53ad433a53c25a9f18c74ddf492f75"
		pbft2PrivString = "bab8dbdcb4d974eba380ff8b2e459efdb6f8240e5362e40378de3f9f5f1e67bb"
		pbft3PrivString = "122d186b77a030e04f5654e13d934b21af2aac03b942c3ecda4632364d81cbab"
		pbft4PrivString = "fe44cbc0e164092a6746bd57957422ab165c009d0299c7639a2f4d290317f20f"
	)
	p2pPrivArr := []string{pbft1PrivString, pbft2PrivString, pbft3PrivString, pbft4PrivString}
	for i, priv := range p2pPrivArr {
		j := int64(i + 1)
		privEsda, err := crypto.HexToECDSA(priv)
		priv := sm2.ToSm2privatekey(privEsda)
		if err != nil {
			log.Fatal(err)
		}
		if i == 0 {
			fmt.Printf("%v\n", priv.Curve.IsOnCurve(priv.X, priv.Y)) // 验证是否为sm2的曲线
		}

		ok, err := sm2.WritePrivateKeytoPem("key"+strconv.FormatInt(j, 10)+".key", priv, nil) // 生成密钥文件
		if ok != true {
			log.Fatal(err)
		}
	}
}

var (
	CryptoSM2 = uint8(2)
	pbft1path = "pem/bft1" + ".pem"
	pbft2path = "pem/bft2" + ".pem"
	pbft3path = "pem/bft3" + ".pem"
	pbft4path = "pem/bft4" + ".pem"

	p2p1path = "pem/p2p1" + ".pem"
	p2p2path = "pem/p2p2" + ".pem"
	p2p3path = "pem/p2p3" + ".pem"
	p2p5path = "pem/p2p5" + ".pem"
)

func TestVerifyCert(t *testing.T) {
	pbft1Byte, _ := taicert.ReadPemFileByPath(pbft1path)
	pbft2Byte, _ := taicert.ReadPemFileByPath(pbft2path)
	pbft3Byte, _ := taicert.ReadPemFileByPath(pbft3path)

	p2p1Byte, _ := taicert.ReadPemFileByPath(p2p1path)
	p2p2Byte, _ := taicert.ReadPemFileByPath(p2p2path)
	p2p3Byte, _ := taicert.ReadPemFileByPath(p2p3path)
	p2p5Byte, _ := taicert.ReadPemFileByPath(p2p5path)

	//new cimList
	cimList := cim.NewCIMList(CryptoSM2)
	cimList.AddCim(cim.CreateCim(pbft1Byte))
	cimList.AddCim(cim.CreateCim(pbft2Byte))
	cimList.AddCim(cim.CreateCim(pbft3Byte))

	err := cimList.VerifyCert(p2p1Byte)
	if err != nil {
		t.Fatalf("verify cert 1 error %v", err)
	}

	err = cimList.VerifyCert(p2p2Byte)
	if err != nil {
		t.Fatalf("verify cert 2 error %v", err)
	}

	err = cimList.VerifyCert(p2p3Byte)
	if err != nil {
		fmt.Printf("verify cert 3 error %v \n",err)
	}

	crypto.CryptoType = crypto.CRYPTO_SM2_SM3_SM4
	err = cimList.VerifyCert(p2p5Byte)
	if err != nil {
		fmt.Printf("verify cert 5 error %v \n", err)
	}
}

func TestPrintPem(t *testing.T) {
	pbft1Byte, _ := taicert.ReadPemFileByPath(pbft1path)
	pbft2Byte, _ := taicert.ReadPemFileByPath(pbft2path)
	pbft3Byte, _ := taicert.ReadPemFileByPath(pbft3path)
	pbft4Byte, _ := taicert.ReadPemFileByPath(pbft4path)
	fmt.Println(hex.EncodeToString(pbft1Byte))
	fmt.Println(hex.EncodeToString(pbft2Byte))
	fmt.Println(hex.EncodeToString(pbft3Byte))
	fmt.Println(hex.EncodeToString(pbft4Byte))
}
