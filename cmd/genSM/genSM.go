package main

import (
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"time"

	"github.com/taiyuechain/taiyuechain/p2p/gmsm/sm2"
)

func genRootKeyAndCert(num int) {
	priv, err := sm2.GenerateKey() // 生成密钥对
	if err != nil {
		log.Fatal(err)
	}

	ok, err := sm2.WritePrivateKeytoPem("rootPriv"+strconv.Itoa(num)+".pem", priv, nil) // 生成密钥文件
	if ok != true {
		log.Fatal(err)
	}

	commonName := "taiyuechain.com"
	nowTime := time.Now()
	endTime := nowTime.AddDate(1, 0, 0)
	template := sm2.Certificate{
		// SerialNumber is negative to ensure that negative
		// values are parsed. This is due to the prevalence of
		// buggy code that produces certificates with negative
		// serial numbers.
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"taiyue"},
			Country:      []string{"CN"},
		},
		NotBefore: nowTime,
		NotAfter:  endTime,

		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: sm2.SM2WithSM3,
	}

	// self-signed certificate
	pubKey, _ := priv.Public().(*sm2.PublicKey)
	ok, _ = sm2.CreateCertificateToPem("rootCert"+strconv.Itoa(num)+".pem", &template, &template, pubKey, priv)
	if ok != true {
		fmt.Printf("failed to create cert file\n")
	}
	fmt.Println("generate root cert ok")
}

func genClientCert(rootPrivPath, rootCertPath string) {
	// gen new key
	clientPriv, err := sm2.GenerateKey() // 生成密钥对
	if err != nil {
		log.Fatal(err)
	}
	clientPublic := clientPriv.Public().(*sm2.PublicKey)
	ok, err := sm2.WritePrivateKeytoPem("clientPriv.pem", clientPriv, nil) // 生成密钥文件
	if ok != true {
		log.Fatal(err)
	}

	rootPriv, err := sm2.ReadPrivateKeyFromPem(rootPrivPath, nil) // 读取密钥
	if err != nil {
		log.Fatal(err)
	}

	rootCert, err := sm2.ReadCertificateFromPem(rootCertPath)
	if err != nil {
		fmt.Printf("failed to read rootCert file")
	}
	commonName := "taiyuechain.com"
	nowTime := time.Now()
	endTime := nowTime.AddDate(1, 0, 0)
	template := sm2.Certificate{
		// SerialNumber is negative to ensure that negative
		// values are parsed. This is due to the prevalence of
		// buggy code that produces certificates with negative
		// serial numbers.
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"taiyue"},
			Country:      []string{"CN"},
		},
		NotBefore: nowTime,
		NotAfter:  endTime,

		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: sm2.SM2WithSM3,
	}

	ok, _ = sm2.CreateCertificateToPem("clientCert.pem", &template, rootCert, clientPublic, rootPriv)
	if ok != true {
		fmt.Printf("failed to create cert file\n")
	}
	fmt.Println("generate root-signed cert ok")
}

func main() {
	var genRoot bool
	var genClient bool
	var h bool

	flag.BoolVar(&genRoot, "genRoot", true, "usage:-genRoot=true/false; whether to generate root private key and cert")
	flag.BoolVar(&genClient, "genClient", false, "usage:-genClient=true/false; whether to generate client private key and cert")
	rootNumber := flag.Int("rootNumber", 1, "number of root to generage")
	rootPrivPath := flag.String("rootPrivPath", "", "choose root priavate key path to sign client")
	rootCertPath := flag.String("rootCertPath", "", "choose root cert path to sign client")
	flag.BoolVar(&h, "h", false, "genSM help")
	flag.Parse()

	if h {
		flag.Usage()
	} else {
		if genRoot {
			for i := 1; i <= *rootNumber; i++ {
				genRootKeyAndCert(i)
			}
		}
		if genClient {
			if *rootPrivPath == "" || *rootCertPath == "" {
				flag.Usage()
			} else {
				genClientCert(*rootPrivPath, *rootCertPath)
			}
		}
	}

}
