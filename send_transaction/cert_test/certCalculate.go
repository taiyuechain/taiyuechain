package main

import (
	"crypto/x509"
	"fmt"
	"github.com/taiyuechain/taiyuechain/cim"
	"github.com/taiyuechain/taiyuechain/crypto"
	"time"
)

func main() {
	startTime := time.Now().UnixNano()
	t1()
	/* 程序主体 */
	endTime := time.Now().UnixNano()
	Milliseconds := float64((endTime - startTime) / 1e6)
	fmt.Println("Milliseconds=", Milliseconds)
}

func t2() {
	var toPrive, _ = crypto.HexToECDSAP256("696b0620068602ecdda42ada206f74952d8c305a811599d463b89cfa3ba3bb98")
	pubKey := crypto.FromECDSAPub(&toPrive.PublicKey)
	fmt.Println(len(pubKey))
	tocertbyte := cim.CreateCertP256(toPrive)
	fmt.Println(len(tocertbyte))

	_, err := x509.ParseCertificate(tocertbyte)
	if err != nil {
		fmt.Println("ParseCertificate error", "err", err)
	}
	//fmt.Println(toCert.PublicKey)
}

func t1() {
	for i := 1; i < 10000; i++ {
		t2()
	}

}
