package keystore

import (
	"testing"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/params"
	"github.com/taiyuechain/taiyuechain/cim"
	"math/big"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
)

var (
	chainID = big.NewInt(11155)
	signer        = types.NewTIP1Signer(chainID)


)


func TestP256Sin(t *testing.T) {
//NewP256Transaction(nonce uint64, to *common.Address, payer *common.Address, amount *big.Int, fee *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte, cert []byte,chainID *big.Int,sig []byte)
	var toPrive ,_ = crypto.HexToECDSAP256("696b0620068602ecdda42ada206f74952d8c305a811599d463b89cfa3ba3bb98")
	var fromPrive ,_ = crypto.HexToECDSAP256("c1094d6cc368fa78f0175974968e9bf3d82216e87a6dfd59328220ac74181f47")


	from := crypto.PubkeyToAddress(fromPrive.PublicKey)
	amount := new(big.Int).SetInt64(0)
	nonce := uint64(1);

	// to

	tocert := cim.CreateCertP256(toPrive)

	toCert,err := x509.ParseCertificate(tocert)
	if(err != nil){
		t.Fatalf("ParseCertificate err")
		return
	}
	//fmt.Println(tocert.Version)
	var topubk ecdsa.PublicKey
	switch pub := toCert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		topubk.Curve = pub.Curve
		topubk.X = pub.X
		topubk.Y = pub.Y
	}
	to := crypto.PubkeyToAddressP256(topubk)
	//fmt.Println("to","is",to)
	// from
	fromcert :=cim.CreateCertP256(fromPrive)

	tx := types.NewP256Transaction(nonce,&to,nil,amount,new(big.Int).SetInt64(0),params.TxGas,new(big.Int).SetInt64(0),nil,fromcert,chainID,nil)

	signTx,_ := types.SignTxBy266(tx,signer,fromPrive);

	 err2 :=types.VerfiySignTxBy266(signTx,signer)
	 if(err2 != nil){
		 t.Fatalf("Verfiy err")
	 }

	 //getFrom
	 fromCertTx := signTx.Cert()
	 fromAddr,err := x509.ParseCertificate(fromCertTx)
	 if(err != nil){
		t.Fatalf("ParseCertificate err")
		return
	}
	//fmt.Println(tocert.Version)
	var frompubkTx ecdsa.PublicKey
	switch pub := fromAddr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		frompubkTx.Curve = pub.Curve
		frompubkTx.X = pub.X
		frompubkTx.Y = pub.Y
	}

	 if from !=crypto.PubkeyToAddress(frompubkTx) {
		 t.Fatalf("from err")
		 return
	 }
	 fmt.Println(from)
	fmt.Println(crypto.PubkeyToAddress(frompubkTx))

}