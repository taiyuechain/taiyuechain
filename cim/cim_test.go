package cim

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/taiyuechain/taiyuechain/cim/config"
	"os"
	"path/filepath"
	"testing"

	"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/crypto/taiCrypto"
	"github.com/ethereum/go-ethereum/common/hexutil"
)


func TestMain(m *testing.M) {
	cimConfigDir, _ := config.GetDevCIMDir()
	cimID := "simpleCIM"
	err := InitCrypto(cimConfigDir, cimID)
	if err != nil {
		fmt.Printf("Setup for CMI should have succeeded, got err %s instead", err)
		os.Exit(-1)
	}
	retVal := m.Run()
	os.Exit(retVal)
}

func TestNewIdentity(t *testing.T) {
	cimConfigDir, _ := config.GetDevCIMDir()
	singcertPath := cimConfigDir + "testcert"
	id, err := GetLocalIdentityDataFromConfig(singcertPath)
	assert.Error(t, err)
	assert.NotNil(t, id)
}

func TestChectIdentity(t *testing.T) {
	cimConfigDir, _ := config.GetDevConfigDir()
	cimDir, _ := config.GetDevCIMDir()
	singcertPath := filepath.Join(cimConfigDir, "/testcert")
	id, err := GetLocalIdentityDataFromConfig(singcertPath)
	assert.NotNil(t, id)
	err = GetLocalCIM().Validate(id)
	assert.Error(t, err)
	singcertValidPath := filepath.Join(cimDir, "/signcerts")
	certValidId, err := GetLocalIdentityDataFromConfig(singcertValidPath)
	assert.NotNil(t, id)
	err = GetLocalCIM().Validate(certValidId)
	assert.Error(t, err)
}

func TestSignAndVerify(t *testing.T) {
	cim := GetLocalCIM()
	id := cim.GetSigningIdentity()

	msg := []byte("foo")
	sig, err := id.Sign(msg)
	if err != nil {
		t.Fatalf("Sign should have succeeded")
		return
	}

	err = id.Verify(msg, sig)
	if err != nil {
		t.Fatalf("The signature should be valid")
		return
	}

	err = id.Verify(msg[1:], sig)
	assert.Error(t, err)
	err = id.Verify(msg, sig[1:])
	assert.Error(t, err)
}

func TestCreateCertByPrivate(t *testing.T) {

	var prv ,_ = crypto.HexToECDSAP256("696b0620068602ecdda42ada206f74952d8c305a811599d463b89cfa3ba3bb98")
	var prv2 ,_ = crypto.HexToECDSAP256("c1094d6cc368fa78f0175974968e9bf3d82216e87a6dfd59328220ac74181f47")
	var prv3 ,_ = crypto.HexToECDSAP256("96531838617b060305f04e5c9b760e8644454cadd375c1dd1fcd6140034a67a5")
	var prv4 ,_ = crypto.HexToECDSAP256("0477ce2c8b15abc55832b9218e624282ad351adcd1c23edc4459f087d4be7edf")
	//var prvB :=

	fmt.Println(crypto.FromECDSA(prv))
	fmt.Println(crypto.FromECDSA(prv2))
	fmt.Println(crypto.FromECDSA(prv3))
	fmt.Println(crypto.FromECDSA(prv4))
	//varpriKey, _     = crypto.HexToECDSA("0260c952edc49037129d8cabbe4603d15185d83aa718291279937fb6db0fa7a2")
	CreateIdentity2(prv,prv2,"696b")
	CreateIdentity2(prv2,prv2,"c109")
	CreateIdentity2(prv3,prv2,"9653")
	CreateIdentity2(prv4,prv2,"0477")
	//CreateIdentity2(prv4,prv2,"0477")
}

func TestVerifyCertByPrivate(t *testing.T) {
	/*var prv ,_ = crypto.HexToECDSAP256("696b0620068602ecdda42ada206f74952d8c305a811599d463b89cfa3ba3bb98")
	fmt.Println(crypto.FromECDSA(prv))
	path := "./testdata/testcert/696bca.pem"
	cert ,err :=ReadPemFileByPath(path)
	if err !=nil{
		t.Fatalf("ReadPemFileByPath err")
		return
	}
	tt := string(cert)
	log.Info("cert","is",tt)
	fmt.Println(tt)
	if VarifyCertByPrivateKey(prv,cert) != nil{
		t.Fatalf("VarifyCertByPrivateKey err")
		return
	}*/
}

func TestCreatePubk(t *testing.T) {
	var prv ,_ = crypto.HexToECDSAP256("696b0620068602ecdda42ada206f74952d8c305a811599d463b89cfa3ba3bb98")
	var prv2 ,_ = crypto.HexToECDSAP256("c1094d6cc368fa78f0175974968e9bf3d82216e87a6dfd59328220ac74181f47")
	var prv3 ,_ = crypto.HexToECDSAP256("96531838617b060305f04e5c9b760e8644454cadd375c1dd1fcd6140034a67a5")
	var prv4 ,_ = crypto.HexToECDSAP256("0477ce2c8b15abc55832b9218e624282ad351adcd1c23edc4459f087d4be7edf")

	//pk :=
	pkbyte1 := crypto.FromECDSAPubCA(&prv.PublicKey)
	pkstring1 := hexutil.Encode(pkbyte1)
	fmt.Println(pkstring1)

	pkbyte2 := crypto.FromECDSAPubCA(&prv2.PublicKey)
	pkstring2 := hexutil.Encode(pkbyte2)
	fmt.Println(pkstring2)

	pkbyte3 := crypto.FromECDSAPubCA(&prv3.PublicKey)
	pkstring3 := hexutil.Encode(pkbyte3)
	fmt.Println(pkstring3)

	pkbyte4 := crypto.FromECDSAPubCA(&prv4.PublicKey)
	pkstring4 := hexutil.Encode(pkbyte4)
	fmt.Println(pkstring4)

	var taipublic taiCrypto.TaiPublicKey

	b, err := hexutil.Decode(pkstring1)
	taiCrypto.AsymmetricCryptoType = taiCrypto.ASYMMETRICCRYPTOECDSA
	_, err = taipublic.UnmarshalPubkey(b)
	if err != nil {
		fmt.Println("errr","is",err)
	}


}


