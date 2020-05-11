package crypto

import (
	"fmt"
	"golang.org/x/crypto/sha3"
	"io/ioutil"
	"log"

	"os"
	"testing"
)

func TestDecrypt(t *testing.T) {
	//1 is guoji 2 is guomi
	cryptotype = CRYPTO_SM2_SM3_SM4
	ecdsapri, _ := GenerateKey()
	fmt.Println(ecdsapri)
	ecdsabyte := FromECDSA(ecdsapri)
	ecdsapri, _ = ToECDSA(ecdsabyte)
	fmt.Println(ecdsapri)
	h := sha3.NewLegacyKeccak256()
	//h:=sm3.New()
	hash := h.Sum(nil)
	//sign and verify test
	sign, _ := Sign(hash, ecdsapri)
	pubbyte := FromECDSAPub(&ecdsapri.PublicKey)
	boolverify := VerifySignature(pubbyte, hash, sign)
	fmt.Println(boolverify)
	//	compress and uncompress test
	compreebyte := CompressPubkey(&ecdsapri.PublicKey)
	fmt.Println(compreebyte)
	ecdsapub, _ := DecompressPubkey(compreebyte)
	fmt.Println(ecdsapub)
	//	sigtopub
	pubkey, _ := SigToPub(hash, sign)
	//     Encryt and Decrypt test
	src := "caoliang"
	data := []byte(src)
	//ct,_:=Encrypt(cryptotype,ecdsapub,data,nil,nil)
	ct, _ := Encrypt(pubkey, data, nil, nil)
	fmt.Println(ct)
	m, _ := Decrypt(ecdsapri, ct, nil, nil)
	fmt.Println(string(m))

}

func Test_zeroBytes(t *testing.T) {
	type args struct {
		bytes []byte
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
		})
	}
}
func TestSm2(t *testing.T) {
	cryptotype = CRYPTO_P256_SH3_AES
	priv, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v\n", priv.Curve.IsOnCurve(priv.X, priv.Y))
	pub := &priv.PublicKey
	msg := []byte("123456")
	d0, err := Encrypt(pub, msg, nil, nil)
	if err != nil {
		fmt.Printf("Error: failed to encrypt %s: %v\n", msg, err)
		return
	}
	fmt.Printf("Cipher text = %v\n", d0)
	d1, err := Decrypt(priv, d0, nil, nil)
	if err != nil {
		fmt.Printf("Error: failed to decrypt: %v\n", err)
	}
	fmt.Printf("clear text = %s\n", d1)

	msg, _ = ioutil.ReadFile("ifile")
	//Keccak256(msg)
	sign, err := Sign(Keccak256(msg), priv)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("ofile", sign, os.FileMode(0644))
	if err != nil {
		log.Fatal(err)
	}
	signdata, _ := ioutil.ReadFile("ofile")
	ok := VerifySignature(FromECDSAPub(pub), Keccak256(msg), signdata)
	if ok != true {
		fmt.Printf("Verify error\n")
	} else {
		fmt.Printf("Verify ok\n")
	}

}
