package ecies

import (
	"crypto/rand"
	"fmt"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm2"
	"testing"
)

func TestImportECDSAPublic(t *testing.T) {

}

func TestGenerateKey(t *testing.T) {
	pri, _ := GenerateKey(rand.Reader, sm2.P256Sm2(), nil)
	fmt.Println(pri)
}

func TestEncrypt(t *testing.T) {
	pri, _ := GenerateKey(rand.Reader, sm2.P256Sm2(), nil)
	fmt.Println(pri)
	src := "caoliang"
	data := []byte(src)
	ct, _ := Encrypt(rand.Reader, &pri.PublicKey, data, nil, nil)
	//ct,_:=sm2.Encrypt(sm2.ToSm2Publickey(pri.PublicKey.ExportECDSA()),data,sm2.C1C2C3)
	//m,_:=sm2.ToSm2privatekey(pri.ExportECDSA()).Decrypt(ct,nil,nil)
	//m,_:=sm2.Decrypt(sm2.ToSm2privatekey(pri.ExportECDSA()),ct,sm2.C1C2C3)
	m, _ := pri.Decrypt(ct, nil, nil)
	fmt.Println(string(m))
}
