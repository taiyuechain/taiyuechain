package crypto

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/crypto/ecies"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm3"
	"golang.org/x/crypto/sha3"
	"io/ioutil"
	"log"
	"math/big"
	"time"

	// "reflect"
	"testing"
)

func TestDecrypt(t *testing.T) {
	//1 is guoji 2 is guomi
	CryptoType = CRYPTO_SM2_SM3_SM4
	ecdsapri, _ := ecies.GenerateKey(rand.Reader, elliptic.P256(), nil)
	ecdsapri1 := ecdsapri.ExportECDSA()
	fmt.Println(ecdsapri)
	ecdsabyte := FromECDSA(ecdsapri1)
	ecdsapri1, _ = ToECDSA(ecdsabyte)
	fmt.Println(ecdsapri)
	h := sha3.NewLegacyKeccak256()
	//h:=sm3.New()
	hash := h.Sum(nil)
	//sign and verify test
	sign, _ := Sign(hash, ecdsapri1)
	fmt.Println(len(sign))
	pubbyte := FromECDSAPub(&ecdsapri1.PublicKey)
	ecdpub, _ := UnmarshalPubkey(pubbyte)
	fmt.Println(ecdpub)
	fmt.Println(ecdsapri.PublicKey)

	boolverify := VerifySignature(pubbyte, hash, sign)
	fmt.Println(boolverify)
	//	compress and uncompress test
	compreebyte := CompressPubkey(&ecdsapri1.PublicKey)
	fmt.Println(compreebyte)
	ecdsapub, _ := DecompressPubkey(compreebyte)
	//fmt.Println(ecdsapub)
	//	sigtopub
	//pubkey, err := SigToPub(hash, sign)

	/* if err != nil {
		 panic(err)
	 }*/
	//     Encryt and Decrypt test
	src := "caoliang"
	data := []byte(src)
	ct, _ := Encrypt(ecdsapub, data, nil, nil)
	//ct, _ := Encrypt(pubkey, data, nil, nil)
	//fmt.Println(ct)
	m, _ := Decrypt(ecdsapri1, ct, nil, nil)
	fmt.Println(string(m))
}

func Test_zeroBytes(t *testing.T) {
	/*	CryptoType = CRYPTO_SM2_SM3_SM4
		ecdsapri, _ := GenerateKey()
		pubkeybyte := FromECDSAPub(&ecdsapri.PublicKey)
		stringsm2pub := hex.EncodeToString(pubkeybyte)
		fmt.Println(stringsm2pub)
		CryptoType = CRYPTO_P256_SH3_AES
		ecdpub, _ := UnmarshalPubkey(pubkeybyte)
		fmt.Println(ecdpub)
		byte, _ := hex.DecodeString(stringsm2pub)
		ecdpub1, _ := UnmarshalPubkey(byte)
		fmt.Println(ecdpub1)*/
	for i := 0; i < 1000; i++ {
		digestHash := "009feb9d89b8cf6e82900bc9ec642ab6278788c9d44ed26b2c3c3d13ac56cb9a"
		priv := "bab8dbdcb4d974eba380ff8b2e459efdb6f8240e5362e40378de3f9f5f1e67bb"
		digestHash1, _ := hex.DecodeString(digestHash)
		pri, _ := HexToECDSA(priv)
		sign, _ := Sign(digestHash1, pri)
		fmt.Println(sign)

		boolverify := VerifySignature(FromECDSAPub(&pri.PublicKey), digestHash1, sign)
		if boolverify == false {
			fmt.Println(boolverify)
		}

	}

}
func TestSm2(t *testing.T) {
	CryptoType = CRYPTO_SM2_SM3_SM4
	for i := 0; i < 1000; i++ {
		priv, err := GenerateKey()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%v\n", priv.Curve.IsOnCurve(priv.X, priv.Y))
		pub := &priv.PublicKey
		fmt.Println(hex.EncodeToString(FromECDSAPub(pub)))
		msg := []byte("123456hhsdhdsjhsjhjhsfjdhjhjhsdfjhjhsdfjhjhsfjhjhsdfhjjhsdfhhjhsfdhjhjsdfhjjhfffffffffjhjhsfjhjhdsfjhhfhhsdhsdfhjhsdjhjhhsdhjhjsdhjhjfjhsjhjhjhdshjfhsdfhhjsfhjjfshdhhhjfshjjhsdfhjhsfhdhfsjddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
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

		signdata := sign
		_, err = Ecrecover(Keccak256(msg), signdata)
		if err != nil {
			fmt.Printf("VerifyTransaction error\n")
		} else {
			fmt.Printf("VerifyTransaction ok\n")
		}
		ok := VerifySignature(FromECDSAPub(pub), Keccak256(msg), signdata)
		//ValidateSignatureValues(signdata[65],sign[])
		if ok != true {
			fmt.Printf("Verify error\n")
		} else {
			fmt.Printf("Verify ok\n")
		}
	}
}

func TestString(t *testing.T) {
	CryptoType = CRYPTO_SM2_SM3_SM4
	priv, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(hex.EncodeToString(FromECDSA(priv)), " pub ", hex.EncodeToString(FromECDSAPub(&priv.PublicKey)))
	CryptoType = CRYPTO_P256_SH3_AES
	priv, err = GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(hex.EncodeToString(FromECDSA(priv)), " pub ", hex.EncodeToString(FromECDSAPub(&priv.PublicKey)))
}
func Test_01(t *testing.T) {
	priv, _ := GenerateKey()
	hash := RlpHash([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	for i := 0; i < 10; i++ {
		sign, err := Sign(hash[:], priv)
		if err == nil {
			fmt.Println("sign:", sign)
		}
	}
}

const BloomByteLength = 256

type Header struct {
	ParentHash    common.Hash    `json:"parentHash"       gencodec:"required"`
	Root          common.Hash    `json:"stateRoot"        gencodec:"required"`
	TxHash        common.Hash    `json:"transactionsRoot" gencodec:"required"`
	ReceiptHash   common.Hash    `json:"receiptsRoot"     gencodec:"required"`
	CommitteeHash common.Hash    `json:"committeeRoot"    gencodec:"required"`
	Proposer      common.Address `json:"maker"            gencodec:"required"`
	Bloom         Bloom          `json:"logsBloom"        gencodec:"required"`
	Number        *big.Int       `json:"number"           gencodec:"required"`
	GasLimit      uint64         `json:"gasLimit"         gencodec:"required"`
	GasUsed       uint64         `json:"gasUsed"          gencodec:"required"`
	Time          *big.Int       `json:"timestamp"        gencodec:"required"`
	Extra         []byte         `json:"extraData"        gencodec:"required"`
}
type Bloom [BloomByteLength]byte

func TestHash256(t *testing.T) {
	//var he interface{}
	var header Header
	h := RlpHash(header)
	fmt.Println(h)
	doublebyte := Double256(h.Bytes())
	fmt.Println(doublebyte)
	byte := Hash256Byte(doublebyte, doublebyte)
	fmt.Println(byte)
	hash256 := Hash256(doublebyte, doublebyte, doublebyte)
	fmt.Println(hash256)
}

func TestFromCertBytesToPubKey(t *testing.T) {
	// str := "3082026630820212a0030201020201ff300a06082a811ccf55018375303031133011060355040a0c0acea32041636d6520436f3119301706035504031310746573742e6578616d706c652e636f6d301e170d3230303531333032313331375a170d3233303731343131353935375a303031133011060355040a0c0acea32041636d6520436f3119301706035504031310746573742e6578616d706c652e636f6d3059301306072a8648ce3d020106082a811ccf5501822d0342000441dbdfd708e660fc955820d257b8783b51c5a75d6f0988257e204147759d9d3dba9eebdd7970d2196b64197f3e1de6bc6714176aa709cd4a3bb6b0ff90f93667a382011b30820117300e0603551d0f0101ff040403020204300f0603551d130101ff040530030101ff300d0603551d0e0406040401020304305f06082b0601050507010104533051302306082b060105050730018617687474703a2f2f6f6373702e6578616d706c652e636f6d302a06082b06010505073002861e687474703a2f2f6372742e6578616d706c652e636f6d2f6361312e637274301a0603551d1104133011820f666f6f2e6578616d706c652e636f6d300f0603551d2004083006300406022a0330570603551d1f0450304e3025a023a021861f687474703a2f2f63726c312e6578616d706c652e636f6d2f6361312e63726c3025a023a021861f687474703a2f2f63726c322e6578616d706c652e636f6d2f6361312e63726c300a06082a811ccf550183750342005c7f04b2b380ee0b136b80dd3cb223372858796ce1a1203a04e3280e74a5b43c6a034951e0192ae68ba1927715173bb7212b946f128aa88cf95862bbf377adc341"
	// data, err := hex.DecodeString(str)
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// pub, err := FromCertBytesToPubKey(data)
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// prv1, err := HexToECDSA("d5939c73167cd3a815530fd8b4b13f1f5492c1c75e4eafb5c07e8fb7f4b09c7c")
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// if !reflect.DeepEqual(pub, &prv1.PublicKey) {
	// 	fmt.Println("1111")
	// }
}

func TestNewHashObject(t *testing.T) {
	/*	CryptoType = CRYPTO_SM2_SM3_SM4
		publichash := Keccak256()
		fmt.Println(publichash)
		tt := sha3.NewLegacyKeccak256()
		tt.Write(nil)
		fmt.Println(tt.Sum(nil))
		h := sha256.New()
		h.Write(nil)
		vv := h.Sum(nil)
		fmt.Println(vv)*/

	//var h hasher

	src := "caoliang"
	data := []byte(src)
	hasher := sm3.New()
	hasher.Write(data) // nolint: errcheck, gas
	sum := hasher.Sum(nil)
	fmt.Println(hex.EncodeToString(sum))
	hasher1 := sm3.New()
	hasher1.Write(data)

	/*	tt:=h.makeHashNode(data)
		fmt.Println(tt)*/

}

func TestSm2Time(t *testing.T) {
	CryptoType = CRYPTO_SM2_SM3_SM4
	priv, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	msg := []byte("123456hhsdhdsjhsjhjhsfjdhjhjhsdfjhjhsdfjhjhsfjhjhsdfhjjhsdfhhjhsfdhjhjsdfhjjhfffffffffjhjhsfjhjhdsfjhhfhhsdhsdfhjhsdjhjhhsdhjhjsdhjhjfjhsjhjhjhdshjfhsdfhhjsfhjjfshdhhhjfshjjhsdfhjhsfhdhfsjddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	hash := Keccak256(msg)
	signdata, err := Sign(hash, priv)
	if err != nil {
		log.Fatal(err)
	}

	t0 := time.Now()
	for i := 0; i < 5000; i++ {
		_,err = Ecrecover(hash, signdata)
		if err != nil {
			fmt.Printf("VerifyTransaction 0 error\n")
		}
	}
	t11 := time.Since(t0)
	fmt.Println("t", t11, " ", t11/5000)

	t0 = time.Now()
	for i := 0; i < 5000; i++ {
		ok := VerifySignature(FromECDSAPub(&priv.PublicKey),hash, signdata)
		if ok != true {
			fmt.Printf("VerifyTransaction 0 error\n")
		}
	}
	t11 = time.Since(t0)
	fmt.Println("t", t11, " ", t11/5000)
}

func TestS256Time(t *testing.T) {
	CryptoType = CRYPTO_S256_SH3_AES
	priv, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	msg := []byte("123456hhsdhdsjhsjhjhsfjdhjhjhsdfjhjhsdfjhjhsfjhjhsdfhjjhsdfhhjhsfdhjhjsdfhjjhfffffffffjhjhsfjhjhdsfjhhfhhsdhsdfhjhsdjhjhhsdhjhjsdhjhjfjhsjhjhjhdshjfhsdfhhjsfhjjfshdhhhjfshjjhsdfhjhsfhdhfsjddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	hash := Keccak256(msg)
	signdata, err := Sign(hash, priv)
	if err != nil {
		log.Fatal(err)
	}

	t0 := time.Now()
	for i := 0; i < 5000; i++ {
		_,err := Ecrecover(hash, signdata)
		if err != nil {
			fmt.Println("VerifyTransaction 1 error ",err)
		}
	}
	t11 := time.Since(t0)
	fmt.Println("t", t11, " ", t11/5000)

	t0 = time.Now()
	for i := 0; i < 5000; i++ {
		ok := VerifySignature(FromECDSAPub(&priv.PublicKey),hash, signdata)
		if ok != true {
			fmt.Printf("VerifyTransaction 0 error\n")
		}
	}
	t11 = time.Since(t0)
	fmt.Println("t", t11, " ", t11/5000)
}

func TestSm2Recover(t *testing.T) {
	CryptoType = CRYPTO_S256_SH3_AES
	priv, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("t", hex.EncodeToString(FromECDSAPub(&priv.PublicKey)))
	msg := []byte("123456hhsdhdsjhsjhjhsfjdhjhjhsdfjhjhsdfjhjhsfjhjhsdfhjjhsdfhhjhsfdhjhjsdfhjjhfffffffffjhjhsfjhjhdsfjhhfhhsdhsdfhjhsdjhjhhsdhjhjsdhjhjfjhsjhjhjhdshjfhsdfhhjsfhjjfshdhhhjfshjjhsdfhjhsfhdhfsjddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	hash := Keccak256(msg)
	signdata, err := Sign(hash, priv)
	if err != nil {
		log.Fatal(err)
	}

	pk,err := SigToPub(hash,signdata)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("t", hex.EncodeToString(FromECDSAPub(pk)))
	pk1,err := Ecrecover(hash,signdata)
	fmt.Println("pk", hex.EncodeToString(pk1))

}
func Test_02(t *testing.T) {
	var vv [32]byte 
	msg := []byte("xiangojfoengjidie1234eu9830u4")
	hash := Keccak256(msg)
	
	val := new(big.Int).SetBytes(hash[:])
	buf := val.Bytes()
	copy(vv[32-len(buf):],buf)
	fmt.Println("vv",vv)
	fmt.Println("finish")
}