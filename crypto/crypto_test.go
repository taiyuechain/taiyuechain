package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"github.com/taiyuechain/taiyuechain/common"
	"golang.org/x/crypto/sha3"
	"math/big"
	"reflect"
	"testing"
)

func TestCreateAddress(t *testing.T) {
	type args struct {
		b     common.Address
		nonce uint64
	}
	tests := []struct {
		name string
		args args
		want common.Address
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CreateAddress(tt.args.b, tt.args.nonce); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateAddress() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateAddress2(t *testing.T) {
	type args struct {
		b        common.Address
		salt     [32]byte
		inithash []byte
	}
	tests := []struct {
		name string
		args args
		want common.Address
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CreateAddress2(tt.args.b, tt.args.salt, tt.args.inithash); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateAddress2() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	//1 is guoji 2 is guomi
	var cryptotype = (uint8)(1)
	ecdsapri, _ := GenerateKey(cryptotype)
	fmt.Println(ecdsapri)
	ecdsabyte := FromECDSA(ecdsapri)
	ecdsapri, _ = ToECDSA(cryptotype, ecdsabyte)
	fmt.Println(ecdsapri)
	h := sha3.NewLegacyKeccak256()
	//h:=sm3.New()
	hash := h.Sum(nil)
	//sign and verify test
	sign, _ := Sign(cryptotype, hash, ecdsapri)
	pubbyte := FromECDSAPub(cryptotype, &ecdsapri.PublicKey)
	boolverify := VerifySignature(cryptotype, pubbyte, hash, sign)
	fmt.Println(boolverify)
	//	compress and uncompress test
	compreebyte := CompressPubkey(cryptotype, &ecdsapri.PublicKey)
	fmt.Println(compreebyte)
	ecdsapub, _ := DecompressPubkey(cryptotype, compreebyte)
	fmt.Println(ecdsapub)
	//	sigtopub
	pubkey, _ := SigToPub(cryptotype, hash, sign)
	//     Encryt and Decrypt test
	src := "caoliang"
	data := []byte(src)
	//ct,_:=Encrypt(cryptotype,ecdsapub,data,nil,nil)
	ct, _ := Encrypt(cryptotype, pubkey, data, nil, nil)
	fmt.Println(ct)
	m, _ := Decrypt(cryptotype, ecdsapri, ct, nil, nil)
	fmt.Println(string(m))

}

func TestEncrypt(t *testing.T) {
	type args struct {
		cryptotype uint8
		pub        *ecdsa.PublicKey
		m          []byte
		s1         []byte
		s2         []byte
	}
	tests := []struct {
		name    string
		args    args
		wantCt  []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCt, err := Encrypt(tt.args.cryptotype, tt.args.pub, tt.args.m, tt.args.s1, tt.args.s2)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotCt, tt.wantCt) {
				t.Errorf("Encrypt() gotCt = %v, want %v", gotCt, tt.wantCt)
			}
		})
	}
}

func TestFromECDSA(t *testing.T) {
	type args struct {
		priv *ecdsa.PrivateKey
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FromECDSA(tt.args.priv); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FromECDSA() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFromECDSAPub(t *testing.T) {
	type args struct {
		cryptotype uint8
		pub        *ecdsa.PublicKey
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FromECDSAPub(tt.args.cryptotype, tt.args.pub); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FromECDSAPub() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateKey(t *testing.T) {
	type args struct {
		cryptotype uint8
	}
	tests := []struct {
		name    string
		args    args
		want    *ecdsa.PrivateKey
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateKey(tt.args.cryptotype)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenerateKey() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateShared(t *testing.T) {
	type args struct {
		cryptotype uint8
		pri        *ecdsa.PrivateKey
		pub        *ecdsa.PublicKey
		skLen      int
		macLen     int
	}
	tests := []struct {
		name    string
		args    args
		wantSk  []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSk, err := GenerateShared(tt.args.cryptotype, tt.args.pri, tt.args.pub, tt.args.skLen, tt.args.macLen)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateShared() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotSk, tt.wantSk) {
				t.Errorf("GenerateShared() gotSk = %v, want %v", gotSk, tt.wantSk)
			}
		})
	}
}

func TestHexToECDSA(t *testing.T) {
	type args struct {
		cryptotype uint8
		hexkey     string
	}
	tests := []struct {
		name    string
		args    args
		want    *ecdsa.PrivateKey
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HexToECDSA(tt.args.cryptotype, tt.args.hexkey)
			if (err != nil) != tt.wantErr {
				t.Errorf("HexToECDSA() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HexToECDSA() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeccak256(t *testing.T) {
	type args struct {
		data [][]byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Keccak256(tt.args.data...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Keccak256() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeccak256Hash(t *testing.T) {
	type args struct {
		data [][]byte
	}
	tests := []struct {
		name  string
		args  args
		wantH common.Hash
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotH := Keccak256Hash(tt.args.data...); !reflect.DeepEqual(gotH, tt.wantH) {
				t.Errorf("Keccak256Hash() = %v, want %v", gotH, tt.wantH)
			}
		})
	}
}

func TestKeccak512(t *testing.T) {
	type args struct {
		data [][]byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Keccak512(tt.args.data...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Keccak512() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoadECDSA(t *testing.T) {
	type args struct {
		cryptotype uint8
		file       string
	}
	tests := []struct {
		name    string
		args    args
		want    *ecdsa.PrivateKey
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadECDSA(tt.args.cryptotype, tt.args.file)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadECDSA() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadECDSA() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPubkeyToAddress(t *testing.T) {
	type args struct {
		cryptotype uint8
		p          ecdsa.PublicKey
	}
	tests := []struct {
		name string
		args args
		want common.Address
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PubkeyToAddress(tt.args.cryptotype, tt.args.p); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PubkeyToAddress() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSaveECDSA(t *testing.T) {
	type args struct {
		file string
		key  *ecdsa.PrivateKey
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := SaveECDSA(tt.args.file, tt.args.key); (err != nil) != tt.wantErr {
				t.Errorf("SaveECDSA() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestToECDSA(t *testing.T) {
	type args struct {
		cryptotype uint8
		d          []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *ecdsa.PrivateKey
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToECDSA(tt.args.cryptotype, tt.args.d)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToECDSA() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ToECDSA() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToECDSAUnsafe(t *testing.T) {
	type args struct {
		cryptotype uint8
		d          []byte
	}
	tests := []struct {
		name string
		args args
		want *ecdsa.PrivateKey
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ToECDSAUnsafe(tt.args.cryptotype, tt.args.d); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ToECDSAUnsafe() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnmarshalPubkey(t *testing.T) {
	type args struct {
		cryptotype uint8
		pub        []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *ecdsa.PublicKey
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalPubkey(tt.args.cryptotype, tt.args.pub)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalPubkey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnmarshalPubkey() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateSignatureValues(t *testing.T) {
	type args struct {
		v         byte
		r         *big.Int
		s         *big.Int
		homestead bool
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateSignatureValues(tt.args.v, tt.args.r, tt.args.s, tt.args.homestead); got != tt.want {
				t.Errorf("ValidateSignatureValues() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_toECDSA(t *testing.T) {
	type args struct {
		curve  elliptic.Curve
		d      []byte
		strict bool
	}
	tests := []struct {
		name    string
		args    args
		want    *ecdsa.PrivateKey
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := toECDSA(tt.args.curve, tt.args.d, tt.args.strict)
			if (err != nil) != tt.wantErr {
				t.Errorf("toECDSA() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("toECDSA() got = %v, want %v", got, tt.want)
			}
		})
	}
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
