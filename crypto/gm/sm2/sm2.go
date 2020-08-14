package sm2

import "C"
import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	sm3 "github.com/taiyuechain/taiyuechain/crypto/gm/sm3"
	"github.com/taiyuechain/taiyuechain/crypto/gm/util"
	"github.com/taiyuechain/taiyuechain/log"
	"hash"
	"io"
	"math/big"
)

const (
	BitSize    = 256
	KeyBytes   = (BitSize + 7) / 8
	UnCompress = 0x04
)
const (
	// DefaultUID The default user id as specified in GM/T 0009-2012
	DefaultUID = "1234567812345678"
)

type Sm2CipherTextType int32

const (
	C1C2C3 Sm2CipherTextType = 1
	C1C3C2 Sm2CipherTextType = 2
)

var (
	sm2H                 = new(big.Int).SetInt64(1)
	ee 					 = new(big.Int).SetInt64(0)
	sm2SignDefaultUserId = []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
)

var sm2P256V1 P256V1Curve

type P256V1Curve struct {
	*elliptic.CurveParams
	A *big.Int
}

type PublicKey struct {
	X, Y  *big.Int
	Curve P256V1Curve
}

func (pub *PublicKey) Error() string {
	panic("implement me")
}

type PrivateKey struct {
	D     *big.Int
	Curve P256V1Curve
	PublicKey
}

type Sm2Signature struct {
	R, S *big.Int
	X, Y *big.Int
}

type sm2CipherC1C3C2 struct {
	X, Y *big.Int
	C3   []byte
	C2   []byte
}

type sm2CipherC1C2C3 struct {
	X, Y *big.Int
	C2   []byte
	C3   []byte
}

func init() {
	initSm2P256V1()
}

func initSm2P256V1() {
	sm2P, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	sm2A, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
	sm2B, _ := new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
	sm2N, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	sm2Gx, _ := new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	sm2Gy, _ := new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	sm2P256V1.CurveParams = &elliptic.CurveParams{Name: "SM2-P-256-V1"}
	sm2P256V1.P = sm2P
	sm2P256V1.A = sm2A
	sm2P256V1.B = sm2B
	sm2P256V1.N = sm2N
	sm2P256V1.Gx = sm2Gx
	sm2P256V1.Gy = sm2Gy
	sm2P256V1.BitSize = BitSize
}

func GetSm2P256V1() P256V1Curve {
	return sm2P256V1
}

func GenerateKey(rand io.Reader) (*PrivateKey, *PublicKey, error) {
	priv, x, y, err := elliptic.GenerateKey(sm2P256V1, rand)
	if err != nil {
		return nil, nil, err
	}
	privateKey := new(PrivateKey)
	privateKey.Curve = sm2P256V1
	privateKey.D = new(big.Int).SetBytes(priv)
	publicKey := new(PublicKey)
	publicKey.Curve = sm2P256V1
	publicKey.X = x
	publicKey.Y = y
	privateKey.PublicKey = *publicKey
	return privateKey, publicKey, nil
}

func (pub *PublicKey) GetUnCompressBytes() []byte {
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	xl := len(xBytes)
	yl := len(yBytes)

	raw := make([]byte, 1+KeyBytes*2)
	raw[0] = UnCompress
	if xl > KeyBytes {
		copy(raw[1:1+KeyBytes], xBytes[xl-KeyBytes:])
	} else if xl < KeyBytes {
		copy(raw[1+(KeyBytes-xl):1+KeyBytes], xBytes)
	} else {
		copy(raw[1:1+KeyBytes], xBytes)
	}

	if yl > KeyBytes {
		copy(raw[1+KeyBytes:], yBytes[yl-KeyBytes:])
	} else if yl < KeyBytes {
		copy(raw[1+KeyBytes+(KeyBytes-yl):], yBytes)
	} else {
		copy(raw[1+KeyBytes:], yBytes)
	}
	return raw
}

func (pub *PublicKey) GetRawBytes() []byte {
	raw := pub.GetUnCompressBytes()
	return raw[1:]
}

func (pri *PrivateKey) GetRawBytes() []byte {
	dBytes := pri.D.Bytes()
	dl := len(dBytes)
	if dl > KeyBytes {
		raw := make([]byte, KeyBytes)
		copy(raw, dBytes[dl-KeyBytes:])
		return raw
	} else if dl < KeyBytes {
		raw := make([]byte, KeyBytes)
		copy(raw[KeyBytes-dl:], dBytes)
		return raw
	} else {

		return dBytes
	}
}

func calculatePubKey(priv *PrivateKey) *PublicKey {
	pub := new(PublicKey)
	pub.Curve = priv.Curve
	pub.X, pub.Y = priv.Curve.ScalarBaseMult(priv.D.Bytes())
	return pub
}

func nextK(rnd io.Reader, max *big.Int) (*big.Int, error) {
	intOne := new(big.Int).SetInt64(1)
	var k *big.Int
	var err error
	for {
		k, err = rand.Int(rnd, max)
		if err != nil {
			return nil, err
		}
		if k.Cmp(intOne) >= 0 {
			return k, err
		}
	}
}

func xor(data []byte, kdfOut []byte, dRemaining int) {
	for i := 0; i != dRemaining; i++ {
		data[i] ^= kdfOut[i]
	}
}

func kdf(digest hash.Hash, c1x *big.Int, c1y *big.Int, encData []byte) {
	bufSize := 4
	if bufSize < digest.BlockSize() {
		bufSize = digest.BlockSize()
	}
	buf := make([]byte, bufSize)

	encDataLen := len(encData)
	c1xBytes := c1x.Bytes()
	c1yBytes := c1y.Bytes()
	off := 0
	ct := uint32(0)
	for off < encDataLen {
		digest.Reset()
		digest.Write(c1xBytes)
		digest.Write(c1yBytes)
		ct++
		binary.BigEndian.PutUint32(buf, ct)
		digest.Write(buf[:4])
		tmp := digest.Sum(nil)
		copy(buf[:bufSize], tmp[:bufSize])

		xorLen := encDataLen - off
		if xorLen > digest.BlockSize() {
			xorLen = digest.BlockSize()
		}
		xor(encData[off:], buf, xorLen)
		off += xorLen
	}
}

func notEncrypted(encData []byte, in []byte) bool {
	encDataLen := len(encData)
	for i := 0; i != encDataLen; i++ {
		if encData[i] != in[i] {
			return false
		}
	}
	return true
}

func incCounter(ctr []byte) {
	if ctr[3]++; ctr[3] != 0 {
		return
	}
	if ctr[2]++; ctr[2] != 0 {
		return
	}
	if ctr[1]++; ctr[1] != 0 {
		return
	}
	if ctr[0]++; ctr[0] != 0 {
		return
	}
}

func concatKDF(hash hash.Hash, z, s1 []byte, kdLen int) (k []byte, err error) {
	if s1 == nil {
		s1 = make([]byte, 0)
	}
	reps := ((kdLen + 7) * 8) / (hash.BlockSize() * 8)

	counter := []byte{0, 0, 0, 1}
	k = make([]byte, 0)

	for i := 0; i <= reps; i++ {
		hash.Write(counter)
		hash.Write(z)
		hash.Write(s1)
		k = append(k, hash.Sum(nil)...)
		hash.Reset()
		incCounter(counter)
	}

	k = k[:kdLen]
	return
}

func Encrypt(pub *PublicKey, in []byte, cipherTextType Sm2CipherTextType) ([]byte, error) {
	R, _, err := GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	hash := sm3.New()
	z, err := R.GenerateShared(pub, 16, 16)
	if err != nil {
		return nil, err
	}
	K, err := concatKDF(hash, z, nil, 32)
	Ke := K[:16]
	c2 := make([]byte, len(in))
	copy(c2, in)
	var c1 []byte
	digest := sm3.New()
	var kPBx, kPBy *big.Int
	for {
		k, err := nextK(rand.Reader, pub.Curve.N)
		if err != nil {
			return nil, err
		}
		kBytes := k.Bytes()
		c1x, c1y := pub.Curve.ScalarBaseMult(kBytes)
		c1 = elliptic.Marshal(pub.Curve, c1x, c1y)
		kPBx, kPBy = pub.Curve.ScalarMult(pub.X, pub.Y, kBytes)
		kdf(digest, kPBx, kPBy, c2)

		if !notEncrypted(c2, in) {
			break
		}
	}

	digest.Reset()
	digest.Write(kPBx.Bytes())
	digest.Write(in)
	digest.Write(kPBy.Bytes())
	c3 := digest.Sum(nil)

	c1Len := len(c1)
	c2Len := len(c2)
	c3Len := len(c3)
	c4len := len(Ke)
	result := make([]byte, c1Len+c2Len+c3Len+c4len)
	if cipherTextType == C1C2C3 {
		copy(result[:c1Len], c1)
		copy(result[c1Len:c1Len+c2Len], c2)
		copy(result[c1Len+c2Len:], c3)
		copy(result[c1Len+c2Len+c3Len:], Ke)
	} else if cipherTextType == C1C3C2 {
		copy(result[:c1Len], c1)
		copy(result[c1Len:c1Len+c3Len], c3)
		copy(result[c1Len+c3Len:], c2)
		copy(result[c1Len+c2Len+c3Len:], Ke)
	} else {
		return nil, errors.New("unknown cipherTextType:" + string(cipherTextType))
	}
	return result, nil
}
func (prv *PrivateKey) GenerateShared(pub *PublicKey, skLen, macLen int) (sk []byte, err error) {
	if prv.PublicKey.Curve != pub.Curve {
		return nil, errors.New("ErrInvalidCurve")
	}
	if skLen+macLen > KeyBytes {
		return nil, errors.New("ErrSharedKeyTooBig")
	}
	x, _ := pub.Curve.ScalarMult(pub.X, pub.Y, prv.D.Bytes())
	if x == nil {
		return nil, errors.New("ErrSharedKeyIsPointAtInfinity")
	}

	sk = make([]byte, skLen+macLen)
	skBytes := x.Bytes()
	copy(sk[len(sk)-len(skBytes):], skBytes)
	return sk, nil
}

func Decrypt(priv *PrivateKey, in []byte, cipherTextType Sm2CipherTextType) ([]byte, error) {
	hash := sm3.New()
	z, err := priv.GenerateShared(&priv.PublicKey, 16, 16)
	if err != nil {
		return nil, err
	}
	K, err := concatKDF(hash, z, nil, 32)
	Ke := K[:16]
	c1Len := ((priv.Curve.BitSize+7)/8)*2 + 1
	c1 := make([]byte, c1Len)
	copy(c1, in[:c1Len])
	c1x, c1y := elliptic.Unmarshal(priv.Curve, c1)
	if c1x == nil || c1y == nil {
		log.Info("Decrypt publickey ", "c1x is ", c1x, "c1y is ", c1y, "c1 is", c1)
		return nil, errors.New("Decrypt publickey is err ")
	}
	sx, sy := priv.Curve.ScalarMult(c1x, c1y, sm2H.Bytes())
	if util.IsEcPointInfinity(sx, sy) {
		return nil, errors.New("[h]C1 at infinity")
	}
	c1x, c1y = priv.Curve.ScalarMult(c1x, c1y, priv.D.Bytes())

	digest := sm3.New()
	c3Len := digest.Size()
	c2Len := len(in) - c1Len - c3Len - len(Ke)
	c2 := make([]byte, c2Len)
	c3 := make([]byte, c3Len)
	if cipherTextType == C1C2C3 {
		copy(c2, in[c1Len:c1Len+c2Len])
		copy(c3, in[c1Len+c2Len:])
	} else if cipherTextType == C1C3C2 {
		copy(c3, in[c1Len:c1Len+c3Len])
		copy(c2, in[c1Len+c3Len:])
	} else {
		return nil, errors.New("unknown cipherTextType:" + string(cipherTextType))
	}

	kdf(digest, c1x, c1y, c2)

	digest.Reset()
	digest.Write(c1x.Bytes())
	digest.Write(c2)
	digest.Write(c1y.Bytes())
	newC3 := digest.Sum(nil)

	if !bytes.Equal(newC3, c3) {
		return nil, errors.New("invalid cipher text")
	}
	return c2, nil
}

func MarshalCipher(in []byte, cipherTextType Sm2CipherTextType) ([]byte, error) {
	byteLen := (sm2P256V1.Params().BitSize + 7) >> 3
	c1x := make([]byte, byteLen)
	c1y := make([]byte, byteLen)
	c2Len := len(in) - (1 + byteLen*2) - sm3.DigestLength
	c2 := make([]byte, c2Len)
	c3 := make([]byte, sm3.DigestLength)
	pos := 1

	copy(c1x, in[pos:pos+byteLen])
	pos += byteLen
	copy(c1y, in[pos:pos+byteLen])
	pos += byteLen
	nc1x := new(big.Int).SetBytes(c1x)
	nc1y := new(big.Int).SetBytes(c1y)

	if cipherTextType == C1C2C3 {
		copy(c2, in[pos:pos+c2Len])
		pos += c2Len
		copy(c3, in[pos:pos+sm3.DigestLength])
		result, err := asn1.Marshal(sm2CipherC1C2C3{nc1x, nc1y, c2, c3})
		if err != nil {
			return nil, err
		}
		return result, nil
	} else if cipherTextType == C1C3C2 {
		copy(c3, in[pos:pos+sm3.DigestLength])
		pos += sm3.DigestLength
		copy(c2, in[pos:pos+c2Len])
		result, err := asn1.Marshal(sm2CipherC1C3C2{nc1x, nc1y, c3, c2})
		if err != nil {
			return nil, err
		}
		return result, nil
	} else {
		return nil, errors.New("unknown cipherTextType:" + string(cipherTextType))
	}
}

func UnmarshalCipher(in []byte, cipherTextType Sm2CipherTextType) (out []byte, err error) {
	if cipherTextType == C1C2C3 {
		cipher := new(sm2CipherC1C2C3)
		_, err = asn1.Unmarshal(in, cipher)
		if err != nil {
			return nil, err
		}
		c1x := cipher.X.Bytes()
		c1y := cipher.Y.Bytes()
		c1xLen := len(c1x)
		c1yLen := len(c1y)
		c2Len := len(cipher.C2)
		c3Len := len(cipher.C3)
		result := make([]byte, 1+c1xLen+c1yLen+c2Len+c3Len)
		pos := 0
		result[pos] = UnCompress
		pos += 1
		copy(result[pos:pos+c1xLen], c1x)
		pos += c1xLen
		copy(result[pos:pos+c1yLen], c1y)
		pos += c1yLen
		copy(result[pos:pos+c2Len], cipher.C2)
		pos += c2Len
		copy(result[pos:pos+c3Len], cipher.C3)
		return result, nil
	} else if cipherTextType == C1C3C2 {
		cipher := new(sm2CipherC1C3C2)
		_, err = asn1.Unmarshal(in, cipher)
		if err != nil {
			return nil, err
		}
		c1x := cipher.X.Bytes()
		c1y := cipher.Y.Bytes()
		c1xLen := len(c1x)
		c1yLen := len(c1y)
		c2Len := len(cipher.C2)
		c3Len := len(cipher.C3)
		result := make([]byte, 1+c1xLen+c1yLen+c2Len+c3Len)
		pos := 0
		result[pos] = UnCompress
		pos += 1
		copy(result[pos:pos+c1xLen], c1x)
		pos += c1xLen
		copy(result[pos:pos+c1yLen], c1y)
		pos += c1yLen
		copy(result[pos:pos+c3Len], cipher.C3)
		pos += c3Len
		copy(result[pos:pos+c2Len], cipher.C2)
		return result, nil
	} else {
		return nil, errors.New("unknown cipherTextType:" + string(cipherTextType))
	}
}

func getZ(digest hash.Hash, curve *P256V1Curve, pubX *big.Int, pubY *big.Int, userId []byte) []byte {
	digest.Reset()
	userIdLen := uint16(len(userId) * 8)
	var userIdLenBytes [2]byte
	binary.BigEndian.PutUint16(userIdLenBytes[:], userIdLen)
	digest.Write(userIdLenBytes[:])
	if userId != nil && len(userId) > 0 {
		digest.Write(userId)
	}

	digest.Write(curve.A.Bytes())
	digest.Write(curve.B.Bytes())
	digest.Write(curve.Gx.Bytes())
	digest.Write(curve.Gy.Bytes())
	digest.Write(pubX.Bytes())
	digest.Write(pubY.Bytes())
	return digest.Sum(nil)
}

func calculateE(digest hash.Hash, curve *P256V1Curve, pubX *big.Int, pubY *big.Int, userId []byte, src []byte) *big.Int {
	z := getZ(digest, curve, pubX, pubY, userId)

	digest.Reset()
	digest.Write(z)
	digest.Write(src)
	eHash := digest.Sum(nil)
	return new(big.Int).SetBytes(eHash)
}
func toSignData(i *big.Int) []byte {
	b := i.Bytes()
	if len(b) > 32 {
		return nil
	}
	if len(b) < 32 {
		data := make([]byte,32)
		copy(data[32-len(b):],b)
		return data
	} else {
		return b
	}
}
// sign algorithm.
func SignToRS(priv *PrivateKey, userId []byte, in []byte) (r, s, ee *big.Int, err error) {
	digest := sm3.New()
	pubX, pubY := priv.Curve.ScalarBaseMult(priv.D.Bytes())
	if userId == nil {
		userId = sm2SignDefaultUserId
	}
	e := calculateE(digest, &priv.Curve, pubX, pubY, userId, in)
	//hash
	intZero := new(big.Int).SetInt64(0)
	intOne := new(big.Int).SetInt64(1)
	for {
		var k *big.Int
		var err error
		for {
			k, err = nextK(rand.Reader, priv.Curve.N)
			if err != nil {
				return nil, nil,nil, err
			}
			px, _ := priv.Curve.ScalarBaseMult(k.Bytes())
			r = util.Add(e, px)
			r = util.Mod(r, priv.Curve.N)

			rk := new(big.Int).Set(r)
			rk = rk.Add(rk, k)
			if r.Cmp(intZero) != 0 && rk.Cmp(priv.Curve.N) != 0 {
				break
			}
		}

		dPlus1ModN := util.Add(priv.D, intOne)
		dPlus1ModN = util.ModInverse(dPlus1ModN, priv.Curve.N)
		s = util.Mul(r, priv.D)
		s = util.Sub(k, s)
		s = util.Mod(s, priv.Curve.N)
		s = util.Mul(dPlus1ModN, s)
		s = util.Mod(s, priv.Curve.N)

		if s.Cmp(intZero) != 0 {
			break
		}
	}
	return r, s,new(big.Int).Set(e), nil
}

// gm sign with privatekey, r and s covert to byte array ,According to
// byte array length to implementation method.
func Sign(priv *PrivateKey, userId []byte, in []byte) ([]byte,*big.Int, error) {
	signrmark := 1   // unused
	r, s,e, err := SignToRS(priv, userId, in)
	if err != nil {
		return nil,nil, err
	}

	sig := make([]byte, 65)
	copy(sig[32-len(r.Bytes()):], r.Bytes())
	copy(sig[64-len(s.Bytes()):], s.Bytes())

	sig[64] = byte(signrmark)
	return sig,e, nil
}

// verify sign algorithm.
func VerifyByRS(pub *PublicKey, userId []byte, src []byte, r, s *big.Int) bool {
	intOne := new(big.Int).SetInt64(1)
	if r.Cmp(intOne) == -1 || r.Cmp(pub.Curve.N) >= 0 {
		return false
	}
	if s.Cmp(intOne) == -1 || s.Cmp(pub.Curve.N) >= 0 {
		return false
	}

	digest := sm3.New()
	if userId == nil {
		userId = sm2SignDefaultUserId
	}
	e := calculateE(digest, &pub.Curve, pub.X, pub.Y, userId, src)

	intZero := new(big.Int).SetInt64(0)
	t := util.Add(r, s)
	t = util.Mod(t, pub.Curve.N)
	if t.Cmp(intZero) == 0 {
		return false
	}

	sgx, sgy := pub.Curve.ScalarBaseMult(s.Bytes())
	tpx, tpy := pub.Curve.ScalarMult(pub.X, pub.Y, t.Bytes())
	x, y := pub.Curve.Add(sgx, sgy, tpx, tpy)
	if util.IsEcPointInfinity(x, y) {
		return false
	}

	expectedR := util.Add(e, x)
	expectedR = util.Mod(expectedR, pub.Curve.N)
	return expectedR.Cmp(r) == 0
}

// Verift sign with publickey.
func Verify(pub *PublicKey, userId []byte, src []byte, sign []byte) bool {
	return VerifyByRS(pub, userId, src, new(big.Int).SetBytes(sign[:32]), new(big.Int).SetBytes(sign[32:64]))
}

//  Validate sign value about v,r and s.
func ValidateSignatureValues(v byte, r, s *big.Int, homestead bool) bool {
	intOne := new(big.Int).SetInt64(1)
	var curve P256V1Curve
	if r.Cmp(intOne) == -1 {
		return false
	}
	if s.Cmp(intOne) == -1 {
		return false
	}
	if homestead && s.Cmp(curve.Params().N) >= 0 {
		return false
	}
	if v == 0 {
		return false
	}
	return true
}

// Get last bit
func getLastBit(a *big.Int) uint {
	return a.Bit(0)
}

// 32byte
func zeroByteSlice() []byte {
	return []byte{
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
}

// Compress publickey to 33  bytes.
func Compress(a *PublicKey) []byte {
	buf := []byte{}
	yp := getLastBit(a.Y)
	buf = append(buf, a.X.Bytes()...)
	if n := len(a.X.Bytes()); n < 32 {
		buf = append(zeroByteSlice()[:(32-n)], buf...)
	}
	// RFC: GB/T 32918.1-2016 4.2.9
	// if yp = 0, buf = 02||x
	// if yp = 0, buf = 03||x
	if yp == uint(0) {
		buf = append([]byte{byte(2)}, buf...)
	}
	if yp == uint(1) {
		buf = append([]byte{byte(3)}, buf...)
	}
	return buf
}

// Decompress transform  33 bytes publickey to publickey point struct.
func Decompress(a []byte) *PublicKey {
	var aa, xx, xx3, sma, smb sm2P256FieldElement

	x := new(big.Int).SetBytes(a[1:])
	curve := sm2P256V1
	sm2P256FromBig(&xx, x)
	sm2P256Square(&xx3, &xx)    // x3 = x ^ 2
	sm2P256Mul(&xx3, &xx3, &xx) // x3 = x ^ 2 * x
	sm2P256FromBig(&sma, curve.A)
	sm2P256Mul(&aa, &sma, &xx) // a = a * x
	sm2P256Add(&xx3, &xx3, &aa)
	sm2P256FromBig(&smb, curve.B)
	sm2P256Add(&xx3, &xx3, &smb)

	y2 := sm2P256ToBig(&xx3)
	y := new(big.Int).ModSqrt(y2, sm2P256V1.P)

	// RFC: GB/T 32918.1-2016 4.2.10
	// if a[0] = 02, getLastBit(y) = 0
	// if a[0] = 03, getLastBit(y) = 1
	// if yp = 0, buf = 03||x
	if getLastBit(y) != uint(a[0])-2 {
		y.Sub(sm2P256V1.P, y)
	}
	return &PublicKey{
		Curve: sm2P256V1,
		X:     x,
		Y:     y,
	}
}

// gm publickey covert to ecdsa publickey.
func ToECDSAPublickey(key *PublicKey) *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: key.Curve,
		X:     key.X,
		Y:     key.Y,
	}
}

//ecdsa publickey covert to gm publickey.
func ToSm2Publickey(key *ecdsa.PublicKey) *PublicKey {
	return &PublicKey{
		X:     key.X,
		Y:     key.Y,
		Curve: sm2P256V1,
	}
}

// ecdsa privatekey covert to gm privatekey.
func ToSm2privatekey(key *ecdsa.PrivateKey) *PrivateKey {
	return &PrivateKey{
		D:         key.D,
		PublicKey: *ToSm2Publickey(&key.PublicKey),
		Curve:     sm2P256V1,
	}
}

// gm privatekey covert to ecdsa privatekey.
func ToEcdsaPrivate(key *PrivateKey) *ecdsa.PrivateKey {
	return &ecdsa.PrivateKey{
		D:         key.D,
		PublicKey: *ToECDSAPublickey(&key.PublicKey),
	}
}

func SigToPub(hash, sig,userId []byte,ee *big.Int) (*ecdsa.PublicKey, error) {
	pk,ok ,err := RecoverCompactSM2(GetSm2P256V1(),sig,hash,userId,ee)
	if err != nil {
		fmt.Println("err ",err)
		panic(err)
	}
	if !ok {
		fmt.Println("ok ",ok)
		return nil,errors.New("sig to pub failed")
	}
	return ToECDSAPublickey(pk),nil
}

// RecoverCompact verifies the compact signature "signature" of "hash" for the
// Koblitz curve in "curve". If the signature matches then the recovered public
// key will be returned as well as a boolen if the original key was compressed
// or not, else an error will be returned.
func RecoverCompactSM2(curve P256V1Curve, signature,
	hash,userId []byte,ee *big.Int) (*PublicKey, bool, error) {
	bitlen := (curve.BitSize + 7) / 8
	if len(signature) != 1+bitlen*2 {
		return nil, false, errors.New("invalid compact signature size")
	}

	// iteration := int((signature[0] - 27) & ^byte(4))

	// format is <header byte><bitlen R><bitlen S>
	sig := &Sm2Signature{
		R: new(big.Int).SetBytes(signature[0: bitlen]),
		S: new(big.Int).SetBytes(signature[bitlen:64]),
	}
	// The iteration used here was encoded
	//key, err := recoverKeyFromSignatureSM2(curve, sig, hash, iteration, false)
	for i := 0; i < int(sm2H.Int64()+1)*2; i++ { 
		key, err := recoverKeyFromSignatureSM2_2(curve, ee,sig, hash, i, false)
		if err != nil {
			// return nil, false, err
			fmt.Println("e:",err)
		} else {
			// check e 
			digest := sm3.New()
			if userId == nil {
				userId = sm2SignDefaultUserId
			}
			e := calculateE(digest, &curve, key.X, key.Y, userId, hash)	
			if e.Cmp(ee) == 0 {
				return key,true,nil
			}
			// return key, false, nil
		}
	}
	return nil, false, nil
}

func recoverKeyFromSignatureSM2_2(curve P256V1Curve,ee *big.Int, sig *Sm2Signature, msg []byte,
	iter int, doChecks bool) (*PublicKey, error) {
	// 1.1 x = (n * i) + r - e 
	Rx := new(big.Int).Mul(curve.Params().N,
		new(big.Int).SetInt64(int64(iter/2)))
	Rx.Add(Rx, sig.R)
	Rx.Sub(Rx,ee)
	
	if Rx.Cmp(curve.Params().P) != -1 {
		return nil, errors.New("calculated Rx is larger than curve P")
	}

	// convert 02<Rx> to point R. (step 1.2 and 1.3). If we are on an odd
	// iteration then 1.6 will be done with -R, so we calculate the other
	// term when uncompressing the point.
	Ry, err := decompressPointSM2(curve, Rx, iter%2 == 1)
	if err != nil {
		return nil, err
	}
	// 1.4 Check n*R is point at infinity
	if doChecks {
		nRx, nRy := curve.ScalarMult(Rx, Ry, curve.Params().N.Bytes())
		if nRx.Sign() != 0 || nRy.Sign() != 0 {
			return nil, errors.New("n*R does not equal the point at infinity")
		}
	}

	// 1.5 calculate e from message using the same algorithm as ecdsa
	// signature calculation.
	// e := hashToInt(msg, curve)

	// Step 1.6.1:
	// We calculate the two terms sR and eG separately multiplied by the
	// inverse of r (from the signature). We then add them to calculate
	// Q = r^-1(sR-eG)
	// Q = (s+r)^-1(R-sG)
	invr := new(big.Int).ModInverse(new(big.Int).Add(sig.S,sig.R), curve.Params().N)
	// first term.
	// invrS := new(big.Int).Mul(invr, sig.S)
	// invrS.Mod(invrS, curve.Params().N)
	sRx, sRy := curve.ScalarMult(Rx, Ry, invr.Bytes())
	s := new(big.Int).Set(sig.S)
	// second term.
	s.Neg(s)
	s.Mod(s, curve.Params().N)
	s.Mul(s, invr)
	s.Mod(s, curve.Params().N)
	minuseGx, minuseGy := curve.ScalarBaseMult(s.Bytes())

	// TODO: this would be faster if we did a mult and add in one
	// step to prevent the jacobian conversion back and forth.
	Qx, Qy := curve.Add(sRx, sRy, minuseGx, minuseGy)
	return &PublicKey{
		Curve: curve,
		X:     Qx,
		Y:     Qy,
	}, nil
}

// 	sm2P256FromBig(&sm2P256.a, A)
func recoverKeyFromSignatureSM2(curve P256V1Curve, sig *Sm2Signature, msg []byte,
	iter int, doChecks bool) (*PublicKey, error) {
	//GetSm2P256V1()

	// 1.1 x = (n * i) + r
	Rx := new(big.Int).Mul(curve.Params().N,
		new(big.Int).SetInt64(int64(iter/2)))
	Rx.Add(Rx, sig.R)
	if Rx.Cmp(curve.Params().P) != -1 {
		return nil, errors.New("calculated Rx is larger than curve P")
	}

	// convert 02<Rx> to point R. (step 1.2 and 1.3). If we are on an odd
	// iteration then 1.6 will be done with -R, so we calculate the other
	// term when uncompressing the point.
	Ry, err := decompressPointSM2(curve, Rx, iter%2 == 1)
	if err != nil {
		return nil, err
	}

	// 1.4 Check n*R is point at infinity
	if doChecks {
		nRx, nRy := curve.ScalarMult(Rx, Ry, curve.Params().N.Bytes())
		if nRx.Sign() != 0 || nRy.Sign() != 0 {
			return nil, errors.New("n*R does not equal the point at infinity")
		}
	}

	// 1.5 calculate e from message using the same algorithm as ecdsa
	// signature calculation.
	e := hashToInt(msg, curve)

	// Step 1.6.1:
	// We calculate the two terms sR and eG separately multiplied by the
	// inverse of r (from the signature). We then add them to calculate
	// Q = r^-1(sR-eG)
	invr := new(big.Int).ModInverse(sig.R, curve.Params().N)

	// first term.
	invrS := new(big.Int).Mul(invr, sig.S)
	invrS.Mod(invrS, curve.Params().N)
	sRx, sRy := curve.ScalarMult(Rx, Ry, invrS.Bytes())

	// second term.
	e.Neg(e)
	e.Mod(e, curve.Params().N)
	e.Mul(e, invr)
	e.Mod(e, curve.Params().N)
	minuseGx, minuseGy := curve.ScalarBaseMult(e.Bytes())

	// TODO: this would be faster if we did a mult and add in one
	// step to prevent the jacobian conversion back and forth.
	Qx, Qy := curve.Add(sRx, sRy, minuseGx, minuseGy)

	return &PublicKey{
		Curve: curve,
		X:     Qx,
		Y:     Qy,
	}, nil
}

// decompressPoint decompresses a point on the given curve given the X point and
// the solution to use.
func decompressPointSM2(curve P256V1Curve, x *big.Int, ybit bool) (*big.Int, error) {
	// TODO: This will probably only work for secp256k1 due to
	// optimizations.

	// Y = +-sqrt(x^3 + B)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Add(x3, curve.Params().B)

	// Y = +-sqrt(x^3 + ax + B)
	var a, ax, x_ sm2P256FieldElement
	sm2P256FromBig(&a, curve.A)
	sm2P256FromBig(&x_, x)
	sm2P256Mul(&ax, &a, &x_) // a = a * x
	x3.Add(x3, sm2P256ToBig(&ax))

	// now calculate sqrt mod p of x2 + B
	// This code used to do a full sqrt based on tonelli/shanks,
	// but this was replaced by the algorithms referenced in
	// https://bitcointalk.org/index.php?topic=162805.msg1712294#msg1712294
	y := new(big.Int).Exp(x3, curve.QPlus1Div4(), curve.Params().P)

	if ybit != isOdd(y) {
		y.Sub(curve.Params().P, y)
	}
	if ybit != isOdd(y) {
		return nil, fmt.Errorf("ybit doesn't match oddness")
	}
	return y, nil
}

func (curve P256V1Curve) QPlus1Div4() *big.Int {
	return new(big.Int).Div(new(big.Int).Add(curve.P,
		big.NewInt(1)), big.NewInt(4))
}

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

// hashToInt converts a hash value to an integer. There is some disagreement
// about how this is done. [NSA] suggests that this is done in the obvious
// manner, but [SECG] truncates the hash to the bit-length of the curve order
// first. We follow [SECG] because that's what OpenSSL does. Additionally,
// OpenSSL right shifts excess bits from the number if the hash is too large
// and we mirror that too.
// This is borrowed from crypto/ecdsa.
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}