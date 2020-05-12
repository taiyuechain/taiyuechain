package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm4"
)

func NewCipher(key []byte) (cipher.Block, error) {
	if CryptoType == CRYPTO_P256_SH3_AES {
		return aes.NewCipher(key)
	}
	if CryptoType == CRYPTO_SM2_SM3_SM4 {
		return sm4.NewCipher(key)
	}
	return nil, nil
}
