package crypto

const (
	CRYPTO_P256_SH3_AES = 1 //GUOJI HASH AND   Asymmetric Encryption
	CRYPTO_SM2_SM3_SM4  = 2 //GUOMI hash and  Asymmetric Encryption;
	CRYPTO_S256_SH3_AES = 3
)

var CryptoType = CRYPTO_S256_SH3_AES

func SetCrtptoType(cryptoType uint8) {
	if int(cryptoType) >= CRYPTO_P256_SH3_AES && int(cryptoType) <= CRYPTO_S256_SH3_AES  {
		CryptoType = int(cryptoType)
	}
}
