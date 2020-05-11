package crypto

const (
	CRYPTO_P256_SH3_AES = 1 //GUOJI HASH AND   Asymmetric Encryption
	CRYPTO_SM2_SM3_SM4  = 2 //GUOMI hash and  Asymmetric Encryption;
	CRYPTO_S256_SH3_AES = 3
)

var cryptotype = CRYPTO_SM2_SM3_SM4

func SetCrtptoType(cryptoType uint8) {
	cryptotype = int(cryptoType)
}
