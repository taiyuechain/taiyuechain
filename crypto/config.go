package crypto

const (
	CRYPTO_P256_SH3 = 1 //GUOJI HASH AND   Asymmetric Encryption
	CRYPTO_SM2_SM3  = 2 //GUOMI hash and  Asymmetric Encryption;
	CRYPTO_S256_SH3 = 3
)

var cryptotype uint8

func SetCrtptoType(cryptoType uint8) {
	cryptotype = cryptoType
}
