package taiCrypto

var SymmetricCryptoType uint8
var AsymmetricCryptoType = ASYMMETRICCRYPTOECDSA
var HashCryptoType = HASHCRYPTOHAS3
var CAAsymmetricCryptoType = CAASYMMETRICCRYPTOECDSA
var CertType uint8

const (
	SYMMETRICCRYPTOSM4      = 1
	SYMMETRICCRYPTOAES      = 2
	ASYMMETRICCRYPTOECDSA   = 3
	ASYMMETRICCRYPTOSM2     = 4
	HASHCRYPTOSM3           = 5
	HASHCRYPTOHAS3          = 6
	CAASYMMETRICCRYPTOECDSA = 7
	CAASYMMETRICCRYPTOSM2   = 8
	CERTGM                  = 9
	CERTECDSA               = 10
)
