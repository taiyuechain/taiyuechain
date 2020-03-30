package taiCrypto

var SymmetricCryptoType uint8
var AsymmetricCryptoType = ASYMMETRICCRYPTOECDSA
var HashCryptoType uint8

const (
	SYMMETRICCRYPTOSM4    = 1
	SYMMETRICCRYPTOAES    = 2
	ASYMMETRICCRYPTOECDSA = 3
	ASYMMETRICCRYPTOSM2   = 4
	HASHCRYPTOSM3         = 5
	HASHCRYPTOHAS3        = 6
)
