package cim

type Key interface {

	// Bytes converts this key to its byte representation,
	// if this operation is allowed.
	Bytes() ([]byte, error)

	// SKI returns the subject key identifier of this key.
	SKI() []byte

	// Symmetric returns true if this key is a symmetric key,
	// false is this key is asymmetric
	Symmetric() bool

	// Private returns true if this key is a private key,
	// false otherwise.
	Private() bool

	// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
	// This method returns an error in symmetric key schemes.
	PublicKey() (Key, error)
}
