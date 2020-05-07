package cim

import (
	"time"
)

type CIMManager interface {
	newCIMManager() error
	// Get all the CIM
	GetCIMs() (map[string]CIM, error)
	GetCIM(identifier string) (CIM, error)
	// validate any identity
	Validate(id Identity)
}

type CryptoConfig struct {
	SignatureHashFamily            string
	IdentityIdentifierHashFunction string
}

// Cim Config sets
/*type CIMConfig struct {
	Name                 string
	RootCerts            [][]byte
	IntermediateCerts    [][]byte
	Admins               [][]byte
	RevocationList       [][]byte
	//SigningIdentity      *SigningIdentityInfo
	TlsRootCerts         [][]byte
	TlsIntermediateCerts [][]byte
}*/

// consortium indentity  manager
type CIM interface {
	//cim uniq  id
	//GetIdentifier() string
	// construct consortium identity manager
	//SetUp(conf *CIMConfig) error
	SetUpFromCA(rootCAByte []byte,cryptoType uint8) error
	//GetRootCert() Identity
	//GetTLSRootCert() []byte
	// revoke cert list
	//GetCrlList() []*pkix.CertificateList
	GetTLSIntermediateCert() []byte
	GetSigningIdentity() SigningIdentity
	Validate(id Identity) error
	///CreateIdentity(priv string) bool
	ValidateByByte(certByte []byte,cryptoType uint8) error
	ValidateRootCert(certByte []byte,cryptoType uint8) error
}

type Identity interface {
	ExpiresAt() time.Time
	//detemine if the signature  is this identity singed.
	//Verify(msg []byte, sig []byte) error
	VerifyByte(cert []byte ,cryptoType uint8) error
	isEqulIdentity(cert []byte,cryptoType uint8) error

}

// sign identity
type SigningIdentity interface {
	Identity
	Sign(msg []byte) ([]byte, error)
	GetPublicVersion() Identity
}
