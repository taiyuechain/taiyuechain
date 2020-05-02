package cim

import (
	"crypto/x509/pkix"
	"time"
	"github.com/taiyuechain/taiyuechain/params"
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
type CIMConfig struct {
	Name                 string
	RootCerts            [][]byte
	IntermediateCerts    [][]byte
	Admins               [][]byte
	RevocationList       [][]byte
	SigningIdentity      *SigningIdentityInfo
	TlsRootCerts         [][]byte
	TlsIntermediateCerts [][]byte
}

// consortium indentity  manager
type CIM interface {
	//cim uniq  id
	GetIdentifier() string
	// construct consortium identity manager
	SetUp(conf *CIMConfig) error
	SetUpFromCA(rootCAByte []byte) error
	GetRootCert() Identity
	GetTLSRootCert() []byte
	// revoke cert list
	GetCrlList() []*pkix.CertificateList
	GetTLSIntermediateCert() []byte
	GetSigningIdentity() SigningIdentity
	Validate(id Identity) error
	CreateIdentity(priv string) bool
	ValidateByByte(certByte []byte,chainConfig *params.ChainConfig) error
	ValidateRootCert(certByte []byte,chainConfig *params.ChainConfig) error
}

type Identity interface {
	ExpiresAt() time.Time
	//detemine if the signature  is this identity singed.
	Verify(msg []byte, sig []byte) error
	VerifyByte(cert []byte,chainConfig *params.ChainConfig) error
	isEqulIdentity(cert []byte,chainConfig *params.ChainConfig) error

}

// sign identity
type SigningIdentity interface {
	Identity
	Sign(msg []byte) ([]byte, error)
	GetPublicVersion() Identity
}

type SigningIdentityInfo struct {
	PublicSigner []byte
	// PrivateSigner denotes a reference to the private key of the
	// peer's signing identity
	PrivateSigner []byte
}
