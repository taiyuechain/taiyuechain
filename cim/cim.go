package cim

import (
	"crypto/x509/pkix"
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

type CIM interface {
	//cim uniq  id
	GetIdentifier() string
	// construct consortium identity manager
	newCIM()
	GetRootCerts() [][]byte
	GetTLSRootCerts() [][]byte
	// revoke cert list
	GetCrlList() []*pkix.CertificateList
	GetTLSIntermediateCerts() [][]byte
	GetSigningIdentity() SigningIdentity
	Validate(id Identity) (bool, error)
}

type Identity interface {
	ExpiresAt() time.Time
	//detemine if the signature  is this identity singed.
	Verify(msg []byte, sig []byte) (bool, error)
}

type SigningIdentity interface {
	Identity
	Sign(msg []byte) ([]byte, error)
	GetPublicVersion() Identity
}
