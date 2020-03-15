package cim

import (
	"crypto/x509/pkix"
	"time"
)

type CIMManager interface {
	Init(msps []CIM) error
	// Get all the CIM
	GetCIMs() (map[string]CIM, error)
	// validate any identity
	Validate(id Identity)
}

type CIM interface {
	//uniq  id
	GetIdentifier()
	// construct consortium identity manager
	Init()
	GetRootCerts() [][]byte
	GetTLSRootCerts() [][]byte
	// revoke cert list
	GetCrlList() []*pkix.CertificateList
	GetTLSIntermediateCerts() [][]byte
	GetSigningIdentity() SigningIdentity
	Validate(id Identity) error
}

type Identity interface {
	ExpiresAt() time.Time
	//detemine if the signature  is this identity singed.
	Verify(msg []byte, sig []byte)
}

type SigningIdentity interface {
	Identity
	Sign(msg []byte) ([]byte, error)
	GetPublicVersion() Identity
}

type cimManagerImpl struct {
	cimMap map[string]CIM
}
