package cim

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/pkg/errors"
)

type cimManagerImpl struct {
	cimMap map[string]CIM
}

type cimimpl struct {
	name string

	rootCert         Identity
	intermediateCert Identity

	tlsRootCert         []byte
	tlsIntermediateCert []byte

	opts                              *x509.VerifyOptions
	certificationTreeInternalNodesMap map[string]bool

	signer SigningIdentity

	admins []Identity
	CRL    []*pkix.CertificateList

	cryptoConfig *CryptoConfig
}

func newCIM() (CIM, error) {

	theCIM := &cimimpl{}
	return theCIM, nil
}

func (cim *cimimpl) GetIdentifier() string {
	panic("implement me")
}

func (cim *cimimpl) setUp(conf CIMConfig) error {
	err := cim.preSetup(conf)
	if err != nil {
		return err
	}
	if err != nil {
		return err
	}

	return nil
}

func (cim *cimimpl) GetRootCert() Identity {
	return cim.rootCert
}

func (cim *cimimpl) GetTLSRootCert() []byte {
	return cim.tlsRootCert
}

func (cim *cimimpl) GetCrlList() []*pkix.CertificateList {
	return cim.CRL
}

func (cim *cimimpl) GetTLSIntermediateCert() []byte {
	return cim.tlsIntermediateCert
}

func (cim *cimimpl) GetSigningIdentity() SigningIdentity {
	panic("implement me")
}

func (cim *cimimpl) Validate(id Identity) error {
	switch id := id.(type) {
	// If this identity is of this specific type,
	// this is how I can validate it given the
	// root of trust this MSP has
	case *identity:
		return cim.validateIdentity(id)
	default:
		return errors.New("identity type not recognized")
	}
}
