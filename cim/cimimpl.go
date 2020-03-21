package cim

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/pkg/errors"
	"os"
)

type cimManagerImpl struct {
	cimMap map[string]CIM
}

func InitCrypto(cimConfigDir, cimID string) error {
	var err error
	// Check whether CIM folder exists
	fi, err := os.Stat(cimConfigDir)
	if os.IsNotExist(err) || !fi.IsDir() {
		return errors.Errorf("cannot init crypto, missing %s folder", cimConfigDir)
	}
	if cimID == "" {
		return errors.New("the local cim must have an ID")
	}

	err = LoadLocalCIM(cimConfigDir, cimID)
	if err != nil {
		return errors.WithMessage(err, fmt.Sprintf("error when setting up from directory"))
	}

	return nil
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

func NewCIM() (CIM, error) {

	theCIM := &cimimpl{}
	return theCIM, nil
}

func (cim *cimimpl) GetIdentifier() string {
	panic("implement me")
}

func (cim *cimimpl) SetUp(conf *CIMConfig) error {
	err := cim.preSetup(*conf)
	if err != nil {
		return err
	}
	if err != nil {
		return err
	}

	return nil
}

func (cim *cimimpl) SetUpFromCA(rootCAByte []byte) error {
	if len(rootCAByte) == 0 {
		return errors.New("expected at least one CA certificate")
	}

	id, err := GetIdentityFromByte(rootCAByte)
	if err != nil {
		return err
	}

	cim.rootCert = id
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
	return cim.signer
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
