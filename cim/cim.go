package cim

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
	SetUpFromCA(rootCAByte []byte) error
	GetRootCert() Identity
	//GetTLSRootCert() []byte
	// revoke cert list
	//GetCrlList() []*pkix.CertificateList
	GetTLSIntermediateCert() []byte
	GetSigningIdentity() SigningIdentity
	Validate(id Identity) error
	///CreateIdentity(priv string) bool
	ValidateByByte(certByte []byte) error
	ValidateRootCert(certByte []byte) error
}

type Identity interface {
	//ExpiresAt() time.Time
	//detemine if the signature  is this identity singed.
	//Verify(msg []byte, sig []byte) error
	VerifyByte(cert []byte) error
	isEqulIdentity(cert []byte) error
}

// sign identity
type SigningIdentity interface {
	Identity
	Sign(msg []byte) ([]byte, error)
	GetPublicVersion() Identity
}

func CreateCim(certbyte []byte) CIM {
	cimCa, err := NewCIM()
	if err != nil {
		return nil
	}

	err = cimCa.SetUpFromCA(certbyte)
	if err != nil {
		return nil
	}

	return cimCa
}
