package cim

import (
	"crypto/x509"
	"crypto/x509/pkix"

	"errors"

	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/core/types"
)





type CimList struct {
	CryptoType uint8
	CimMap []CIM
}

func NewCIMList(CryptoType uint8) *CimList {
	return &CimList{CryptoType:CryptoType}

}

func (cl *CimList) AddCim(cimTemp CIM) error  {
	for _,ci:= range cl.CimMap{
		if ci == cimTemp{
			return errors.New("have one CIM")
		}
		//verfiy
	}

	cl.CimMap = append(cl.CimMap, cimTemp)
	return nil
}

func (cl *CimList) DelCim(cimTemp *CIM) error  {

	 success := false
	for i,ci:= range cl.CimMap{
		if &ci == cimTemp{
			cl.CimMap = append(cl.CimMap[:i],cl.CimMap[i+1:]...)
			success = true
		}
	}

	if !success{
		return errors.New("not find CIM")
	}

	return nil
}

func (cl *CimList) VerifyCert(cert []byte) error  {

	//var err error
	errNumber :=0;
	for _,ci:= range cl.CimMap{
		err := ci.ValidateByByte(cert)
		if err != nil{
			errNumber++;
		}else{
			return nil
		}

	}
	if errNumber == len(cl.CimMap){
		return errors.New("can not find right root cert")
	}else{
		return nil
	}

}

func (cl *CimList) VerifyRootCert(cert []byte) error  {

	//var err error
	findOne :=false
	for _,ci:= range cl.CimMap{
		err := ci.ValidateRootCert(cert)
		if err != nil{
			continue
		}else{
			findOne = true
		}
	}
	if !findOne {
		return errors.New("not find this root cert")
	}
	return nil
}

func (cl *CimList) VerifyPermission(operatorFrom common.Address,tx *types.Transaction) bool  {
	return true
}

func (cl *CimList)UpdataCert(clist [][]byte)  {

	if len(clist) == 0{
		return
	}
	cl.CimMap = make([]CIM,len(clist))

	for _,v :=range clist{
		cimCa, _ := NewCIM()
		cimCa.SetUpFromCA(v)
		cl.AddCim(cimCa)
	}

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


func (cim *cimimpl) ValidateByByte(certByte []byte) error {
	return cim.rootCert.VerifyByte(certByte)
}
func (cim *cimimpl) ValidateRootCert(certByte []byte) error {
	return cim.rootCert.isEqulIdentity(certByte)
}




/*func (cim *cimimpl) CreateIdentity(priv string) bool {
	//var private taiCrypto.TaiPrivateKey
	//var public taiCrypto.TaiPublicKey
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Country:            []string{"China"},
			Organization:       []string{"Yjwt"},
			OrganizationalUnit: []string{"YjwtU"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	ecdsa, err := crypto.HexToECDSA(priv)
	//var thash taiCrypto.THash
	caecda, err := crypto.ToECDSA(crypto.FromECDSA(ecdsa))
	if err != nil {
		log.Println("create ca failed", err)
		return false
	}
	ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca, &caecda.PublicKey, &caecda)
	if err != nil {
		log.Println("create ca failed", err)
		return false
	}
	encodeString := base64.StdEncoding.EncodeToString(ca_b)
	fileName := priv[:4] + "ca.pem"
	dstFile, err := os.Create(fileName)
	if err != nil {
		return false
	}
	defer dstFile.Close()
	priv_b, _ := x509.MarshalECPrivateKey(caecda)
	encodeString1 := base64.StdEncoding.EncodeToString(priv_b)
	if err != nil {
		fmt.Println(err)
	}
	fileName1 := priv[:4] + "ca.key"
	dstFile1, err := os.Create(fileName1)
	if err != nil {
		return false
	}
	defer dstFile1.Close()
	dstFile1.WriteString(encodeString1 + "\n")
	fmt.Println(encodeString)
	return true
}*/
