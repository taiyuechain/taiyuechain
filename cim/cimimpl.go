package cim

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
)

type cimManagerImpl struct {
	cimMap map[string]CIM
}

type cimimpl struct {
	rootCerts         []Identity
	intermediateCerts []Identity

	tlsRootCerts         [][]byte
	tlsIntermediateCerts [][]byte

	admins []Identity
	CRL    []*pkix.CertificateList
}

type identity struct {
	cert *x509.Certificate
	//Public key
	pk [][]byte
}

type signingidentity struct {
	// we embed everything from a base identity
	identity
	// signer corresponds to the object that can produce signatures from this identity
	signer crypto.Signer
}
