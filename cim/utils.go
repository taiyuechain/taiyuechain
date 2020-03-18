package cim

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/pkg/errors"
)

func GetIdentityFromByte(idBytes []byte) (Identity, error) {
	cert, err := GetCertFromPem(idBytes)
	if err != nil {
		return nil, err
	}

	keyImporter := &x509PublicKeyImportOptsKeyImporter{}
	opts := &X509PublicKeyImportOpts{Temporary: true}

	certPubK, err := keyImporter.KeyImport(cert, opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed importing key with opts")
	}

	identity, err := NewIdentity(cert, certPubK)
	if err != nil {
		return nil, err
	}
	return identity, nil
}

func GetCertFromPem(idBytes []byte) (*x509.Certificate, error) {
	if idBytes == nil {
		return nil, errors.New("getCertFromPem error: nil idBytes")
	}

	// Decode the pem bytes
	pemCert, _ := pem.Decode(idBytes)
	if pemCert == nil {
		return nil, errors.Errorf("getCertFromPem error: could not decode pem bytes [%v]", idBytes)
	}

	// get a cert
	var cert *x509.Certificate
	cert, err := x509.ParseCertificate(pemCert.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "getCertFromPem error: failed to parse x509 cert")
	}

	return cert, nil
}
