package cim

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/pkg/errors"
)



func (cim *cimimpl) setupCrypto() error {

	if cim.cryptoConfig == nil {
		// Move to defaults
		cim.cryptoConfig = &CryptoConfig{
			SignatureHashFamily:            "SHA2",
			IdentityIdentifierHashFunction: "SHA256",
		}
	}
	return nil
}


func (cim *cimimpl) getCertFromPem(idBytes []byte) (*x509.Certificate, error) {
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

func (cim *cimimpl) setupAdmin() error {
	return nil
}

func (cim *cimimpl) setupCRL() error {
	return nil
}

