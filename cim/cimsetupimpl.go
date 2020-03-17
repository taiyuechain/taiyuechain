package cim

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/pkg/errors"
	"time"
)

func (cim *cimimpl) preSetup(conf CIMConfig) error {
	// setup crypto config
	if err := cim.setupCrypto(); err != nil {
		return err
	}

	// Setup CAs
	if err := cim.setupCA(conf); err != nil {
		return err
	}

	// setup the signer (if present)
	//if err := cim.setupSigningIdentity(conf); err != nil {
	//	return err
	//}
	return nil
}

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

func (cim *cimimpl) setupCA(conf CIMConfig) error {

	if len(conf.RootCerts) == 0 {
		return errors.New("expected at least one CA certificate")
	}

	id, err := GetIdentityFromConf(conf.RootCerts[0])
	if err != nil {
		return err
	}

	cim.rootCert = id
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

func (cim *cimimpl) setupSigningIdentity(conf CIMConfig) error {
	sid, err := cim.getSigningIdentityFromConf(conf.SigningIdentity)
	if err != nil {
		return err
	}

	expirationTime := sid.ExpiresAt()
	now := time.Now()
	if expirationTime.After(now) {
	} else if expirationTime.IsZero() {
	} else {
		return errors.Errorf("signing identity expired %v ago", now.Sub(expirationTime))
	}

	cim.signer = sid

	return nil
}

func (cim *cimimpl) getSigningIdentityFromConf(sig *SigningIdentityInfo) (SigningIdentity, error) {
	// Extract the public part of the identity
	idPub, err := GetIdentityFromConf(sig.PublicSigner)
	if err != nil {
		return nil, err
	}

	pk, err := KeyStoreImport(sig.PrivateSigner)
	if err != nil {
		return nil, errors.WithMessage(err, "pubKey key import error")
	}

	if err != nil {
		return nil, errors.WithMessage(err, "NewCryptoSigner error")
	}

	return newSigningIdentity(idPub.(*identity).cert, pk)
}
