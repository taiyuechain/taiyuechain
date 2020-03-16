package cim

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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
	if err := cim.setupSigningIdentity(conf); err != nil {
		return err
	}
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

	id, _, err := cim.getIdentityFromConf(conf.RootCerts[0])
	if err != nil {
		return err
	}

	cim.rootCert = id
	return nil
}

func (cim *cimimpl) getIdentityFromConf(idBytes []byte) (Identity, []byte, error) {
	cert, err := cim.getCertFromPem(idBytes)
	if err != nil {
		return nil, nil, err
	}
	// get the public key in the right format
	certPubK, err := cim.KeyImport(cert)
	if err != nil {
		return nil, nil, err
	}

	identity, err := newIdentity(cert, certPubK)
	if err != nil {
		return nil, nil, err
	}
	return identity, certPubK, nil
}

func (cim *cimimpl) KeyImport(raw interface{}) (pk []byte, err error) {
	// Validate arguments
	if raw == nil {
		return nil, errors.New("Invalid raw. Cannot be nil")
	}
	x509Cert, ok := raw.(*x509.Certificate)
	if !ok {
		return nil, errors.New("[X509PublicKeyImportOpts] Invalid raw material. Expected *x509.Certificate")
	}
	return x509Cert.PublicKey.([]byte), nil

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
	idPub, pubKey, err := cim.getIdentityFromConf(sig.PublicSigner)
	if err != nil {
		return nil, err
	}

	pk, err := KeyImport(sig.PrivateSigner)
	if err != nil {
		return nil, errors.WithMessage(err, "pk key import error")
	}

	cryptosig, err := NewCryptoSigner(idPub.(*identity).cert, *pk)
	if err != nil {
		return nil, errors.WithMessage(err, "NewCryptoSigner error")
	}

	return newSigningIdentity(idPub.(*identity).cert, pubKey, cryptosig)
}

func KeyImport(raw interface{}) (key *ecdsa.PrivateKey, err error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[ECDSADERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[ECDSADERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := DERToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to ECDSA public key [%s]", err)
	}

	ecdsaSK, ok := lowLevelKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to ECDSA private key. Invalid raw material.")
	}

	return ecdsaSK, nil
}

// DERToPrivateKey unmarshals a der to private key
func DERToPrivateKey(der []byte) (key interface{}, err error) {

	if key, err = x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	if key, err = x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return
		default:
			return nil, errors.New("Found unknown private key type in PKCS#8 wrapping")
		}
	}

	if key, err = x509.ParseECPrivateKey(der); err == nil {
		return
	}

	return nil, errors.New("Invalid key type. The DER must contain an rsa.PrivateKey or ecdsa.PrivateKey")
}
