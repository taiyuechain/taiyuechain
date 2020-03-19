package cim

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

func readFile(file string) ([]byte, error) {
	fileCont, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, errors.Wrapf(err, "could not read file %s", file)
	}

	return fileCont, nil
}

func readPemFile(file string) ([]byte, error) {
	bytes, err := readFile(file)
	if err != nil {
		return nil, errors.Wrapf(err, "reading from file %s failed", file)
	}

	b, _ := pem.Decode(bytes)
	if b == nil { // TODO: also check that the type is what we expect (cert vs key..)
		return nil, errors.Errorf("no pem content for file %s", file)
	}
	return bytes, nil
}

func ReadPemFile(file string) ([]byte, error) {
	bytes, err := readFile(file)
	if err != nil {
		return nil, errors.Wrapf(err, "reading from file %s failed", file)
	}

	b, _ := pem.Decode(bytes)
	if b == nil { // TODO: also check that the type is what we expect (cert vs key..)
		return nil, errors.Errorf("no pem content for file %s", file)
	}
	return bytes, nil
}

func getPemMaterialFromDir(dir string) ([][]byte, error) {

	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return nil, err
	}

	content := make([][]byte, 0)
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, errors.Wrapf(err, "could not read directory %s", dir)
	}

	for _, f := range files {
		fullName := filepath.Join(dir, f.Name())

		f, err := os.Stat(fullName)
		if err != nil {
			continue
		}
		if f.IsDir() {
			continue
		}

		item, err := readPemFile(fullName)
		if err != nil {
			continue
		}

		content = append(content, item)
	}

	return content, nil
}

const (
	cacerts              = "cacerts"
	admincerts           = "admincerts"
	signcerts            = "signcerts"
	keystore             = "keystore"
	intermediatecerts    = "intermediatecerts"
	crlsfolder           = "crls"
	configfilename       = "config.yaml"
	tlscacerts           = "tlscacerts"
	tlsintermediatecerts = "tlsintermediatecerts"
)

func GetLocalIdentityDataFromConfig(signcertDir string) (Identity, error) {
	signcert, err := getPemMaterialFromDir(signcertDir)
	if err != nil || len(signcert) == 0 {
		return nil, errors.Wrapf(err, "could not load a valid signer certificate from directory %s", signcertDir)
	}
	return GetIdentityFromByte(signcert[0])
}

func GetLocalCmiConfig(dir string, ID string) (*CIMConfig, error) {
	signcertDir := filepath.Join(dir, signcerts)
	keystoreDir := filepath.Join(dir, keystore)

	signcert, err := getPemMaterialFromDir(signcertDir)
	if err != nil || len(signcert) == 0 {
		return nil, errors.Wrapf(err, "could not load a valid signer certificate from directory %s", signcertDir)
	}

	privatesign, err := getPemMaterialFromDir(keystoreDir)
	if err != nil || len(signcert) == 0 {
		return nil, errors.Wrapf(err, "could not load a valid signer certificate from directory %s", signcertDir)
	}

	/* FIXME: for now we're making the following assumptions
	1) there is exactly one signing cert
	2) BCCSP's KeyStore has the private key that matches SKI of
	   signing cert
	*/

	sigid := &SigningIdentityInfo{PublicSigner: signcert[0], PrivateSigner: privatesign[0]}

	return getCmiConfig(dir, ID, sigid)
}

func getCmiConfig(dir string, ID string, sigid *SigningIdentityInfo) (*CIMConfig, error) {
	cacertDir := filepath.Join(dir, cacerts)
	admincertDir := filepath.Join(dir, admincerts)
	intermediatecertsDir := filepath.Join(dir, intermediatecerts)
	crlsDir := filepath.Join(dir, crlsfolder)
	tlscacertDir := filepath.Join(dir, tlscacerts)
	tlsintermediatecertsDir := filepath.Join(dir, tlsintermediatecerts)

	cacerts, err := getPemMaterialFromDir(cacertDir)
	if err != nil || len(cacerts) == 0 {
		return nil, errors.WithMessage(err, fmt.Sprintf("could not load a valid ca certificate from directory %s", cacertDir))
	}

	admincert, err := getPemMaterialFromDir(admincertDir)
	if err != nil || len(admincert) == 0 {
		return nil, errors.WithMessage(err, fmt.Sprintf("could not load a valid admin certificate from directory %s", admincertDir))
	}

	intermediatecerts, err := getPemMaterialFromDir(intermediatecertsDir)
	if os.IsNotExist(err) {
	} else if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("failed loading intermediate ca certs at [%s]", intermediatecertsDir))
	}

	tlsCACerts, err := getPemMaterialFromDir(tlscacertDir)
	tlsIntermediateCerts := [][]byte{}
	if os.IsNotExist(err) {
	} else if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("failed loading TLS ca certs at [%s]", tlsintermediatecertsDir))
	} else if len(tlsCACerts) != 0 {
		tlsIntermediateCerts, err = getPemMaterialFromDir(tlsintermediatecertsDir)
		if os.IsNotExist(err) {
		} else if err != nil {
			return nil, errors.WithMessage(err, fmt.Sprintf("failed loading TLS intermediate ca certs at [%s]", tlsintermediatecertsDir))
		}
	} else {
	}

	crls, err := getPemMaterialFromDir(crlsDir)
	if os.IsNotExist(err) {
	} else if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("failed loading crls at [%s]", crlsDir))
	}

	cimconf := &CIMConfig{
		Admins:               admincert,
		RootCerts:            cacerts,
		IntermediateCerts:    intermediatecerts,
		SigningIdentity:      sigid,
		Name:                 ID,
		RevocationList:       crls,
		TlsRootCerts:         tlsCACerts,
		TlsIntermediateCerts: tlsIntermediateCerts,
	}

	return cimconf, nil
}
