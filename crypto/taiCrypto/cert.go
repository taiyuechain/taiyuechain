package taiCrypto

import (
	"crypto/x509"
	"errors"
	"github.com/taiyuechain/taiyuechain/cim"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm2/cert"
)

type Ciminterface interface {
	CreateIdentity2(priv, priv2 *TaiPrivateKey, name string) bool
	VarifyCertByPubkey(pub *TaiPublicKey, cert []byte) error
	ReadPemFileByPath(path string) ([]byte, error)
	GetCertFromPem(idBytes []byte) (*x509.Certificate, error)
}

func (TPK *TaiPrivateKey) CreateIdentity2(priv, priv2 *TaiPrivateKey, name string) bool {
	switch CertType {
	case CERTGM:
		return cert.CreateCertificateRequest(&priv.GmPrivate.PublicKey, &priv.GmPrivate, nil, name)
	case CERTECDSA:
		return cim.CreateIdentity2((priv.EciesPrivate).ExportECDSA(), (priv2.EciesPrivate).ExportECDSA(), name)
	}
	return false
}
func (TPK *TaiPrivateKey) VarifyCertByPubkey(pub *TaiPublicKey, certbyte []byte) error {
	switch CertType {
	case CERTGM:
		return cert.VarifyCertByPubKey(&pub.SmPublickey, certbyte)
	case CERTECDSA:
		return cim.VarifyCertByPubKey(&pub.Publickey, certbyte)
	}
	return errors.New("")
}
func (TPK *TaiPrivateKey) ReadPemFileByPath(path string) ([]byte, error) {
	switch CertType {
	case CERTGM:
		return cert.ReadPemFileByPath(path)
	case CERTECDSA:
		return cim.ReadPemFileByPath(path)
	}
	return nil, errors.New("path is wrong")
}
func (TPK *TaiPrivateKey) GetCertFromPem(idBytes []byte) (*x509.Certificate, error) {
	switch CertType {
	case CERTGM:
		//return cert.ParseCertificateRequest(idBytes)
	case CERTECDSA:
		//cim,err:=cim.NewCIM()
		return cim.GetCertFromPem(idBytes)
	}
	return nil, errors.New("path is wrong")
}
