package certinterface

import (
	"crypto/x509"
	"errors"
	"github.com/taiyuechain/taiyuechain/cim"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm2/cert"
	"github.com/taiyuechain/taiyuechain/crypto/taiCrypto"
)

type Ciminterface interface {
	CreateIdentity2(priv, priv2 *taiCrypto.TaiPrivateKey, name string) bool
	VarifyCertByPubkey(pub *taiCrypto.TaiPublicKey, cert []byte) error
	ReadPemFileByPath(path string) ([]byte, error)
	GetCertFromPem(idBytes []byte) (*x509.Certificate, error)
}
type taicrypto taiCrypto.TaiPrivateKey

func (TPK *taicrypto) CreateIdentity2(priv, priv2 *taiCrypto.TaiPrivateKey, name string) bool {
	switch taiCrypto.CertType {
	case taiCrypto.CERTGM:
		return cert.CreateCertificateRequest(&priv.GmPrivate.PublicKey, &priv.GmPrivate, nil, name)
	case taiCrypto.CERTECDSA:
		return cim.CreateIdentity2((priv.EciesPrivate).ExportECDSA(), (priv2.EciesPrivate).ExportECDSA(), name)
	}
	return false
}
func (TPK *taicrypto) VarifyCertByPubkey(pub *taiCrypto.TaiPublicKey, certbyte []byte) error {
	switch taiCrypto.CertType {
	case taiCrypto.CERTGM:
		return cert.VarifyCertByPubKey(&pub.SmPublickey, certbyte)
	case taiCrypto.CERTECDSA:
		return cim.VarifyCertByPubKey(&pub.Publickey, certbyte)
	}
	return errors.New("")
}
func (TPK *taicrypto) ReadPemFileByPath(path string) ([]byte, error) {
	switch taiCrypto.CertType {
	case taiCrypto.CERTGM:
		return cert.ReadPemFileByPath(path)
	case taiCrypto.CERTECDSA:
		return cim.ReadPemFileByPath(path)
	}
	return nil, errors.New("path is wrong")
}
func (TPK *taicrypto) GetCertFromPem(idBytes []byte) (*x509.Certificate, error) {
	/*switch taiCrypto.CertType {
	case taiCrypto.CERTGM:
		certquest, err := cert.ParseCertificateRequest(idBytes)
		if err != nil {
			return nil, err
		}
		return cert.ToCertificate(certquest), nil
	case taiCrypto.CERTECDSA:
		//cim,err:=cim.NewCIM()
		return cim.GetCertFromPem(idBytes)
	}*/
	return nil, errors.New("path is wrong")
}
