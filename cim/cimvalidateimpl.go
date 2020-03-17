package cim

import (
	"github.com/pkg/errors"
	"time"
)

func (cim *cimimpl) validateIdentity(id *identity) error {

	err := id.cert.CheckSignatureFrom(cim.rootCert.(*identity).cert)

	if id.cert.IsCA {
		return errors.New("An X509 certificate with Basic Constraint: " +
			"Certificate Authority equals true cannot be used as an identity")
	}
	now := time.Now()
	if now.Before(id.cert.NotBefore) || now.After(id.cert.NotAfter) {
		return errors.New("x509: certificate has expired or is not yet valid")
	}

	if err != nil {
		return errors.WithMessage(err, "could not validate cert.")
	}

	//validationChain, err := cim.getCertificationChainForIdentity(id)
	//if err != nil {
	//	return errors.WithMessage(err, "could not obtain certification chain")
	//}

	//err = cim.validateIdentityAgainstChain(id, validationChain)
	//if err != nil {
	//	return errors.WithMessage(err, "could not validate identity against certification chain")
	//}

	//err = cim.validateIdentityOUsV11(id)
	//if err != nil {
	//	return errors.WithMessage(err, "could not validate identity's OUs")
	//}

	return nil
}
