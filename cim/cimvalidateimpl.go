package cim

import (
	"github.com/pkg/errors"
)

func (cim *cimimpl) validateIdentity(id *identity) error {

	err := id.cert.CheckSignatureFrom(cim.rootCert.(*identity).cert)

	if err != nil {
		return errors.WithMessage(err, "could not obtain certification chain")
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
