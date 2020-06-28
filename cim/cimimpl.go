package cim

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"

	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/core/types"
	"github.com/taiyuechain/taiyuechain/core/state"
	"sync"
	"github.com/taiyuechain/taiyuechain/core/vm"
	//"github.com/taiyuechain/taiyuechain/core/evm"
	"bytes"
	"github.com/taiyuechain/taiyuechain/params"
	"math/big"
)






type CimList struct {
	lock sync.Mutex
	CryptoType uint8
	CimMap []CIM
	CIM_Epoch  *big.Int
	PTable *vm.PerminTable
}

func NewCIMList(CryptoType uint8) *CimList {
	return &CimList{CryptoType:CryptoType}

}

func  (cl *CimList) InitCertAndPermission(height *big.Int,stateDB *state.StateDB) error {
	caCertList := vm.NewCACertList()
	err := caCertList.LoadCACertList(stateDB, types.CACertListAddress)
	if err != nil {
		return err
	}
	epoch := types.GetEpochIDFromHeight(height)
	cl.SetCertEpoch(epoch)
	for _, caCert := range caCertList.GetCACertMapByEpoch(epoch.Uint64()).CACert {
		cimCa, err := NewCIM()
		if err != nil {
			return err
		}

		err = cimCa.SetUpFromCA(caCert)
		if err != nil {
			return err
		}
		err = cl.AddCim(cimCa)
		if err != nil {
			return err
		}
	}
	err = cl.UpdataPermission(stateDB)
	if err != nil {
		return err
	}

	return nil
}

func  (cl *CimList) SetCertEpoch(epoch *big.Int)  {
	cl.CIM_Epoch = epoch
}

func (cl *CimList) AddCim(cimTemp CIM) error  {
	for _,ci:= range cl.CimMap{
		if ci == cimTemp{
			return errors.New("have one CIM")
		}
		//verfiy
	}

	cl.CimMap = append(cl.CimMap, cimTemp)
	return nil
}

func (cl *CimList) DelCim(cimTemp *CIM) error  {

	 success := false
	for i,ci:= range cl.CimMap{
		if &ci == cimTemp{
			cl.CimMap = append(cl.CimMap[:i],cl.CimMap[i+1:]...)
			success = true
		}
	}

	if !success{
		return errors.New("not find CIM")
	}

	return nil
}

func (cl *CimList) VerifyCert(cert []byte) error  {

	//var err error
	errNumber :=0;
	for _,ci:= range cl.CimMap{
		err := ci.ValidateByByte(cert)
		if err != nil{
			errNumber++;
		}else{
			return nil
		}

	}
	if errNumber == len(cl.CimMap){
		return errors.New("can not find right root cert")
	}else{
		return nil
	}

}

func (cl *CimList) VerifyRootCert(cert []byte) error  {

	//var err error
	findOne :=false
	for _,ci:= range cl.CimMap{
		err := ci.ValidateRootCert(cert)
		if err != nil{
			continue
		}else{
			findOne = true
		}
	}
	if !findOne {
		return errors.New("not find this root cert")
	}
	return nil
}

func (cl *CimList) VerifyPermission(tx *types.Transaction,sender types.Signer,db state.StateDB) (bool  ,error){
	cl.lock.Lock()
	defer cl.lock.Unlock()

	if !params.IsEnablePermission() {
		return true,nil
	}

	if cl.PTable == nil{
		return false,errors.New("permission table is nil at cimlist")
	}

	from, err:= types.Sender(sender,tx)
	if err != nil{
		return false,err
	}

	// need check cert
	if err :=cl.VerifyCert(tx.Cert());err !=nil{
		return false,errors.New("VerifyPermission the cert error")
	}

	to := tx.To()
	if to == nil{
		//create contract
		//PerminType_CreateContract

		if cl.PTable.CheckActionPerm(from,common.Address{},common.Address{},vm.PerminType_CreateContract){
			return true,nil
		}else{
			return false,errors.New("check PerminType_CreateContract fail")
		}
	}else{
		toAddr := common.BytesToAddress(to.Bytes())

		// to set permisTable
		if bytes.Equal(to.Bytes(),types.PermiTableAddress.Bytes()) && len(tx.Data()) >0{
			//anaylis tx
			return true,nil
		}
		//contract
		if len(db.GetCode(toAddr))>0 && len(tx.Data()) >0{
		//contract
			if cl.PTable.CheckActionPerm(from,common.Address{},toAddr,vm.PerminType_AccessContract){
				return true,nil
			}else{
				return false,errors.New("check PerminType_AccessContract fail")
			}


		}else{
			//other transtion
			if cl.PTable.CheckActionPerm(from,common.Address{},common.Address{},vm.PerminType_SendTx){

				return true,nil
			}else{
				return false,errors.New("check PerminType_SendTx fail")
			}
		}

	}

	return true,nil
}

func (cl *CimList)UpdataCert(clist [][]byte)  {

	if len(clist) == 0{
		return
	}
	cl.CimMap = cl.CimMap[0:0]

	for _,v :=range clist{
		cimCa, _ := NewCIM()
		cimCa.SetUpFromCA(v)
		cl.AddCim(cimCa)
	}

}

func (cl *CimList)UpdataPermission(db *state.StateDB)  error {
	cl.lock.Lock()
	defer cl.lock.Unlock()

	permTable := vm.NewPerminTable()
	err := permTable.Load(db)
	if err != nil {
		return errors.New("load permiTable fail")
	}
	cl.PTable = vm.ClonePerminCaCache(permTable)

	return nil
}





type cimimpl struct {
	name string

	rootCert         Identity
	intermediateCert Identity

	tlsRootCert         []byte
	tlsIntermediateCert []byte

	opts                              *x509.VerifyOptions
	certificationTreeInternalNodesMap map[string]bool

	signer SigningIdentity

	admins []Identity
	CRL    []*pkix.CertificateList

	cryptoConfig *CryptoConfig

}

func NewCIM() (CIM, error) {

	theCIM := &cimimpl{}
	return theCIM, nil
}


func (cim *cimimpl) GetIdentifier() string {
	panic("implement me")
}



func (cim *cimimpl) SetUpFromCA(rootCAByte []byte) error {
	if len(rootCAByte) == 0 {
		return errors.New("expected at least one CA certificate")
	}

	id, err := GetIdentityFromByte(rootCAByte)
	if err != nil {
		return err
	}

	cim.rootCert = id
	return nil
}

func (cim *cimimpl) GetRootCert() Identity {
	return cim.rootCert
}

func (cim *cimimpl) GetTLSRootCert() []byte {
	return cim.tlsRootCert
}

func (cim *cimimpl) GetCrlList() []*pkix.CertificateList {
	return cim.CRL
}

func (cim *cimimpl) GetTLSIntermediateCert() []byte {
	return cim.tlsIntermediateCert
}

func (cim *cimimpl) GetSigningIdentity() SigningIdentity {
	return cim.signer
}

func (cim *cimimpl) Validate(id Identity) error {
	switch id := id.(type) {
	// If this identity is of this specific type,
	// this is how I can validate it given the
	// root of trust this MSP has
	case *identity:
		return cim.validateIdentity(id)
	default:
		return errors.New("identity type not recognized")
	}
}


func (cim *cimimpl) ValidateByByte(certByte []byte) error {
	if err :=cim.rootCert.isEqulIdentity(certByte); err!=nil {
		return cim.rootCert.VerifyByte(certByte)
	}else{
		return nil
	}
}

func (cim *cimimpl) ValidateRootCert(certByte []byte) error {
	return cim.rootCert.isEqulIdentity(certByte)
}


