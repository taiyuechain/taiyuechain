package cim

import (
	"github.com/pkg/errors"
	"reflect"
	"sync"
)

func LoadLocalCIM(dir string, cimID string) error {
	if cimID == "" {
		return errors.New("the local CIM must have an ID")
	}

	conf, err := GetLocalCmiConfig(dir, cimID)
	if err != nil {
		return err
	}

	return GetLocalCIM().SetUp(conf)
}

var m sync.Mutex
var localCIM CIM

var keyImporters map[reflect.Type]KeyImporter

// GetLocalCIM returns the local cim (and creates it if it doesn't exist)
func GetLocalCIM() CIM {
	m.Lock()
	defer m.Unlock()

	if localCIM != nil {
		return localCIM
	}

	localCIM = loadLocalCIM()

	return localCIM
}

func loadLocalCIM() CIM {

	cimInst, err := NewCIM()
	if err != nil {
		return nil
	}
	loadLocalKeyImporter()
	return cimInst
}

func loadLocalKeyImporter() {
	keyImporters = make(map[reflect.Type]KeyImporter)
	// Set the key importers

	AddWrapper(reflect.TypeOf(&ECDSAPKIXPublicKeyImportOpts{}), &ecdsaPKIXPublicKeyImportOptsKeyImporter{})
	AddWrapper(reflect.TypeOf(&ECDSAPrivateKeyImportOpts{}), &ecdsaPrivateKeyImportOptsKeyImporter{})
	AddWrapper(reflect.TypeOf(&ECDSAGoPublicKeyImportOpts{}), &ecdsaGoPublicKeyImportOptsKeyImporter{})
	AddWrapper(reflect.TypeOf(&RSAGoPublicKeyImportOpts{}), &rsaGoPublicKeyImportOptsKeyImporter{})
	AddWrapper(reflect.TypeOf(&X509PublicKeyImportOpts{}), &x509PublicKeyImportOptsKeyImporter{})
}

func AddWrapper(t reflect.Type, w interface{}) error {
	if t == nil {
		return errors.Errorf("type cannot be nil")
	}
	if w == nil {
		return errors.Errorf("wrapper cannot be nil")
	}
	switch dt := w.(type) {
	case KeyImporter:
		keyImporters[t] = dt
	default:
		return errors.Errorf("wrapper type not valid, must be on of: KeyGenerator, KeyDeriver, KeyImporter, Encryptor, Decryptor, Signer, Verifier, Hasher")
	}
	return nil
}
