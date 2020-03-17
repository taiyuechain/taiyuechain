package cim

import (
	"github.com/pkg/errors"
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

// GetLocalCIM returns the local cim (and creates it if it doesn't exist)
func GetLocalCIM() CIM {
	m.Lock()
	defer m.Unlock()

	if localCIM != nil {
		return localCIM
	}

	localCIM = loadLocaCIM()

	return localCIM
}

func loadLocaCIM() CIM {

	mspInst, err := NewCIM()
	if err != nil {
		return nil
	}

	return mspInst
}
