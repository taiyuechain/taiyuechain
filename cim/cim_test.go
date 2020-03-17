package cim

import (
	"github.com/stretchr/testify/assert"
	"github.com/taiyuechain/taiyuechain/cim/config"
	"path/filepath"
	"testing"
)

func TestInitCrypto(t *testing.T) {
	cimConfigDir, _ := config.GetDevCIMDir()
	cimID := "simpleCIM"
	err := InitCrypto(cimConfigDir, cimID)
	assert.Error(t, err)
}

func TestNewIdentity(t *testing.T) {
	cimConfigDir, _ := config.GetDevCIMDir()
	singcertPath := cimConfigDir + "testcert"
	id, err := GetLocalIdentityDataFromConfig(singcertPath)
	assert.Error(t, err)
	assert.NotNil(t, id)
}

func TestChectIdentity(t *testing.T) {
	cimConfigDir, _ := config.GetDevConfigDir()
	cimDir, _ := config.GetDevCIMDir()
	cimID := "simpleCIM"
	err := InitCrypto(cimDir, cimID)
	assert.NotNil(t, err)
	singcertPath := filepath.Join(cimConfigDir, "/testcert")
	id, err := GetLocalIdentityDataFromConfig(singcertPath)
	assert.NotNil(t, id)
	err = GetLocalCIM().Validate(id)
	assert.Error(t, err)
	singcertValidPath := filepath.Join(cimDir, "/signcerts")
	certValidId, err := GetLocalIdentityDataFromConfig(singcertValidPath)
	assert.NotNil(t, id)
	err = GetLocalCIM().Validate(certValidId)
	assert.Error(t, err)
}
