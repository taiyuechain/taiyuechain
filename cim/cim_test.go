package cim

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/taiyuechain/taiyuechain/cim/config"
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	cimConfigDir, _ := config.GetDevCIMDir()
	cimID := "simpleCIM"
	err := InitCrypto(cimConfigDir, cimID)
	if err != nil {
		fmt.Printf("Setup for CMI should have succeeded, got err %s instead", err)
		os.Exit(-1)
	}
	retVal := m.Run()
	os.Exit(retVal)
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

func TestSignAndVerify(t *testing.T) {
	cim := GetLocalCIM()
	id := cim.GetSigningIdentity()

	msg := []byte("foo")
	sig, err := id.Sign(msg)
	if err != nil {
		t.Fatalf("Sign should have succeeded")
		return
	}

	err = id.Verify(msg, sig)
	if err != nil {
		t.Fatalf("The signature should be valid")
		return
	}

	err = id.Verify(msg[1:], sig)
	assert.Error(t, err)
	err = id.Verify(msg, sig[1:])
	assert.Error(t, err)
}
