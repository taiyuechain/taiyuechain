/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"fmt"
	"os"
	"path/filepath"
)

func dirExists(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fi.IsDir()
}

// GetDevConfigDir gets the path to the default configuration that is
// maintained with the source tree. This should only be used in a
// test/development context.
func GetDevConfigDir() (string, error) {
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		return "", fmt.Errorf("GOPATH not set")
	}

	for _, p := range filepath.SplitList(gopath) {
		devPath := filepath.Join(p, "src/github.com/taiyuechain/taiyuechain/cim/testdata")
		if !dirExists(devPath) {
			continue
		}

		return devPath, nil
	}

	return "", fmt.Errorf("DevConfigDir not found in %s", gopath)
}

// GetDevCIMDir gets the path to the sampleconfig/cim treethat is maintained
// with the source tree.  This should only be used in a test/development
// context.
func GetDevCIMDir() (string, error) {
	devDir, err := GetDevConfigDir()
	if err != nil {
		return "", fmt.Errorf("Error obtaining DevConfigDir: %s", devDir)
	}

	return filepath.Join(devDir, "cim"), nil
}
