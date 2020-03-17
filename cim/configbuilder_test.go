/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cim

import (
	"github.com/taiyuechain/taiyuechain/cim/config"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetLocalMspConfig(t *testing.T) {
	mspDir, err := config.GetDevCIMDir()
	assert.NoError(t, err)
	_, err = GetLocalCmiConfig(mspDir, "")
	assert.NoError(t, err)
}
