// Copyright 2018 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package enode

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/p2p/enr"
	"github.com/taiyuechain/taiyuechain/rlp"
)

var (
	privkey, _ = crypto.GenerateKey()
	pubkey     = &privkey.PublicKey
)

func TestEmptyNodeID(t *testing.T) {
	var r enr.Record
	if addr := ValidSchemes.NodeAddr(&r); addr != nil {
		t.Errorf("wrong address on empty record: got %v, want %v", addr, nil)
	}

	require.NoError(t, SignV4(&r, privkey))
	fmt.Println(hex.EncodeToString(ValidSchemes.NodeAddr(&r)))
}

// Checks that failure to sign leaves the record unmodified.
func TestSignError(t *testing.T) {
	invalidKey := &ecdsa.PrivateKey{D: new(big.Int), PublicKey: *pubkey}

	var r enr.Record
	emptyEnc, _ := rlp.EncodeToBytes(&r)
	if err := SignV4(&r, invalidKey); err == nil {
		t.Fatal("expected error from SignV4")
	}
	newEnc, _ := rlp.EncodeToBytes(&r)
	if !bytes.Equal(newEnc, emptyEnc) {
		t.Fatal("record modified even though signing failed")
	}
}

// TestGetSetSecp256k1 tests encoding/decoding and setting/getting of the Secp256k1 key.
func TestGetSetSecp256k1(t *testing.T) {
	var r enr.Record
	if err := SignV4(&r, privkey); err != nil {
		t.Fatal(err)
	}

	var pk Secp256k1
	require.NoError(t, r.Load(&pk))
	assert.EqualValues(t, pubkey, &pk)
}
