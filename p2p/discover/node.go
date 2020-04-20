// Copyright 2015 The go-ethereum Authors
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

package discover

import (
	"crypto/ecdsa"
	"errors"
	"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/crypto/gm/sm2"
	"github.com/taiyuechain/taiyuechain/crypto/taiCrypto"
	"math/big"
	"net"
	"time"

	"github.com/ethereum/go-ethereum/common/math"

	"github.com/taiyuechain/taiyuechain/p2p/enode"
)

// node represents a host on the network.
// The fields of Node may not be modified.
type node struct {
	enode.Node
	addedAt        time.Time // time when the node was added to the table
	livenessChecks uint      // how often liveness was checked
}

type encPubkey [64]byte

//func encodePubkey(key *ecdsa.PublicKey) encPubkey {
func encodePubkey(key *taiCrypto.TaiPublicKey) encPubkey {
	var e encPubkey
	if taiCrypto.AsymmetricCryptoType == taiCrypto.ASYMMETRICCRYPTOECDSA {
		math.ReadBits(key.Publickey.X, e[:len(e)/2])
		math.ReadBits(key.Publickey.Y, e[len(e)/2:])
	}
	if taiCrypto.AsymmetricCryptoType == taiCrypto.ASYMMETRICCRYPTOSM2 {
		math.ReadBits(key.SmPublickey.X, e[:len(e)/2])
		math.ReadBits(key.SmPublickey.Y, e[len(e)/2:])
	}

	return e
}

//func decodePubkey(e encPubkey) (*ecdsa.PublicKey, error) {
func decodePubkey(e encPubkey) (*taiCrypto.TaiPublicKey, error) {
	var taipublic taiCrypto.TaiPublicKey
	if taiCrypto.AsymmetricCryptoType == taiCrypto.ASYMMETRICCRYPTOECDSA {
		p := &ecdsa.PublicKey{Curve: crypto.S256(), X: new(big.Int), Y: new(big.Int)}
		half := len(e) / 2
		p.X.SetBytes(e[:half])
		p.Y.SetBytes(e[half:])
		if !p.Curve.IsOnCurve(p.X, p.Y) {
			return nil, errors.New("invalid secp256k1 curve point")
		}
		taipublic.Publickey = *p
		return &taipublic, nil
	}
	if taiCrypto.AsymmetricCryptoType == taiCrypto.ASYMMETRICCRYPTOECDSA {
		p := &sm2.PublicKey{Curve: sm2.GetSm2P256V1(), X: new(big.Int), Y: new(big.Int)}
		half := len(e) / 2
		p.X.SetBytes(e[:half])
		p.Y.SetBytes(e[half:])
		if !p.Curve.IsOnCurve(p.X, p.Y) {
			return nil, errors.New("invalid secp256k1 curve point")
		}
		taipublic.SmPublickey = *p
		return &taipublic, nil
	}
	return nil, nil
}

func (e encPubkey) id() enode.ID {
	var thash taiCrypto.THash
	//return enode.ID(crypto.Keccak256Hash(e[:]))
	return enode.ID(thash.Keccak256Hash(e[:]))
}

// recoverNodeKey computes the public key used to sign the
// given hash from the signature.
func recoverNodeKey(hash, sig []byte) (key encPubkey, err error) {
	pubkey, err := crypto.Ecrecover(hash, sig)
	if err != nil {
		return key, err
	}
	copy(key[:], pubkey[1:])
	return key, nil
}

func wrapNode(n *enode.Node) *node {
	return &node{Node: *n}
}

func wrapNodes(ns []*enode.Node) []*node {
	result := make([]*node, len(ns))
	for i, n := range ns {
		result[i] = wrapNode(n)
	}
	return result
}

func unwrapNode(n *node) *enode.Node {
	return &n.Node
}

func unwrapNodes(ns []*node) []*enode.Node {
	result := make([]*enode.Node, len(ns))
	for i, n := range ns {
		result[i] = unwrapNode(n)
	}
	return result
}

func (n *node) addr() *net.UDPAddr {
	return &net.UDPAddr{IP: n.IP(), Port: n.UDP()}
}

func (n *node) String() string {
	return n.Node.String()
}
