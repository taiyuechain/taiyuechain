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

package params

// MainnetBootnodes are the enode URLs of the P2P bootstrap nodes running on
// the main Taiyuechain network.
var MainnetBootnodes = []string{
	"enode://fb331ff6aded86b393d9de2f9c449d313b356af0c4c0b9500e0f6c51bcb4ed31ca45dc2ab64c6182d1876eb9e3fd073d488277a40a6d357bc6e63350a2e00ffc@101.132.183.35:30313", // CN
}

// TestnetBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// Ropsten test network.
var TestnetBootnodes = []string{
	"enode://a2ca310bd77a962c1fd504db7c4caed1556882f19e901638749ce2434d0307c7a084ef31ad146e32bb4c9253a37040d92703f3170abd7bf9f66f7223cff477e1@39.99.195.63:30313",
}

// DevnetBootnodes are the enode URLs of the P2P bootstrap nodes running on
// the dev Taiyuechain network.
var DevnetBootnodes = []string{
	"enode://5f8f37510d880693e3b8f68f76c2d12fa11074bdf0f11695743af4546b374065fb1dc2ec83dc0f31e1ae7d5304102d429c664869aa7f6b2b70bda45d2a1716ee@39.98.240.34:30314",
}

var SingleNodeBootnodes = []string{}
