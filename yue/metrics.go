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

package yue

import (
	"github.com/taiyuechain/taiyuechain/metrics"
	"github.com/taiyuechain/taiyuechain/p2p"
)

var (
	propTxnInPacketsMeter     = metrics.NewRegisteredMeter("yue/prop/txns/in/packets", nil)
	propTxnInTrafficMeter     = metrics.NewRegisteredMeter("yue/prop/txns/in/traffic", nil)
	propTxnOutPacketsMeter    = metrics.NewRegisteredMeter("yue/prop/txns/out/packets", nil)
	propTxnOutTrafficMeter    = metrics.NewRegisteredMeter("yue/prop/txns/out/traffic", nil)
	propFtnInPacketsMeter     = metrics.NewRegisteredMeter("yue/prop/ftns/in/packets", nil)
	propFtnInTrafficMeter     = metrics.NewRegisteredMeter("yue/prop/ftns/in/traffic", nil)
	propFtnOutPacketsMeter    = metrics.NewRegisteredMeter("yue/prop/ftns/out/packets", nil)
	propFtnOutTrafficMeter    = metrics.NewRegisteredMeter("yue/prop/ftns/out/traffic", nil)
	propFHashInPacketsMeter   = metrics.NewRegisteredMeter("yue/prop/fhashes/in/packets", nil)
	propFHashInTrafficMeter   = metrics.NewRegisteredMeter("yue/prop/fhashes/in/traffic", nil)
	propFHashOutPacketsMeter  = metrics.NewRegisteredMeter("yue/prop/fhashes/out/packets", nil)
	propFHashOutTrafficMeter  = metrics.NewRegisteredMeter("yue/prop/fhashes/out/traffic", nil)
	propSHashInPacketsMeter   = metrics.NewRegisteredMeter("yue/prop/shashes/in/packets", nil)
	propSHashInTrafficMeter   = metrics.NewRegisteredMeter("yue/prop/shashes/in/traffic", nil)
	propSHashOutPacketsMeter  = metrics.NewRegisteredMeter("yue/prop/shashes/out/packets", nil)
	propSHashOutTrafficMeter  = metrics.NewRegisteredMeter("yue/prop/shashes/out/traffic", nil)
	propFBlockInPacketsMeter  = metrics.NewRegisteredMeter("yue/prop/fblocks/in/packets", nil)
	propFBlockInTrafficMeter  = metrics.NewRegisteredMeter("yue/prop/fblocks/in/traffic", nil)
	propFBlockOutPacketsMeter = metrics.NewRegisteredMeter("yue/prop/fblocks/out/packets", nil)
	propFBlockOutTrafficMeter = metrics.NewRegisteredMeter("yue/prop/fblocks/out/traffic", nil)
	propSBlockInPacketsMeter  = metrics.NewRegisteredMeter("yue/prop/sblocks/in/packets", nil)
	propSBlockInTrafficMeter  = metrics.NewRegisteredMeter("yue/prop/sblocks/in/traffic", nil)
	propSBlockOutPacketsMeter = metrics.NewRegisteredMeter("yue/prop/sblocks/out/packets", nil)
	propSBlockOutTrafficMeter = metrics.NewRegisteredMeter("yue/prop/sblocks/out/traffic", nil)

	propNodeInfoInPacketsMeter  = metrics.NewRegisteredMeter("yue/prop/nodeinfo/in/packets", nil)
	propNodeInfoInTrafficMeter  = metrics.NewRegisteredMeter("yue/prop/nodeinfo/in/traffic", nil)
	propNodeInfoOutPacketsMeter = metrics.NewRegisteredMeter("yue/prop/nodeinfo/out/packets", nil)
	propNodeInfoOutTrafficMeter = metrics.NewRegisteredMeter("yue/prop/nodeinfo/out/traffic", nil)

	propNodeInfoHashInPacketsMeter  = metrics.NewRegisteredMeter("yue/prop/nodeinfohash/in/packets", nil)
	propNodeInfoHashInTrafficMeter  = metrics.NewRegisteredMeter("yue/prop/nodeinfohash/in/traffic", nil)
	propNodeInfoHashOutPacketsMeter = metrics.NewRegisteredMeter("yue/prop/nodeinfohash/out/packets", nil)
	propNodeInfoHashOutTrafficMeter = metrics.NewRegisteredMeter("yue/prop/nodeinfohash/out/traffic", nil)

	reqFHeaderInPacketsMeter  = metrics.NewRegisteredMeter("yue/req/headers/in/packets", nil)
	reqFHeaderInTrafficMeter  = metrics.NewRegisteredMeter("yue/req/headers/in/traffic", nil)
	reqFHeaderOutPacketsMeter = metrics.NewRegisteredMeter("yue/req/headers/out/packets", nil)
	reqFHeaderOutTrafficMeter = metrics.NewRegisteredMeter("yue/req/headers/out/traffic", nil)
	reqSHeaderInPacketsMeter  = metrics.NewRegisteredMeter("yue/req/sheaders/in/packets", nil)
	reqSHeaderInTrafficMeter  = metrics.NewRegisteredMeter("yue/req/sheaders/in/traffic", nil)
	reqSHeaderOutPacketsMeter = metrics.NewRegisteredMeter("yue/req/sheaders/out/packets", nil)
	reqSHeaderOutTrafficMeter = metrics.NewRegisteredMeter("yue/req/sheaders/out/traffic", nil)

	reqFBodyInPacketsMeter  = metrics.NewRegisteredMeter("yue/req/fbodies/in/packets", nil)
	reqFBodyInTrafficMeter  = metrics.NewRegisteredMeter("yue/req/fbodies/in/traffic", nil)
	reqFBodyOutPacketsMeter = metrics.NewRegisteredMeter("yue/req/fbodies/out/packets", nil)
	reqFBodyOutTrafficMeter = metrics.NewRegisteredMeter("yue/req/fbodies/out/traffic", nil)
	reqSBodyInPacketsMeter  = metrics.NewRegisteredMeter("yue/req/sbodies/in/packets", nil)
	reqSBodyInTrafficMeter  = metrics.NewRegisteredMeter("yue/req/sbodies/in/traffic", nil)
	reqSBodyOutPacketsMeter = metrics.NewRegisteredMeter("yue/req/sbodies/out/packets", nil)
	reqSBodyOutTrafficMeter = metrics.NewRegisteredMeter("yue/req/sbodies/out/traffic", nil)

	reqStateInPacketsMeter    = metrics.NewRegisteredMeter("yue/req/states/in/packets", nil)
	reqStateInTrafficMeter    = metrics.NewRegisteredMeter("yue/req/states/in/traffic", nil)
	reqStateOutPacketsMeter   = metrics.NewRegisteredMeter("yue/req/states/out/packets", nil)
	reqStateOutTrafficMeter   = metrics.NewRegisteredMeter("yue/req/states/out/traffic", nil)
	reqReceiptInPacketsMeter  = metrics.NewRegisteredMeter("yue/req/receipts/in/packets", nil)
	reqReceiptInTrafficMeter  = metrics.NewRegisteredMeter("yue/req/receipts/in/traffic", nil)
	reqReceiptOutPacketsMeter = metrics.NewRegisteredMeter("yue/req/receipts/out/packets", nil)
	reqReceiptOutTrafficMeter = metrics.NewRegisteredMeter("yue/req/receipts/out/traffic", nil)

	getHeadInPacketsMeter  = metrics.NewRegisteredMeter("yue/get/head/in/packets", nil)
	getHeadInTrafficMeter  = metrics.NewRegisteredMeter("yue/get/head/in/traffic", nil)
	getHeadOutPacketsMeter = metrics.NewRegisteredMeter("yue/get/head/out/packets", nil)
	getHeadOutTrafficMeter = metrics.NewRegisteredMeter("yue/get/head/out/traffic", nil)
	getBodyInPacketsMeter  = metrics.NewRegisteredMeter("yue/get/bodies/in/packets", nil)
	getBodyInTrafficMeter  = metrics.NewRegisteredMeter("yue/get/bodies/in/traffic", nil)
	getBodyOutPacketsMeter = metrics.NewRegisteredMeter("yue/get/bodies/out/packets", nil)
	getBodyOutTrafficMeter = metrics.NewRegisteredMeter("yue/get/bodies/out/traffic", nil)

	getNodeInfoInPacketsMeter  = metrics.NewRegisteredMeter("yue/get/nodeinfo/in/packets", nil)
	getNodeInfoInTrafficMeter  = metrics.NewRegisteredMeter("yue/get/nodeinfo/in/traffic", nil)
	getNodeInfoOutPacketsMeter = metrics.NewRegisteredMeter("yue/get/nodeinfo/out/packets", nil)
	getNodeInfoOutTrafficMeter = metrics.NewRegisteredMeter("yue/get/nodeinfo/out/traffic", nil)

	miscInPacketsMeter  = metrics.NewRegisteredMeter("yue/misc/in/packets", nil)
	miscInTrafficMeter  = metrics.NewRegisteredMeter("yue/misc/in/traffic", nil)
	miscOutPacketsMeter = metrics.NewRegisteredMeter("yue/misc/out/packets", nil)
	miscOutTrafficMeter = metrics.NewRegisteredMeter("yue/misc/out/traffic", nil)
)

// meteredMsgReadWriter is a wrapper around a p2p.MsgReadWriter, capable of
// accumulating the above defined metrics based on the data stream contents.
type meteredMsgReadWriter struct {
	p2p.MsgReadWriter     // Wrapped message stream to meter
	version           int // Protocol version to select correct meters
}

// newMeteredMsgWriter wraps a p2p MsgReadWriter with metering support. If the
// metrics system is disabled, this function returns the original object.
func newMeteredMsgWriter(rw p2p.MsgReadWriter) p2p.MsgReadWriter {
	if !metrics.Enabled {
		return rw
	}
	return &meteredMsgReadWriter{MsgReadWriter: rw}
}

// Init sets the protocol version used by the stream to know which meters to
// increment in case of overlapping message ids between protocol versions.
func (rw *meteredMsgReadWriter) Init(version int) {
	rw.version = version
}

func (rw *meteredMsgReadWriter) ReadMsg() (p2p.Msg, error) {
	// Read the message and short circuit in case of an error
	msg, err := rw.MsgReadWriter.ReadMsg()
	if err != nil {
		return msg, err
	}
	// Account for the data traffic
	packets, traffic := miscInPacketsMeter, miscInTrafficMeter
	switch {
	case msg.Code == NodeDataMsg:
		packets, traffic = reqStateInPacketsMeter, reqStateInTrafficMeter
	case msg.Code == ReceiptsMsg:
		packets, traffic = reqReceiptInPacketsMeter, reqReceiptInTrafficMeter

	case msg.Code == TransactionMsg:
		packets, traffic = propTxnInPacketsMeter, propTxnInTrafficMeter
	case msg.Code == TbftNodeInfoMsg:
		packets, traffic = propNodeInfoInPacketsMeter, propNodeInfoInTrafficMeter
	case msg.Code == TbftNodeInfoHashMsg:
		packets, traffic = propNodeInfoHashInPacketsMeter, propNodeInfoHashInTrafficMeter
	case msg.Code == GetTbftNodeInfoMsg:
		packets, traffic = getNodeInfoInPacketsMeter, getNodeInfoInTrafficMeter
	}
	packets.Mark(1)
	traffic.Mark(int64(msg.Size))

	return msg, err
}

func (rw *meteredMsgReadWriter) WriteMsg(msg p2p.Msg) error {
	// Account for the data traffic
	packets, traffic := miscOutPacketsMeter, miscOutTrafficMeter
	switch {
	case msg.Code == NodeDataMsg:
		packets, traffic = reqStateOutPacketsMeter, reqStateOutTrafficMeter
	case msg.Code == ReceiptsMsg:
		packets, traffic = reqReceiptOutPacketsMeter, reqReceiptOutTrafficMeter

	case msg.Code == TransactionMsg:
		packets, traffic = propTxnOutPacketsMeter, propTxnOutTrafficMeter
	case msg.Code == TbftNodeInfoMsg:
		packets, traffic = propNodeInfoOutPacketsMeter, propNodeInfoOutTrafficMeter
	case msg.Code == TbftNodeInfoHashMsg:
		packets, traffic = propNodeInfoHashOutPacketsMeter, propNodeInfoHashOutTrafficMeter
	case msg.Code == GetTbftNodeInfoMsg:
		packets, traffic = getNodeInfoOutPacketsMeter, getNodeInfoOutTrafficMeter
	}
	packets.Mark(1)
	traffic.Mark(int64(msg.Size))

	// Send the packet to the p2p layer
	return rw.MsgReadWriter.WriteMsg(msg)
}
