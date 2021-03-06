// Code generated by github.com/fjl/gencodec. DO NOT EDIT.

package p2p

import (
	"crypto/ecdsa"

	"github.com/taiyuechain/taiyuechain/common/hexutil"
	"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/log"
	"github.com/taiyuechain/taiyuechain/p2p/discv5"
	"github.com/taiyuechain/taiyuechain/p2p/enode"
	"github.com/taiyuechain/taiyuechain/p2p/nat"
	"github.com/taiyuechain/taiyuechain/p2p/netutil"
)

var _ = (*configMarshaling)(nil)

// MarshalTOML marshals as TOML.
func (c Config) MarshalTOML() (interface{}, error) {
	type Config struct {
		PrivateKey        *ecdsa.PrivateKey `toml:"-"`
		P2PNodeCert       hexutil.Bytes     `toml:"-"`
		P2PKey            hexutil.Bytes
		P2PNodeCertFile   string
		P2PPrivateKeyFile string
		BootstrapNodesStr    []string
		P2PPrivateKey     crypto.PrivateKey `toml:"-"`
		MaxPeers          int
		MaxPendingPeers   int `toml:",omitempty"`
		DialRatio         int `toml:",omitempty"`
		NoDiscovery       bool
		DiscoveryV5       bool   `toml:",omitempty"`
		Name              string `toml:"-"`
		BootstrapNodes    []*enode.Node
		BootstrapNodesV5  []*discv5.Node `toml:",omitempty"`
		StaticNodes       []*enode.Node
		TrustedNodes      []*enode.Node
		NetRestrict       *netutil.Netlist `toml:",omitempty"`
		NodeDatabase      string           `toml:",omitempty"`
		Protocols         []Protocol       `toml:"-"`
		ListenAddr        string
		NAT               nat.Interface `toml:",omitempty"`
		Dialer            NodeDialer    `toml:"-"`
		NoDial            bool          `toml:",omitempty"`
		EnableMsgEvents   bool
		Logger            log.Logger `toml:",omitempty"`
		Host              string     `toml:",omitempty"`
	}
	var enc Config
	enc.PrivateKey = c.PrivateKey
	enc.P2PNodeCert = c.P2PNodeCert
	enc.P2PKey = c.P2PKey
	enc.P2PNodeCertFile = c.P2PNodeCertFile
	enc.P2PPrivateKey = c.P2PPrivateKey
	enc.P2PPrivateKeyFile = c.P2PPrivateKeyFile
	enc.BootstrapNodesStr = c.BootstrapNodesStr
	enc.MaxPeers = c.MaxPeers
	enc.MaxPendingPeers = c.MaxPendingPeers
	enc.DialRatio = c.DialRatio
	enc.NoDiscovery = c.NoDiscovery
	enc.DiscoveryV5 = c.DiscoveryV5
	enc.Name = c.Name
	enc.BootstrapNodes = c.BootstrapNodes
	enc.BootstrapNodesV5 = c.BootstrapNodesV5
	enc.StaticNodes = c.StaticNodes
	enc.TrustedNodes = c.TrustedNodes
	enc.NetRestrict = c.NetRestrict
	enc.NodeDatabase = c.NodeDatabase
	enc.Protocols = c.Protocols
	enc.ListenAddr = c.ListenAddr
	enc.NAT = c.NAT
	enc.Dialer = c.Dialer
	enc.NoDial = c.NoDial
	enc.EnableMsgEvents = c.EnableMsgEvents
	enc.Logger = c.Logger
	enc.Host = c.Host
	return &enc, nil
}

// UnmarshalTOML unmarshals from TOML.
func (c *Config) UnmarshalTOML(unmarshal func(interface{}) error) error {
	type Config struct {
		PrivateKey        *ecdsa.PrivateKey `toml:"-"`
		P2PNodeCert       *hexutil.Bytes    `toml:"-"`
		P2PKey            *hexutil.Bytes
		P2PNodeCertFile   *string
		P2PPrivateKeyFile *string
		BootstrapNodesStr    []string
		P2PPrivateKey     crypto.PrivateKey `toml:"-"`
		MaxPeers          *int
		MaxPendingPeers   *int `toml:",omitempty"`
		DialRatio         *int `toml:",omitempty"`
		NoDiscovery       *bool
		DiscoveryV5       *bool   `toml:",omitempty"`
		Name              *string `toml:"-"`
		BootstrapNodes    []*enode.Node
		BootstrapNodesV5  []*discv5.Node `toml:",omitempty"`
		StaticNodes       []*enode.Node
		TrustedNodes      []*enode.Node
		NetRestrict       *netutil.Netlist `toml:",omitempty"`
		NodeDatabase      *string          `toml:",omitempty"`
		Protocols         []Protocol       `toml:"-"`
		ListenAddr        *string
		NAT               nat.Interface `toml:",omitempty"`
		Dialer            NodeDialer    `toml:"-"`
		NoDial            *bool         `toml:",omitempty"`
		EnableMsgEvents   *bool
		Logger            log.Logger `toml:",omitempty"`
		Host              *string    `toml:",omitempty"`
	}
	var dec Config
	if err := unmarshal(&dec); err != nil {
		return err
	}
	if dec.PrivateKey != nil {
		c.PrivateKey = dec.PrivateKey
	}
	if dec.P2PNodeCert != nil {
		c.P2PNodeCert = *dec.P2PNodeCert
	}
	if dec.P2PNodeCertFile != nil {
		c.P2PNodeCertFile = *dec.P2PNodeCertFile
	}
	if dec.P2PKey != nil {
		c.P2PKey = *dec.P2PKey
	}
	if dec.P2PPrivateKey != nil {
		c.P2PPrivateKey = dec.P2PPrivateKey
	}
	if dec.P2PPrivateKeyFile != nil {
		c.P2PPrivateKeyFile = *dec.P2PPrivateKeyFile
	}
	if dec.BootstrapNodesStr != nil {
		c.BootstrapNodesStr = dec.BootstrapNodesStr
	}
	if dec.MaxPeers != nil {
		c.MaxPeers = *dec.MaxPeers
	}
	if dec.MaxPendingPeers != nil {
		c.MaxPendingPeers = *dec.MaxPendingPeers
	}
	if dec.DialRatio != nil {
		c.DialRatio = *dec.DialRatio
	}
	if dec.NoDiscovery != nil {
		c.NoDiscovery = *dec.NoDiscovery
	}
	if dec.DiscoveryV5 != nil {
		c.DiscoveryV5 = *dec.DiscoveryV5
	}
	if dec.Name != nil {
		c.Name = *dec.Name
	}
	if dec.BootstrapNodes != nil {
		c.BootstrapNodes = dec.BootstrapNodes
	}
	if dec.BootstrapNodesV5 != nil {
		c.BootstrapNodesV5 = dec.BootstrapNodesV5
	}
	if dec.StaticNodes != nil {
		c.StaticNodes = dec.StaticNodes
	}
	if dec.TrustedNodes != nil {
		c.TrustedNodes = dec.TrustedNodes
	}
	if dec.NetRestrict != nil {
		c.NetRestrict = dec.NetRestrict
	}
	if dec.NodeDatabase != nil {
		c.NodeDatabase = *dec.NodeDatabase
	}
	if dec.Protocols != nil {
		c.Protocols = dec.Protocols
	}
	if dec.ListenAddr != nil {
		c.ListenAddr = *dec.ListenAddr
	}
	if dec.NAT != nil {
		c.NAT = dec.NAT
	}
	if dec.Dialer != nil {
		c.Dialer = dec.Dialer
	}
	if dec.NoDial != nil {
		c.NoDial = *dec.NoDial
	}
	if dec.EnableMsgEvents != nil {
		c.EnableMsgEvents = *dec.EnableMsgEvents
	}
	if dec.Logger != nil {
		c.Logger = dec.Logger
	}
	if dec.Host != nil {
		c.Host = *dec.Host
	}
	return nil
}
