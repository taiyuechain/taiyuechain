package customtls

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/taiyuechain/taiyuechain/p2p/gmsm/sm2"
	"github.com/taiyuechain/taiyuechain/p2p/tls"
)

var ecdsaKeyPEM = testingKey(`-----BEGIN EC PARAMETERS-----
BggqgRzPVQGCLQ==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIK3zGWdwkmUsPnW3rU5v8nBJ9aqoo35TQPKKHTostrt0oAoGCCqBHM9V
AYItoUQDQgAEqFbv2lUUC3jMJEWhrB+MMigUaAt01AA3KDSH99XwdQR0x15XmmTL
k8boRxNw/OccN0qLvEGjusYlgi/AO8eyCg==
-----END EC PRIVATE KEY-----
`)

// var ecdsaKeyPEM = testingKey(`-----BEGIN EC PARAMETERS-----
// BggqgRzPVQGCLQ==
// -----END EC PARAMETERS-----
// -----BEGIN EC TESTING KEY-----
// MHcCAQEEIK3zGWdwkmUsPnW3rU5v8nBJ9aqoo35TQPKKHTostrt0oAoGCCqBHM9V
// AYItoUQDQgAEqFbv2lUUC3jMJEWhrB+MMigUaAt01AA3KDSH99XwdQR0x15XmmTL
// k8boRxNw/OccN0qLvEGjusYlgi/AO8eyCg==
// -----END EC TESTING KEY-----
// `)

// ToECDSAPublickey convert gm publickey to ecdsa publickey.
func ToECDSAPublickey(key *sm2.PublicKey) *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: key.Curve,
		X:     key.X,
		Y:     key.Y,
	}
}

// ToEcdsaPrivate convert gm privatekey to ecdsa privatekey.
func ToEcdsaPrivate(key *sm2.PrivateKey) *ecdsa.PrivateKey {
	return &ecdsa.PrivateKey{
		D:         key.D,
		PublicKey: *ToECDSAPublickey(&key.PublicKey),
	}
}
func loadPrivateKeyFile(keyFile string) (crypto.PrivateKey, error) {
	// load P2PPrivateKey from pem file
	if len(keyFile) > 0 {
		privKey, err := ParsePrivateKeyFile(keyFile)
		if err != nil {
			gmprivKey, err := sm2.ReadPrivateKeyFromPem(keyFile, nil)
			if err != nil {

				fmt.Println("setNodeKey failed,the wrong P2PPrivateKeyFile", err)
				return nil, err
			}
			newPrivKey := ToEcdsaPrivate(gmprivKey)
			return newPrivKey, nil
		}
		return privKey, nil

	}
	return nil, fmt.Errorf("nil key file")
}

func loadPrivateKeyMem(keyPEMBlock []byte, t *testing.T) (crypto.PrivateKey, error) {
	// load P2PPrivateKey from pem file
	var keyDERBlock *pem.Block
	backupBlock := keyPEMBlock
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)

		if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			break
		}
	}
	privKey, err := parsePrivateKey(keyDERBlock.Bytes)
	if err != nil {
		// data, err := ioutil.ReadFile("./newNormalCert/CA11.key")
		// t.Log(string(data))
		// if err != nil {
		// 	return nil, err
		// }
		gmprivKey, err := sm2.ReadPrivateKeyFromMem([]byte(backupBlock), nil)
		if err != nil {

			fmt.Println("setNodeKey failed,the wrong P2PPrivateKeyFile", err)
			return nil, err
		}
		newPrivKey := ToEcdsaPrivate(gmprivKey)
		return newPrivKey, nil
	}
	return privKey, nil

}

func testingKey(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }

func TestLoadPrivateKey(t *testing.T) {
	if _, err := loadPrivateKeyFile("./newNormalCert/CA1.key"); err != nil {
		t.Errorf("Failed to load private key from file: %v", err)
	}
}

func TestLodaPrivateKeyMem(t *testing.T) {
	if _, err := loadPrivateKeyMem([]byte(ecdsaKeyPEM), t); err != nil {
		t.Errorf("Failed to load private key string: %v", err)
	}
}

func TestLoadCertFile(t *testing.T) {
	if _, err := CustomX509Cert("./newNormalCert/CA1.pem"); err != nil {
		t.Errorf("Failed to load cert from pem file")
	}
}

func TestTLSServer(t *testing.T) {
	certFilePath := "./newNormalCert/CA2.pem"
	keyFilePath := "./newNormalCert/CA2.key"
	cert, err := CustomX509Cert(certFilePath)
	if err != nil {
		t.Errorf("Failed to load cert from pem file: %v", err)
	}
	var privKey crypto.PrivateKey
	if privKey, err = loadPrivateKeyFile(keyFilePath); err != nil {
		t.Errorf("Failed to load private key from file: %v", err)
	}
	cert.PrivateKey = privKey
	// set tls listener config
	conf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequestClientCert,
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS12,
		// ClientCAs:    clientCertPool,
	}
	conf.VerifyPeerCertificate = func(certificates [][]byte, _ [][]*x509.Certificate) error {
		// verify peer certificate
		// if err := srv.localnode.CM.List.VerifyCert(certificates[0]); err != nil {
		// 	fmt.Println("verifyPeerCert failed", err)
		// 	return err
		// }
		return nil

	}
	// Launch the tls listener
	ln, err := tls.Listen("tcp", ":30333", conf)
	if err != nil {
		t.Log(err)
		return
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			t.Log(err)
			continue
		}
		go handleConn(conn, t)
	}
}

func handleConn(conn net.Conn, t *testing.T) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		msg, err := r.ReadString('\n')
		if err != nil {
			t.Log(err)
			return
		}
		t.Log(msg)
		n, err := conn.Write([]byte("world\n"))
		if err != nil {
			t.Log(n, err)
			return
		}
	}
}

func TestTLSClient(t *testing.T) {
	certFilePath := "./newNormalCert/CA1.pem"
	keyFilePath := "./newNormalCert/CA1.key"
	cert, err := CustomX509Cert(certFilePath)
	if err != nil {
		t.Errorf("Failed to load cert from pem file: %v", err)
	}
	var privKey crypto.PrivateKey
	if privKey, err = loadPrivateKeyFile(keyFilePath); err != nil {
		t.Errorf("Failed to load private key from file: %v", err)
	}
	cert.PrivateKey = privKey
	conf := &tls.Config{
		// RootCAs:      serverCertPool,
		Certificates: []tls.Certificate{cert},
		// Certificates: []tls.Certificate{},
		// InsecureSkipVerify controls whether a client verifies the
		// server's certificate chain and host name.
		InsecureSkipVerify: true,
		// CipherSuites:       []uint16{45159, 45169, 49187, 49191},
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS12,
	}
	conf.VerifyPeerCertificate = func(certificates [][]byte, _ [][]*x509.Certificate) error {
		fmt.Println("client verifypeercertificate")
		fmt.Println("certificates", certificates)
		return nil

	}

	conn, err := tls.Dial("tcp", "192.168.184.129:30333", conf)
	if err != nil {
		t.Log(err)
		return
	} else {
		t.Log("finish dial")
	}
	defer conn.Close()

	n, err := conn.Write([]byte("hello\n"))
	if err != nil {
		t.Log("client write error", n, err)
		return
	}

	buf := make([]byte, 100)
	n, err = conn.Read(buf)
	if err != nil {
		t.Log("client write error", n, err)
		return
	}
	t.Log(string(buf[:n]))
}
