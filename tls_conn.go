package conn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"golang_org/x/crypto/ed25519"
	"math/big"
	"time"

	proto "github.com/gogo/protobuf/proto"
	ic "github.com/libp2p/go-libp2p-crypto"
	pb "github.com/libp2p/go-libp2p-crypto/pb"
	iconn "github.com/libp2p/go-libp2p-interface-conn"
	peer "github.com/libp2p/go-libp2p-peer"
	tpt "github.com/libp2p/go-libp2p-transport"
	ma "github.com/multiformats/go-multiaddr"
)

// tlsConn wraps a Conn object in a TLS encrypted channel.
type tlsConn struct {
	*tls.Conn
	in     iconn.Conn
	client bool
	sk     ic.PrivKey
	peer   ic.PubKey
}

func (c *tlsConn) Loggable() map[string]interface{} {
	m := make(map[string]interface{})
	m["localPeer"] = c.LocalPeer().Pretty()
	m["remotePeer"] = c.RemotePeer().Pretty()
	m["client"] = c.client
	return m
}

func newTLSConn(ctx context.Context, sk ic.PrivKey, insecure iconn.Conn, client bool) (iconn.Conn, error) {
	if insecure == nil {
		return nil, errors.New("insecure is nil")
	}
	if insecure.LocalPeer() == "" {
		return nil, errors.New("insecure.LocalPeer() is nil")
	}
	if sk == nil {
		return nil, errors.New("private key is nil")
	}
	if !insecure.LocalPeer().MatchesPrivateKey(sk) {
		return nil, errors.New("insecure.LocalPeer() doesn't match the private key")
	}

	conn := &tlsConn{
		in:     insecure,
		client: client,
		sk:     sk,
	}
	defer log.EventBegin(ctx, "tlsHandshake", conn).Done()

	cert, err := keyToCertificate(sk)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAnyClientCert,
		Certificates:       []tls.Certificate{*cert},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
		SessionTicketsDisabled: true,
		MinVersion:             tls.VersionTLS12,
		// MinVersion:             tls.VersionTLS13,
		// MaxVersion:             tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.CurveP256, tls.X25519},
	}
	if client {
		conn.Conn = tls.Client(insecure, config)
	} else {
		conn.Conn = tls.Server(insecure, config)
	}

	handshakeResult := make(chan error, 1)
	go func() {
		handshakeResult <- conn.Handshake()
	}()
	select {
	case <-ctx.Done():
		insecure.Close()
		return nil, ctx.Err()
	case err = <-handshakeResult:
		if err != nil {
			return nil, err
		}
	}

	if len(conn.ConnectionState().PeerCertificates) < 1 {
		return nil, errors.New("no certificate")
	}
	rpk, err := certificateToKey(conn.ConnectionState().PeerCertificates[0])
	if err != nil {
		return nil, err
	}
	conn.peer = rpk

	return conn, nil
}

// ID is an identifier unique to this connection.
func (c *tlsConn) ID() string {
	return iconn.ID(c)
}

func (c *tlsConn) String() string {
	return iconn.String(c, "tlsConn")
}

// LocalMultiaddr is the Multiaddr on this side.
func (c *tlsConn) LocalMultiaddr() ma.Multiaddr {
	return c.in.LocalMultiaddr()
}

// RemoteMultiaddr is the Multiaddr on the remote side.
func (c *tlsConn) RemoteMultiaddr() ma.Multiaddr {
	return c.in.RemoteMultiaddr()
}

// LocalPeer is the Peer on this side.
func (c *tlsConn) LocalPeer() peer.ID {
	return c.in.LocalPeer()
}

// RemotePeer is the Peer on the remote side.
func (c *tlsConn) RemotePeer() peer.ID {
	id, _ := peer.IDFromPublicKey(c.RemotePublicKey())
	return id
}

// LocalPrivateKey is the public key of the peer on this side.
func (c *tlsConn) LocalPrivateKey() ic.PrivKey {
	return c.sk
}

// RemotePubKey is the public key of the peer on the remote side.
func (c *tlsConn) RemotePublicKey() ic.PubKey {
	return c.peer
}

func (c *tlsConn) Transport() tpt.Transport {
	return c.in.Transport()
}

func keyToCertificate(sk ic.PrivKey) (*tls.Certificate, error) {
	tmpl := &x509.Certificate{}
	tmpl.NotAfter = time.Now().Add(24 * time.Hour)
	tmpl.NotBefore = time.Now().Add(-24 * time.Hour)
	tmpl.SerialNumber, _ = rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
	p, _ := peer.IDFromPrivateKey(sk)
	tmpl.Subject.CommonName = p.Pretty()

	var publicKey, privateKey interface{}
	keyBytes, err := sk.Bytes()
	if err != nil {
		return nil, err
	}
	pbmes := new(pb.PrivateKey)
	if err := proto.Unmarshal(keyBytes, pbmes); err != nil {
		return nil, err
	}
	switch pbmes.GetType() {
	case pb.KeyType_RSA:
		tmpl.SignatureAlgorithm = x509.SHA256WithRSA
		k, err := x509.ParsePKCS1PrivateKey(pbmes.GetData())
		if err != nil {
			return nil, err
		}
		publicKey = &k.PublicKey
		privateKey = k
	case pb.KeyType_Ed25519:
		tmpl.SignatureAlgorithm = x509.PureEd25519
		privateKey = ed25519.PrivateKey(pbmes.GetData()[:ed25519.PrivateKeySize])
		publicKey = ed25519.PublicKey(pbmes.GetData()[ed25519.PrivateKeySize:])
	default:
		return nil, errors.New("unsupported key type for TLS")
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{cert},
		PrivateKey:  privateKey,
	}, nil
}

func certificateToKey(cert *x509.Certificate) (ic.PubKey, error) {
	switch pk := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		der, err := x509.MarshalPKIXPublicKey(pk)
		if err != nil {
			return nil, err
		}
		k, err := ic.UnmarshalRsaPublicKey(der)
		if err != nil {
			return nil, err
		}
		return k, nil
	case ed25519.PublicKey:
		k, err := ic.UnmarshalEd25519PublicKey(pk)
		if err != nil {
			return nil, err
		}
		return k, nil
	default:
		return nil, errors.New("unsupported certificate key type")
	}
}
