package conn

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	addrutil "github.com/libp2p/go-addr-util"
	ci "github.com/libp2p/go-libp2p-crypto"
	iconn "github.com/libp2p/go-libp2p-interface-conn"
	ipnet "github.com/libp2p/go-libp2p-interface-pnet"
	lgbl "github.com/libp2p/go-libp2p-loggables"
	peer "github.com/libp2p/go-libp2p-peer"
	transport "github.com/libp2p/go-libp2p-transport"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr-net"
	msmux "github.com/multiformats/go-multistream"
)

// DialTimeout is the maximum duration a Dial is allowed to take.
// This includes the time between dialing the raw network connection,
// protocol selection as well the handshake, if applicable.
var DialTimeout = 60 * time.Second

type WrapFunc func(transport.Conn) transport.Conn

// Dialer is an object that can open connections. We could have a "convenience"
// Dial function as before, but it would have many arguments, as dialing is
// no longer simple (need a peerstore, a local peer, a context, a network, etc)
type Dialer struct {
	// LocalPeer is the identity of the local Peer.
	LocalPeer peer.ID

	// LocalAddrs is a set of local addresses to use.
	//LocalAddrs []ma.Multiaddr

	// Dialers are the sub-dialers usable by this dialer
	// selected in order based on the address being dialed
	Dialers []transport.Dialer

	// PrivateKey used to initialize a secure connection.
	// Warning: if PrivateKey is nil, connection will not be secured.
	PrivateKey ci.PrivKey

	// Protector makes dialer part of a private network.
	// It includes implementation details how connection are protected.
	// Can be nil, then dialer is in public network.
	Protector ipnet.Protector

	// Wrapper to wrap the raw connection (optional)
	Wrapper WrapFunc

	fallback transport.Dialer
}

func NewDialer(p peer.ID, pk ci.PrivKey, wrap WrapFunc) *Dialer {
	return &Dialer{
		LocalPeer:  p,
		PrivateKey: pk,
		Wrapper:    wrap,
		fallback:   new(transport.FallbackDialer),
	}
}

// String returns the string rep of d.
func (d *Dialer) String() string {
	return fmt.Sprintf("<Dialer %s ...>", d.LocalPeer)
}

// Dial connects to a peer over a particular address
// Ensures raddr is part of peer.Addresses()
// Example: d.DialAddr(ctx, peer.Addresses()[0], peer)
func (d *Dialer) Dial(ctx context.Context, raddr ma.Multiaddr, remote peer.ID) (iconn.Conn, error) {
	deadline := time.Now().Add(DialTimeout)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	logdial := lgbl.Dial("conn", d.LocalPeer, remote, nil, raddr)
	logdial["encrypted"] = (d.PrivateKey != nil) // log wether this will be an encrypted dial or not.
	logdial["inPrivNet"] = (d.Protector != nil)

	defer log.EventBegin(ctx, "connDial", logdial).Done()

	if d.Protector == nil && ipnet.ForcePrivateNetwork {
		log.Error("tried to dial with no Private Network Protector but usage" +
			" of Private Networks is forced by the enviroment")
		return nil, ipnet.ErrNotInPrivateNetwork
	}

	var connOut iconn.Conn
	var errOut error
	done := make(chan struct{})

	// do it async to ensure we respect don contexteone
	go func() {
		defer func() {
			select {
			case done <- struct{}{}:
			case <-ctx.Done():
			}
		}()

		maconn, err := d.rawConnDial(ctx, raddr, remote)
		if err != nil {
			errOut = err
			return
		}

		if d.Protector != nil {
			pconn, err := d.Protector.Protect(maconn)
			if err != nil {
				maconn.Close()
				errOut = err
				return
			}
			maconn = pconn
		}

		if d.Wrapper != nil {
			maconn = d.Wrapper(maconn)
		}

		cryptoProtoChoice := SecioTag
		if !iconn.EncryptConnections || d.PrivateKey == nil {
			cryptoProtoChoice = NoEncryptionTag
		}

		maconn.SetDeadline(deadline)

		err = msmux.SelectProtoOrFail(cryptoProtoChoice, maconn)
		if err != nil {
			maconn.Close()
			errOut = err
			return
		}

		maconn.SetDeadline(time.Time{})

		c := newSingleConn(ctx, d.LocalPeer, remote, maconn)
		if d.PrivateKey == nil || !iconn.EncryptConnections {
			log.Warning("dialer %s dialing INSECURELY %s at %s!", d, remote, raddr)
			connOut = c
			return
		}

		c2, err := newSecureConn(ctx, d.PrivateKey, c)
		if err != nil {
			errOut = err
			c.Close()
			return
		}

		connOut = c2
	}()

	select {
	case <-ctx.Done():
		logdial["error"] = ctx.Err().Error()
		logdial["dial"] = "failure"
		return nil, ctx.Err()
	case <-done:
		// whew, finished.
	}

	if errOut != nil {
		logdial["error"] = errOut.Error()
		logdial["dial"] = "failure"
		return nil, errOut
	}

	// if the connection is not to whom we thought it would be...
	connRemote := connOut.RemotePeer()
	if connRemote != remote {
		err := connOut.Close()
		errOut = fmt.Errorf("misdial to %s through %s (got %s): %s", remote, raddr, connRemote, err)
		logdial["error"] = errOut.Error()
		logdial["dial"] = "failure"
		return nil, errOut
	}

	logdial["dial"] = "success"
	return connOut, nil
}

func (d *Dialer) AddDialer(pd transport.Dialer) {
	d.Dialers = append(d.Dialers, pd)
}

// returns dialer that can dial the given address
func (d *Dialer) subDialerForAddr(raddr ma.Multiaddr) transport.Dialer {
	for _, pd := range d.Dialers {
		if pd.Matches(raddr) {
			return pd
		}
	}

	if d.fallback.Matches(raddr) {
		return d.fallback
	}

	return nil
}

// rawConnDial dials the underlying net.Conn + manet.Conns
func (d *Dialer) rawConnDial(ctx context.Context, raddr ma.Multiaddr, remote peer.ID) (transport.Conn, error) {
	if strings.HasPrefix(raddr.String(), "/ip4/0.0.0.0") {
		log.Event(ctx, "connDialZeroAddr", lgbl.Dial("conn", d.LocalPeer, remote, nil, raddr))
		return nil, fmt.Errorf("Attempted to connect to zero address: %s", raddr)
	}

	sd := d.subDialerForAddr(raddr)
	if sd == nil {
		return nil, fmt.Errorf("no dialer for %s", raddr)
	}

	return sd.DialContext(ctx, raddr)
}

func pickLocalAddr(laddrs []ma.Multiaddr, raddr ma.Multiaddr) (laddr ma.Multiaddr) {
	if len(laddrs) < 1 {
		return nil
	}

	// make sure that we ONLY use local addrs that match the remote addr.
	laddrs = manet.AddrMatch(raddr, laddrs)
	if len(laddrs) < 1 {
		return nil
	}

	// make sure that we ONLY use local addrs that CAN dial the remote addr.
	// filter out all the local addrs that aren't capable
	raddrIPLayer := ma.Split(raddr)[0]
	raddrIsLoopback := manet.IsIPLoopback(raddrIPLayer)
	raddrIsLinkLocal := manet.IsIP6LinkLocal(raddrIPLayer)
	laddrs = addrutil.FilterAddrs(laddrs, func(a ma.Multiaddr) bool {
		laddrIPLayer := ma.Split(a)[0]
		laddrIsLoopback := manet.IsIPLoopback(laddrIPLayer)
		laddrIsLinkLocal := manet.IsIP6LinkLocal(laddrIPLayer)
		if laddrIsLoopback { // our loopback addrs can only dial loopbacks.
			return raddrIsLoopback
		}
		if laddrIsLinkLocal {
			return raddrIsLinkLocal // out linklocal addrs can only dial link locals.
		}
		return true
	})

	// TODO pick with a good heuristic
	// we use a random one for now to prevent bad addresses from making nodes unreachable
	// with a random selection, multiple tries may work.
	return laddrs[rand.Intn(len(laddrs))]
}

// MultiaddrProtocolsMatch returns whether two multiaddrs match in protocol stacks.
func MultiaddrProtocolsMatch(a, b ma.Multiaddr) bool {
	ap := a.Protocols()
	bp := b.Protocols()

	if len(ap) != len(bp) {
		return false
	}

	for i, api := range ap {
		if api.Code != bp[i].Code {
			return false
		}
	}

	return true
}

// MultiaddrNetMatch returns the first Multiaddr found to match  network.
func MultiaddrNetMatch(tgt ma.Multiaddr, srcs []ma.Multiaddr) ma.Multiaddr {
	for _, a := range srcs {
		if MultiaddrProtocolsMatch(tgt, a) {
			return a
		}
	}
	return nil
}
