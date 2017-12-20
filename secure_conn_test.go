package conn

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	ic "github.com/libp2p/go-libp2p-crypto"
	iconn "github.com/libp2p/go-libp2p-interface-conn"
	peer "github.com/libp2p/go-libp2p-peer"
	travis "github.com/libp2p/go-testutil/ci/travis"
)

func secureHandshake(ctx context.Context, sk ic.PrivKey, c *iconn.Conn, done chan error, tls, client bool) {
	if _, ok := (*c).(*secureConn); ok {
		done <- errors.New("already a secure connection")
		return
	}
	if _, ok := (*c).(*tlsConn); ok {
		done <- errors.New("already a TLS connection")
		return
	}

	var err error
	var sc iconn.Conn
	if tls {
		sc, err = newTLSConn(ctx, sk, *c, client)
	} else {
		sc, err = newSecureConn(ctx, sk, *c)
	}
	if err != nil {
		done <- err
		return
	}

	if err := sayHello(sc); err != nil {
		done <- err
		return
	}

	*c = sc
	done <- nil
}

func testSecureSimple(t *testing.T, ed, tls bool) {
	numMsgs := 100
	if testing.Short() {
		numMsgs = 10
	}

	ctx := context.Background()
	c1, c2, p1, p2 := setupConn(t, ctx, ed, false)

	done := make(chan error)
	go secureHandshake(ctx, p1.PrivKey, &c1, done, tls, true)
	go secureHandshake(ctx, p2.PrivKey, &c2, done, tls, false)

	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}

	if c1.RemotePeer() != c2.LocalPeer() {
		t.Error("remote/local peer mismatch")
	}
	if c2.RemotePeer() != c1.LocalPeer() {
		t.Error("remote/local peer mismatch")
	}
	if p, _ := peer.IDFromPublicKey(c1.RemotePublicKey()); p != c1.RemotePeer() {
		t.Error("wrong RemotePublicKey")
	}
	if p, _ := peer.IDFromPublicKey(c2.RemotePublicKey()); p != c2.RemotePeer() {
		t.Error("wrong RemotePublicKey")
	}

	for i := 0; i < numMsgs; i++ {
		testOneSendRecv(t, c1, c2)
		testOneSendRecv(t, c2, c1)
	}

	c1.Close()
	c2.Close()
}

func TestSecureSimple(t *testing.T) {
	t.Run("secio/RSA", func(t *testing.T) {
		testSecureSimple(t, false, false)
	})
	t.Run("secio/Ed25519", func(t *testing.T) {
		testSecureSimple(t, true, false)
	})
	t.Run("tls/RSA", func(t *testing.T) {
		testSecureSimple(t, false, true)
	})
	t.Run("tls/Ed25519", func(t *testing.T) {
		t.Skip("Ed25519 is only supported by TLS 1.3")
		testSecureSimple(t, true, true)
	})
}

func testSecureClose(t *testing.T, tls bool) {
	ctx := context.Background()
	c1, c2, p1, p2 := setupSingleConn(t, ctx)

	done := make(chan error)
	go secureHandshake(ctx, p1.PrivKey, &c1, done, tls, true)
	go secureHandshake(ctx, p2.PrivKey, &c2, done, tls, false)

	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}

	testOneSendRecv(t, c1, c2)

	c1.Close()
	testNotOneSendRecv(t, c1, c2)

	c2.Close()
	testNotOneSendRecv(t, c1, c2)
	testNotOneSendRecv(t, c2, c1)

}

func TestSecureClose(t *testing.T) {
	t.Run("secio", func(t *testing.T) {
		testSecureClose(t, false)
	})
	t.Run("tls", func(t *testing.T) {
		testSecureClose(t, true)
	})
}

func testSecureCancelHandshake(t *testing.T, tls bool) {
	for _, client := range []bool{true, false} {
		ctx, cancel := context.WithCancel(context.Background())
		c1, c2, p1, _ := setupSingleConn(t, ctx)

		done := make(chan error)
		go secureHandshake(ctx, p1.PrivKey, &c1, done, tls, client)
		time.Sleep(time.Millisecond)
		cancel() // cancel ctx

		if err := <-done; err == nil {
			t.Error("cancel should've errored out")
		}

		c2.Close()
	}
}

func TestSecureCancelHandshake(t *testing.T) {
	t.Run("secio", func(t *testing.T) {
		testSecureCancelHandshake(t, false)
	})
	t.Run("tls", func(t *testing.T) {
		testSecureCancelHandshake(t, true)
	})
}

func testSecureHandshakeFailsWithWrongKeys(t *testing.T, tls bool) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c1, c2, p1, p2 := setupSingleConn(t, ctx)

	done := make(chan error)
	go secureHandshake(ctx, p2.PrivKey, &c1, done, tls, true)
	go secureHandshake(ctx, p1.PrivKey, &c2, done, tls, false)

	for i := 0; i < 2; i++ {
		if err := <-done; err == nil {
			t.Fatal("wrong keys should've errored out.")
		}
	}
}

func TestSecureHandshakeFailsWithWrongKeys(t *testing.T) {
	t.Run("secio", func(t *testing.T) {
		testSecureHandshakeFailsWithWrongKeys(t, false)
	})
	t.Run("tls", func(t *testing.T) {
		testSecureHandshakeFailsWithWrongKeys(t, true)
	})
}

func TestSecureCloseLeak(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	if travis.IsRunning() {
		t.Skip("this doesn't work well on travis")
	}

	runPair := func(c1, c2 iconn.Conn, num int) {
		mc1 := msgioWrap(c1)
		mc2 := msgioWrap(c2)

		log.Debugf("runPair %d", num)

		for i := 0; i < num; i++ {
			log.Debugf("runPair iteration %d", i)
			b1 := []byte("beep")
			mc1.WriteMsg(b1)
			b2, err := mc2.ReadMsg()
			if err != nil {
				panic(err)
			}
			if !bytes.Equal(b1, b2) {
				panic("bytes not equal")
			}

			b2 = []byte("beep")
			mc2.WriteMsg(b2)
			b1, err = mc1.ReadMsg()
			if err != nil {
				panic(err)
			}
			if !bytes.Equal(b1, b2) {
				panic("bytes not equal")
			}

			time.Sleep(time.Microsecond * 5)
		}
	}

	var cons = 5
	var msgs = 50
	log.Debugf("Running %d connections * %d msgs.\n", cons, msgs)

	var wg sync.WaitGroup
	for i := 0; i < cons; i++ {
		wg.Add(1)

		ctx, cancel := context.WithCancel(context.Background())
		c1, c2, _, _ := setupSecureConn(t, ctx)
		go func(c1, c2 iconn.Conn) {

			defer func() {
				c1.Close()
				c2.Close()
				cancel()
				wg.Done()
			}()

			runPair(c1, c2, msgs)
		}(c1, c2)
	}

	log.Debugf("Waiting...")
	wg.Wait()
	// done!

	time.Sleep(time.Millisecond * 150)
	ngr := runtime.NumGoroutine()
	if ngr > 25 {
		// panic("uncomment me to debug")
		t.Fatal("leaking goroutines:", ngr)
	}
}
