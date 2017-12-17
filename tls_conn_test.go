package conn

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	tu "github.com/libp2p/go-testutil"
)

func TestKeyToCertificate(t *testing.T) {
	priv, pub, err := tu.RandTestKeyPair(512)
	fatalIfErr(t, err)
	cert, err := keyToCertificate(priv)
	fatalIfErr(t, err)

	t.Logf("\n%s", pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Certificate[0],
	}))

	c, err := x509.ParseCertificate(cert.Certificate[0])
	fatalIfErr(t, err)
	newPub, err := certificateToKey(c)
	fatalIfErr(t, err)

	if !pub.Equals(newPub) {
		t.Error("extracted public key is different")
	}
}

func fatalIfErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
