package certcheck

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/hellpuffyt/certwatch/internal/inventory"
)

// These tests drive the real TLSFetcher against TLS listeners on the
// loopback interface, with certificates generated in memory. No public
// network access is involved.

type testPKI struct {
	rootDER, interDER, leafDER []byte
	leafKey                    *ecdsa.PrivateKey
}

func newTestPKI(t *testing.T, notBefore, notAfter time.Time, dnsNames []string) testPKI {
	t.Helper()
	gen := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	rootKey, interKey, leafKey := gen(), gen(), gen()
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)
	inter := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Intermediate"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(5 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	interDER, err := x509.CreateCertificate(rand.Reader, inter, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	interCert, _ := x509.ParseCertificate(interDER)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: dnsNames[0]},
		DNSNames: dnsNames, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, interCert, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}
	return testPKI{rootDER: rootDER, interDER: interDER, leafDER: leafDER, leafKey: leafKey}
}

// serveTLS starts a loopback TLS listener presenting chain and returns a
// Host pointing at it.
func serveTLS(t *testing.T, chain [][]byte, key *ecdsa.PrivateKey, sni string) inventory.Host {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				c.Close()
			}()
		}
	}()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(port)
	return inventory.Host{Name: host, Port: p, SNI: sni}
}

func TestTLSFetcherReportsChainCompleteness(t *testing.T) {
	now := time.Now()
	pki := newTestPKI(t, now.Add(-time.Hour), now.Add(20*24*time.Hour), []string{"svc.test"})

	full := serveTLS(t, [][]byte{pki.leafDER, pki.interDER}, pki.leafKey, "svc.test")
	info, err := TLSFetcher{DialTimeout: 5 * time.Second}.Fetch(context.Background(), full)
	if err != nil {
		t.Fatal(err)
	}
	if info.ChainIncomplete || info.SelfSigned || info.ChainLength != 2 || info.SerialNumber != "77" {
		t.Fatalf("full chain: %+v", info)
	}
	r := Evaluate(full, info, inventory.DefaultLeadTimes(), now)
	if r.Severity != SeverityWarning || r.SANMismatch {
		t.Fatalf("full chain result: %+v", r)
	}

	leafOnly := serveTLS(t, [][]byte{pki.leafDER}, pki.leafKey, "svc.test")
	info, err = TLSFetcher{DialTimeout: 5 * time.Second}.Fetch(context.Background(), leafOnly)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ChainIncomplete || info.ChainLength != 1 {
		t.Fatalf("leaf only should be chain-incomplete: %+v", info)
	}
}

// Expired and not-yet-valid certificates must still be fetched (the fetcher
// does not verify) so they can be reported with the right severity.
func TestTLSFetcherFetchesBrokenCertificates(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name     string
		nb, na   time.Time
		sni      string
		want     Severity
		mismatch bool
	}{
		{"expired", now.Add(-60 * 24 * time.Hour), now.Add(-24 * time.Hour), "svc.test", SeverityExpired, false},
		{"not yet valid", now.Add(24 * time.Hour), now.Add(90 * 24 * time.Hour), "svc.test", SeverityNotYetValid, false},
		{"wrong name", now.Add(-time.Hour), now.Add(90 * 24 * time.Hour), "other.test", SeverityOK, true},
	}
	for _, c := range cases {
		pki := newTestPKI(t, c.nb, c.na, []string{"svc.test"})
		h := serveTLS(t, [][]byte{pki.leafDER, pki.interDER}, pki.leafKey, c.sni)
		info, err := TLSFetcher{DialTimeout: 5 * time.Second}.Fetch(context.Background(), h)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		r := Evaluate(h, info, inventory.DefaultLeadTimes(), now)
		if r.Severity != c.want || r.SANMismatch != c.mismatch {
			t.Fatalf("%s: severity %v mismatch %v", c.name, r.Severity, r.SANMismatch)
		}
	}
}

// A listener that accepts TCP but never speaks TLS must time out within
// the per-host timeout rather than hang the run.
func TestTLSFetcherTimesOutOnSilentServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close() // hold the connection open, say nothing
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(port)
	start := time.Now()
	_, err = TLSFetcher{DialTimeout: 300 * time.Millisecond}.Fetch(context.Background(), inventory.Host{Name: "127.0.0.1", Port: p})
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("fetch took %v, timeout not enforced", time.Since(start))
	}
}
