package certcheck

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// genCertOpts describes a certificate to generate in-memory for tests. No
// private key material is ever written to disk; certificates exist only
// for the lifetime of the test process.
type genCertOpts struct {
	CommonName   string
	DNSNames     []string
	NotBefore    time.Time
	NotAfter     time.Time
	SelfSigned   bool
	SerialNumber int64
	// Issuer, when set and SelfSigned is false, generates a separate CA
	// key pair and signs the leaf with it, producing a distinct
	// issuer/subject pair with a valid signature chain.
	IssuerCommonName string
}

// mustGenCert builds an ECDSA certificate matching opts and returns the
// parsed *x509.Certificate, ready to feed into CertInfoFromCertificate.
func mustGenCert(t *testing.T, opts genCertOpts) *x509.Certificate {
	t.Helper()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}

	serial := opts.SerialNumber
	if serial == 0 {
		serial = 1
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: opts.CommonName},
		DNSNames:     opts.DNSNames,
		NotBefore:    opts.NotBefore,
		NotAfter:     opts.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	var derBytes []byte
	if opts.SelfSigned || opts.IssuerCommonName == "" {
		tmpl.Issuer = tmpl.Subject
		derBytes, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &leafKey.PublicKey, leafKey)
	} else {
		caKey, cerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if cerr != nil {
			t.Fatalf("generating ca key: %v", cerr)
		}
		caTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(serial + 1000),
			Subject:               pkix.Name{CommonName: opts.IssuerCommonName},
			NotBefore:             opts.NotBefore.Add(-24 * time.Hour),
			NotAfter:              opts.NotAfter.Add(24 * time.Hour),
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}
		caTmpl.Issuer = caTmpl.Subject
		caDER, cerr := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
		if cerr != nil {
			t.Fatalf("creating ca cert: %v", cerr)
		}
		caCert, cerr := x509.ParseCertificate(caDER)
		if cerr != nil {
			t.Fatalf("parsing ca cert: %v", cerr)
		}
		tmpl.Issuer = caTmpl.Subject
		derBytes, err = x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
	}
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("parsing generated certificate: %v", err)
	}
	return cert
}
