package certcheck

import (
	"testing"
	"time"

	"certwatch/internal/inventory"
)

func TestCertInfoFromCertificate_Basic(t *testing.T) {
	now := time.Now()
	cert := mustGenCert(t, genCertOpts{
		CommonName:       "example.com",
		DNSNames:         []string{"example.com", "www.example.com"},
		NotBefore:        now.Add(-24 * time.Hour),
		NotAfter:         now.Add(20 * 24 * time.Hour),
		IssuerCommonName: "Test Intermediate CA",
	})

	info := CertInfoFromCertificate(cert, 2)
	if info.SelfSigned {
		t.Fatal("expected CA-issued cert to not be self-signed")
	}
	if info.ChainIncomplete {
		t.Fatal("expected chain of 2 to be considered complete")
	}
	if len(info.DNSNames) != 2 {
		t.Fatalf("expected 2 SANs, got %v", info.DNSNames)
	}
	if info.Issuer == info.Subject {
		t.Fatal("expected distinct issuer and subject for CA-issued cert")
	}
	if info.SerialNumber == "" {
		t.Fatal("expected serial number to be populated")
	}
}

func TestCertInfoFromCertificate_SelfSigned(t *testing.T) {
	now := time.Now()
	cert := mustGenCert(t, genCertOpts{
		CommonName: "selfsigned.example.com",
		DNSNames:   []string{"selfsigned.example.com"},
		NotBefore:  now.Add(-24 * time.Hour),
		NotAfter:   now.Add(20 * 24 * time.Hour),
		SelfSigned: true,
	})

	info := CertInfoFromCertificate(cert, 1)
	if !info.SelfSigned {
		t.Fatal("expected self-signed detection")
	}
	if info.ChainIncomplete {
		t.Fatal("self-signed single cert should not be flagged chain-incomplete")
	}
}

func TestCertInfoFromCertificate_ChainIncomplete(t *testing.T) {
	now := time.Now()
	cert := mustGenCert(t, genCertOpts{
		CommonName:       "leafonly.example.com",
		DNSNames:         []string{"leafonly.example.com"},
		NotBefore:        now.Add(-24 * time.Hour),
		NotAfter:         now.Add(20 * 24 * time.Hour),
		IssuerCommonName: "Some Missing Intermediate",
	})

	// Server presented only the leaf (chain length 1) despite being
	// CA-issued (not self-signed) -- this is the "no intermediates"
	// misconfiguration certwatch should flag.
	info := CertInfoFromCertificate(cert, 1)
	if info.SelfSigned {
		t.Fatal("expected not self-signed")
	}
	if !info.ChainIncomplete {
		t.Fatal("expected chain-incomplete to be flagged")
	}
}

func TestCertInfoFromCertificate_Expired(t *testing.T) {
	now := time.Now()
	cert := mustGenCert(t, genCertOpts{
		CommonName:       "expired.example.com",
		DNSNames:         []string{"expired.example.com"},
		NotBefore:        now.Add(-100 * 24 * time.Hour),
		NotAfter:         now.Add(-1 * 24 * time.Hour),
		IssuerCommonName: "Test CA",
	})
	info := CertInfoFromCertificate(cert, 2)
	if !info.NotAfter.Before(now) {
		t.Fatal("expected NotAfter in the past")
	}
}

func TestCertInfoFromCertificate_ExpiringSoonVariants(t *testing.T) {
	now := time.Now()
	for _, days := range []int{3, 20, 45} {
		cert := mustGenCert(t, genCertOpts{
			CommonName:       "soon.example.com",
			DNSNames:         []string{"soon.example.com"},
			NotBefore:        now.Add(-24 * time.Hour),
			NotAfter:         now.Add(time.Duration(days) * 24 * time.Hour),
			IssuerCommonName: "Test CA",
		})
		info := CertInfoFromCertificate(cert, 2)
		remaining := info.NotAfter.Sub(now).Hours() / 24
		if remaining < float64(days)-1 || remaining > float64(days) {
			t.Fatalf("expected ~%d days remaining, got %f", days, remaining)
		}
	}
}

func TestCertInfoFromCertificate_NotYetValid(t *testing.T) {
	now := time.Now()
	cert := mustGenCert(t, genCertOpts{
		CommonName:       "future.example.com",
		DNSNames:         []string{"future.example.com"},
		NotBefore:        now.Add(10 * 24 * time.Hour),
		NotAfter:         now.Add(100 * 24 * time.Hour),
		IssuerCommonName: "Test CA",
	})
	info := CertInfoFromCertificate(cert, 2)
	if !info.NotBefore.After(now) {
		t.Fatal("expected NotBefore in the future")
	}
}

func TestCertInfoFromCertificate_WrongSAN(t *testing.T) {
	now := time.Now()
	cert := mustGenCert(t, genCertOpts{
		CommonName:       "wrongsan.example.com",
		DNSNames:         []string{"totally-different.example.org"},
		NotBefore:        now.Add(-24 * time.Hour),
		NotAfter:         now.Add(20 * 24 * time.Hour),
		IssuerCommonName: "Test CA",
	})
	info := CertInfoFromCertificate(cert, 2)
	if AnyHostnameMatch(info.DNSNames, "wrongsan.example.com") {
		t.Fatal("expected SAN mismatch against requested host")
	}
}

func TestFullPipeline_GeneratedCertThroughEvaluate(t *testing.T) {
	// End-to-end: generate a cert, convert it, evaluate it, and check the
	// resulting Result -- this is the offline substitute for a real TLS
	// handshake, exercising the same code path production Fetch() uses.
	now := time.Now()
	cert := mustGenCert(t, genCertOpts{
		CommonName:       "pipeline.example.com",
		DNSNames:         []string{"pipeline.example.com"},
		NotBefore:        now.Add(-24 * time.Hour),
		NotAfter:         now.Add(3 * 24 * time.Hour),
		IssuerCommonName: "Pipeline CA",
	})
	info := CertInfoFromCertificate(cert, 2)
	host := inventory.Host{Name: "pipeline.example.com"}
	r := Evaluate(host, info, defaultLT(), now)
	if r.Severity != SeverityCritical {
		t.Fatalf("expected critical for 3-day cert, got %s", r.Severity)
	}
	if r.SANMismatch {
		t.Fatal("expected SAN match")
	}
}
