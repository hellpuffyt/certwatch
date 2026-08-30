package certcheck

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"time"

	"certwatch/internal/inventory"
)

// TLSFetcher fetches certificate information by dialing the host over TLS.
// It never fails the check due to certificate validity problems (expired,
// not-yet-valid, self-signed, hostname mismatch) — those are exactly what
// certwatch exists to report — so it disables Go's built-in verification
// and inspects the presented chain directly. It only errors on network or
// protocol failure (host unreachable, connection refused, timeout, TLS
// handshake failure below the certificate layer).
type TLSFetcher struct {
	// DialTimeout bounds the TCP connect + TLS handshake for a single
	// host. Zero means 10s.
	DialTimeout time.Duration
}

// Fetch implements Fetcher.
func (f TLSFetcher) Fetch(ctx context.Context, host inventory.Host) (CertInfo, error) {
	timeout := f.DialTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	addr := net.JoinHostPort(host.Name, strconv.Itoa(host.EffectivePort()))

	dialer := &net.Dialer{Timeout: timeout}
	tlsConf := &tls.Config{
		ServerName:         host.EffectiveSNI(),
		InsecureSkipVerify: true, // we do our own certificate evaluation
		MinVersion:         tls.VersionTLS10,
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	rawConn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return CertInfo{}, fmt.Errorf("dial %s: %w", addr, err)
	}
	defer rawConn.Close()

	if deadline, ok := dialCtx.Deadline(); ok {
		_ = rawConn.SetDeadline(deadline)
	}

	conn := tls.Client(rawConn, tlsConf)
	defer conn.Close()

	if err := conn.HandshakeContext(dialCtx); err != nil {
		return CertInfo{}, fmt.Errorf("tls handshake %s: %w", addr, err)
	}

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return CertInfo{}, fmt.Errorf("no certificates presented by %s", addr)
	}

	leaf := state.PeerCertificates[0]
	return CertInfoFromCertificate(leaf, len(state.PeerCertificates)), nil
}

// CertInfoFromCertificate converts a parsed leaf certificate (plus how many
// certificates the peer served in total) into the plain CertInfo used by
// the evaluation logic. Exported so both the real fetcher and tests that
// generate certificates with crypto/x509 can share the same conversion.
func CertInfoFromCertificate(leaf *x509.Certificate, chainLen int) CertInfo {
	selfSigned := isSelfSigned(leaf)
	return CertInfo{
		NotBefore:       leaf.NotBefore,
		NotAfter:        leaf.NotAfter,
		DNSNames:        leaf.DNSNames,
		Issuer:          leaf.Issuer.String(),
		Subject:         leaf.Subject.String(),
		SerialNumber:    leaf.SerialNumber.String(),
		SelfSigned:      selfSigned,
		ChainIncomplete: chainLen <= 1 && !selfSigned,
		ChainLength:     chainLen,
	}
}

// isSelfSigned reports whether a certificate appears to be self-signed: its
// raw issuer and subject DER encodings are identical. This mirrors what
// browsers and most TLS tooling use to flag self-signed certificates. It
// deliberately does not additionally require a valid self-signature via
// x509.CheckSignatureFrom, since that call also enforces CA/basic-
// constraints bits that a self-signed leaf certificate may not set, which
// would produce false negatives on real self-signed certs served by
// misconfigured hosts.
func isSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawIssuer, cert.RawSubject)
}
