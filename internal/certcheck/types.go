// Package certcheck contains the certificate-fetching and evaluation logic
// at the heart of certwatch: given information about a leaf certificate, it
// classifies expiry severity, detects hostname mismatches, self-signed and
// incomplete-chain certificates, and CA/serial changes between runs.
package certcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"certwatch/internal/inventory"
)

// Severity classifies the health of a single certificate check. The zero
// value is SeverityOK. Ranks increase with urgency; Rank() gives the total
// order used by --fail-on threshold comparisons.
type Severity int

const (
	SeverityOK Severity = iota
	SeverityNotice
	SeverityWarning
	SeverityCritical
	SeverityNotYetValid
	SeverityExpired
	SeverityError // host unreachable / check failed
)

// String returns the lowercase name of the severity, used in reports and
// for parsing --fail-on / --only-changed style flags.
func (s Severity) String() string {
	switch s {
	case SeverityOK:
		return "ok"
	case SeverityNotice:
		return "notice"
	case SeverityWarning:
		return "warning"
	case SeverityCritical:
		return "critical"
	case SeverityNotYetValid:
		return "not-yet-valid"
	case SeverityExpired:
		return "expired"
	case SeverityError:
		return "error"
	default:
		return "unknown"
	}
}

// ParseSeverity parses a severity name (as produced by String) back into a
// Severity value. Used for --fail-on flag parsing.
func ParseSeverity(s string) (Severity, bool) {
	switch s {
	case "ok":
		return SeverityOK, true
	case "notice":
		return SeverityNotice, true
	case "warning":
		return SeverityWarning, true
	case "critical":
		return SeverityCritical, true
	case "not-yet-valid":
		return SeverityNotYetValid, true
	case "expired":
		return SeverityExpired, true
	case "error":
		return SeverityError, true
	default:
		return SeverityOK, false
	}
}

// MarshalJSON renders the severity as its lowercase name (e.g. "critical")
// rather than its underlying integer, so JSON output is self-describing.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON parses a severity name back into a Severity, the inverse of
// MarshalJSON. Used when state or JSON output is read back in.
func (s *Severity) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return err
	}
	sev, ok := ParseSeverity(name)
	if !ok {
		return fmt.Errorf("invalid severity %q", name)
	}
	*s = sev
	return nil
}

// CertInfo is the fetcher-agnostic view of a leaf certificate that the
// evaluation logic operates on. It intentionally holds only plain data (no
// *x509.Certificate) so that tests can build it directly without a real TLS
// handshake or parsed certificate.
type CertInfo struct {
	NotBefore       time.Time
	NotAfter        time.Time
	DNSNames        []string
	Issuer          string
	Subject         string
	SerialNumber    string
	SelfSigned      bool
	ChainIncomplete bool // leaf presented with no intermediates and not self-signed
	ChainLength     int  // number of certificates served, including leaf
}

// Result is the outcome of checking a single host, ready for reporting and
// state comparison.
type Result struct {
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	SNI       string    `json:"sni"`
	Owner     string    `json:"owner,omitempty"`
	Team      string    `json:"team,omitempty"`
	CheckedAt time.Time `json:"checked_at"`

	Severity      Severity `json:"severity"`
	DaysRemaining int      `json:"days_remaining"`

	NotBefore    time.Time `json:"not_before,omitempty"`
	NotAfter     time.Time `json:"not_after,omitempty"`
	Issuer       string    `json:"issuer,omitempty"`
	Subject      string    `json:"subject,omitempty"`
	SerialNumber string    `json:"serial_number,omitempty"`

	SANMismatch     bool `json:"san_mismatch"`
	SelfSigned      bool `json:"self_signed"`
	ChainIncomplete bool `json:"chain_incomplete"`

	Error string `json:"error,omitempty"`
}

// Key mirrors inventory.Host.Key for state tracking.
func (r Result) Key() string {
	return inventory.Host{Name: r.Host, Port: r.Port}.Key()
}

// Problem reports whether this result represents something worth a human's
// attention (anything other than a clean OK).
func (r Result) Problem() bool {
	return r.Severity != SeverityOK
}

// Fetcher retrieves certificate information for a host. Production code
// uses the real TLS-dialing implementation in fetch.go; tests substitute a
// fake that returns canned CertInfo values or errors, so all downstream
// logic is testable without network access.
type Fetcher interface {
	Fetch(ctx context.Context, host inventory.Host) (CertInfo, error)
}
