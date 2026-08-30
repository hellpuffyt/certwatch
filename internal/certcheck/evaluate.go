package certcheck

import (
	"time"

	"certwatch/internal/inventory"
)

// Evaluate turns fetched certificate info into a reportable Result,
// applying the given lead times and current time. now is threaded through
// explicitly (rather than calling time.Now internally) so severity boundary
// behavior is exactly reproducible in tests.
func Evaluate(host inventory.Host, info CertInfo, lt inventory.LeadTimes, now time.Time) Result {
	r := Result{
		Host:            host.Name,
		Port:            host.EffectivePort(),
		SNI:             host.EffectiveSNI(),
		Owner:           host.Owner,
		Team:            host.Team,
		CheckedAt:       now,
		NotBefore:       info.NotBefore,
		NotAfter:        info.NotAfter,
		Issuer:          info.Issuer,
		Subject:         info.Subject,
		SerialNumber:    info.SerialNumber,
		SelfSigned:      info.SelfSigned,
		ChainIncomplete: info.ChainIncomplete,
	}

	r.SANMismatch = !AnyHostnameMatch(info.DNSNames, host.EffectiveSNI())

	// Days remaining until expiry, rounded toward zero on the calendar day
	// boundary so "3 days left" behaves the way an operator expects.
	remaining := info.NotAfter.Sub(now)
	r.DaysRemaining = int(remaining.Hours() / 24)

	switch {
	case now.Before(info.NotBefore):
		r.Severity = SeverityNotYetValid
	case !now.Before(info.NotAfter):
		r.Severity = SeverityExpired
	case r.DaysRemaining < lt.CriticalDays:
		r.Severity = SeverityCritical
	case r.DaysRemaining < lt.WarningDays:
		r.Severity = SeverityWarning
	case r.DaysRemaining < lt.NoticeDays:
		r.Severity = SeverityNotice
	default:
		r.Severity = SeverityOK
	}

	return r
}

// EvaluateError builds a Result representing a failed check (host
// unreachable, TLS handshake failure, timeout, etc). It always carries
// SeverityError so a single bad host is visible without crashing the run.
func EvaluateError(host inventory.Host, now time.Time, err error) Result {
	return Result{
		Host:      host.Name,
		Port:      host.EffectivePort(),
		SNI:       host.EffectiveSNI(),
		Owner:     host.Owner,
		Team:      host.Team,
		CheckedAt: now,
		Severity:  SeverityError,
		Error:     err.Error(),
	}
}
