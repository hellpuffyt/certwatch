package certcheck

import (
	"testing"
	"time"

	"certwatch/internal/inventory"
)

var fixedNow = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func daysFromNow(d int) time.Time {
	return fixedNow.Add(time.Duration(d) * 24 * time.Hour)
}

func defaultLT() inventory.LeadTimes {
	return inventory.DefaultLeadTimes() // critical<7 warning<30 notice<60
}

func TestEvaluate_Expired(t *testing.T) {
	host := inventory.Host{Name: "example.com"}
	info := CertInfo{
		NotBefore: daysFromNow(-100),
		NotAfter:  daysFromNow(-1),
		DNSNames:  []string{"example.com"},
	}
	r := Evaluate(host, info, defaultLT(), fixedNow)
	if r.Severity != SeverityExpired {
		t.Fatalf("expected expired, got %s", r.Severity)
	}
}

func TestEvaluate_ExpiresExactlyNow(t *testing.T) {
	host := inventory.Host{Name: "example.com"}
	info := CertInfo{
		NotBefore: daysFromNow(-100),
		NotAfter:  fixedNow, // exactly now: no longer valid
		DNSNames:  []string{"example.com"},
	}
	r := Evaluate(host, info, defaultLT(), fixedNow)
	if r.Severity != SeverityExpired {
		t.Fatalf("expected expired at exact boundary, got %s", r.Severity)
	}
}

func TestEvaluate_NotYetValid(t *testing.T) {
	host := inventory.Host{Name: "example.com"}
	info := CertInfo{
		NotBefore: daysFromNow(5),
		NotAfter:  daysFromNow(100),
		DNSNames:  []string{"example.com"},
	}
	r := Evaluate(host, info, defaultLT(), fixedNow)
	if r.Severity != SeverityNotYetValid {
		t.Fatalf("expected not-yet-valid, got %s", r.Severity)
	}
}

func TestEvaluate_NotYetValidTakesPriorityOverExpired(t *testing.T) {
	// A pathological cert where NotBefore > NotAfter (misconfigured), or
	// simply one that hasn't started yet. not-yet-valid must win since
	// "now" is before NotBefore.
	host := inventory.Host{Name: "example.com"}
	info := CertInfo{
		NotBefore: daysFromNow(1),
		NotAfter:  daysFromNow(2),
		DNSNames:  []string{"example.com"},
	}
	r := Evaluate(host, info, defaultLT(), fixedNow)
	if r.Severity != SeverityNotYetValid {
		t.Fatalf("expected not-yet-valid, got %s", r.Severity)
	}
}

func TestEvaluate_CriticalWarningBoundary_6vs7(t *testing.T) {
	host := inventory.Host{Name: "example.com"}
	lt := defaultLT() // critical < 7

	info6 := CertInfo{NotBefore: daysFromNow(-1), NotAfter: daysFromNow(6), DNSNames: []string{"example.com"}}
	r6 := Evaluate(host, info6, lt, fixedNow)
	if r6.Severity != SeverityCritical {
		t.Fatalf("expected critical at 6 days, got %s (days=%d)", r6.Severity, r6.DaysRemaining)
	}

	info7 := CertInfo{NotBefore: daysFromNow(-1), NotAfter: daysFromNow(7), DNSNames: []string{"example.com"}}
	r7 := Evaluate(host, info7, lt, fixedNow)
	if r7.Severity != SeverityWarning {
		t.Fatalf("expected warning at 7 days, got %s (days=%d)", r7.Severity, r7.DaysRemaining)
	}

	if r6.Severity == r7.Severity {
		t.Fatalf("expected 6 and 7 day certs to differ in severity")
	}
}

func TestEvaluate_WarningNoticeBoundary_7vs8(t *testing.T) {
	// Exercise the adjacent-day boundary explicitly at 7 vs 8 days too:
	// both fall in "warning" under defaults, so they must have the SAME
	// severity but DIFFERENT DaysRemaining -- guards against an off-by-one
	// that collapses distinct remaining-day counts into one bucket.
	host := inventory.Host{Name: "example.com"}
	lt := defaultLT()

	info7 := CertInfo{NotBefore: daysFromNow(-1), NotAfter: daysFromNow(7), DNSNames: []string{"example.com"}}
	info8 := CertInfo{NotBefore: daysFromNow(-1), NotAfter: daysFromNow(8), DNSNames: []string{"example.com"}}
	r7 := Evaluate(host, info7, lt, fixedNow)
	r8 := Evaluate(host, info8, lt, fixedNow)

	if r7.Severity != SeverityWarning || r8.Severity != SeverityWarning {
		t.Fatalf("expected both warning, got %s and %s", r7.Severity, r8.Severity)
	}
	if r7.DaysRemaining == r8.DaysRemaining {
		t.Fatalf("expected distinct day counts for 7 vs 8 day certs")
	}
}

func TestEvaluate_WarningNoticeBoundary_29vs30(t *testing.T) {
	host := inventory.Host{Name: "example.com"}
	lt := defaultLT() // warning < 30

	r29 := Evaluate(host, CertInfo{NotBefore: daysFromNow(-1), NotAfter: daysFromNow(29), DNSNames: []string{"example.com"}}, lt, fixedNow)
	if r29.Severity != SeverityWarning {
		t.Fatalf("expected warning at 29 days, got %s", r29.Severity)
	}
	r30 := Evaluate(host, CertInfo{NotBefore: daysFromNow(-1), NotAfter: daysFromNow(30), DNSNames: []string{"example.com"}}, lt, fixedNow)
	if r30.Severity != SeverityNotice {
		t.Fatalf("expected notice at 30 days, got %s", r30.Severity)
	}
}

func TestEvaluate_NoticeOKBoundary_59vs60(t *testing.T) {
	host := inventory.Host{Name: "example.com"}
	lt := defaultLT() // notice < 60

	r59 := Evaluate(host, CertInfo{NotBefore: daysFromNow(-1), NotAfter: daysFromNow(59), DNSNames: []string{"example.com"}}, lt, fixedNow)
	if r59.Severity != SeverityNotice {
		t.Fatalf("expected notice at 59 days, got %s", r59.Severity)
	}
	r60 := Evaluate(host, CertInfo{NotBefore: daysFromNow(-1), NotAfter: daysFromNow(60), DNSNames: []string{"example.com"}}, lt, fixedNow)
	if r60.Severity != SeverityOK {
		t.Fatalf("expected ok at 60 days, got %s", r60.Severity)
	}
}

func TestEvaluate_CustomLeadTimes(t *testing.T) {
	host := inventory.Host{Name: "example.com"}
	lt := inventory.LeadTimes{CriticalDays: 1, WarningDays: 2, NoticeDays: 3}
	r := Evaluate(host, CertInfo{NotBefore: daysFromNow(-1), NotAfter: daysFromNow(1), DNSNames: []string{"example.com"}}, lt, fixedNow)
	if r.Severity != SeverityWarning {
		t.Fatalf("expected warning under custom thresholds, got %s", r.Severity)
	}
}

func TestEvaluate_SANMatchExact(t *testing.T) {
	host := inventory.Host{Name: "example.com"}
	info := CertInfo{NotBefore: daysFromNow(-1), NotAfter: daysFromNow(100), DNSNames: []string{"example.com", "www.example.com"}}
	r := Evaluate(host, info, defaultLT(), fixedNow)
	if r.SANMismatch {
		t.Fatal("expected SAN match")
	}
}

func TestEvaluate_SANMismatch(t *testing.T) {
	host := inventory.Host{Name: "example.com"}
	info := CertInfo{NotBefore: daysFromNow(-1), NotAfter: daysFromNow(100), DNSNames: []string{"other.com"}}
	r := Evaluate(host, info, defaultLT(), fixedNow)
	if !r.SANMismatch {
		t.Fatal("expected SAN mismatch")
	}
}

func TestEvaluate_SANMismatchUsesSNIOverride(t *testing.T) {
	host := inventory.Host{Name: "10.0.0.1", SNI: "internal.example.com"}
	info := CertInfo{NotBefore: daysFromNow(-1), NotAfter: daysFromNow(100), DNSNames: []string{"internal.example.com"}}
	r := Evaluate(host, info, defaultLT(), fixedNow)
	if r.SANMismatch {
		t.Fatal("expected match against SNI override, not raw host")
	}
}

func TestEvaluate_WildcardSAN(t *testing.T) {
	host := inventory.Host{Name: "api.example.com"}
	info := CertInfo{NotBefore: daysFromNow(-1), NotAfter: daysFromNow(100), DNSNames: []string{"*.example.com"}}
	r := Evaluate(host, info, defaultLT(), fixedNow)
	if r.SANMismatch {
		t.Fatal("expected wildcard match")
	}
}

func TestEvaluate_SelfSignedAndChainIncompletePassthrough(t *testing.T) {
	host := inventory.Host{Name: "example.com"}
	info := CertInfo{
		NotBefore:       daysFromNow(-1),
		NotAfter:        daysFromNow(100),
		DNSNames:        []string{"example.com"},
		SelfSigned:      true,
		ChainIncomplete: false,
	}
	r := Evaluate(host, info, defaultLT(), fixedNow)
	if !r.SelfSigned {
		t.Fatal("expected self-signed flag to pass through")
	}

	info2 := CertInfo{
		NotBefore:       daysFromNow(-1),
		NotAfter:        daysFromNow(100),
		DNSNames:        []string{"example.com"},
		ChainIncomplete: true,
	}
	r2 := Evaluate(host, info2, defaultLT(), fixedNow)
	if !r2.ChainIncomplete {
		t.Fatal("expected chain-incomplete flag to pass through")
	}
}

func TestEvaluate_HostFieldsPopulated(t *testing.T) {
	host := inventory.Host{Name: "example.com", Port: 8443, Owner: "sre", Team: "platform"}
	info := CertInfo{NotBefore: daysFromNow(-1), NotAfter: daysFromNow(100), DNSNames: []string{"example.com"}}
	r := Evaluate(host, info, defaultLT(), fixedNow)
	if r.Host != "example.com" || r.Port != 8443 || r.Owner != "sre" || r.Team != "platform" {
		t.Fatalf("unexpected result fields: %+v", r)
	}
}

func TestEvaluateError(t *testing.T) {
	host := inventory.Host{Name: "unreachable.example.com"}
	r := EvaluateError(host, fixedNow, errTimeout{})
	if r.Severity != SeverityError {
		t.Fatalf("expected error severity, got %s", r.Severity)
	}
	if r.Error == "" {
		t.Fatal("expected error message to be set")
	}
	if !r.Problem() {
		t.Fatal("expected error result to be a problem")
	}
}

func TestResultKey(t *testing.T) {
	r := Result{Host: "example.com", Port: 8443}
	if r.Key() != "example.com:8443" {
		t.Fatalf("unexpected key: %s", r.Key())
	}
}

func TestResultProblem(t *testing.T) {
	ok := Result{Severity: SeverityOK}
	if ok.Problem() {
		t.Fatal("OK should not be a problem")
	}
	crit := Result{Severity: SeverityCritical}
	if !crit.Problem() {
		t.Fatal("critical should be a problem")
	}
}

type errTimeout struct{}

func (errTimeout) Error() string { return "i/o timeout" }
