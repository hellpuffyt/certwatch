package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"certwatch/internal/certcheck"
)

func TestLoadMissingFileReturnsEmptyState(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s.Entries) != 0 {
		t.Fatal("expected empty state")
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s := New()
	s.Entries["example.com:443"] = Entry{
		Host: "example.com", Port: 443, Severity: certcheck.SeverityWarning,
		Issuer: "CN=Test CA", SerialNumber: "123", LastChecked: time.Now().UTC().Round(time.Second),
	}
	if err := s.Save(path); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	e, ok := loaded.Entries["example.com:443"]
	if !ok {
		t.Fatal("expected entry to round-trip")
	}
	if e.Issuer != "CN=Test CA" || e.SerialNumber != "123" {
		t.Fatalf("unexpected entry: %+v", e)
	}
}

func TestLoadCorruptState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for corrupt state file")
	}
}

func TestFromResultsSkipsErrors(t *testing.T) {
	results := []certcheck.Result{
		{Host: "good", Port: 443, Severity: certcheck.SeverityOK},
		{Host: "bad", Port: 443, Severity: certcheck.SeverityError, Error: "timeout"},
	}
	s := FromResults(results)
	if _, ok := s.Entries["good:443"]; !ok {
		t.Fatal("expected good host recorded")
	}
	if _, ok := s.Entries["bad:443"]; ok {
		t.Fatal("expected errored host to be skipped")
	}
}

func TestMergeForwardCarriesErroredHostState(t *testing.T) {
	previous := New()
	previous.Entries["flaky:443"] = Entry{Host: "flaky", Port: 443, Severity: certcheck.SeverityWarning, Issuer: "CN=CA"}

	results := []certcheck.Result{
		{Host: "flaky", Port: 443, Severity: certcheck.SeverityError, Error: "timeout"},
	}
	next := MergeForward(previous, results)
	e, ok := next.Entries["flaky:443"]
	if !ok {
		t.Fatal("expected errored host's previous state to be carried forward")
	}
	if e.Severity != certcheck.SeverityWarning {
		t.Fatalf("expected carried-forward severity warning, got %s", e.Severity)
	}
}

func TestMergeForwardNilPrevious(t *testing.T) {
	results := []certcheck.Result{{Host: "a", Port: 443, Severity: certcheck.SeverityOK}}
	next := MergeForward(nil, results)
	if _, ok := next.Entries["a:443"]; !ok {
		t.Fatal("expected entry present")
	}
}

func TestCompare_NewProblem(t *testing.T) {
	previous := New()
	previous.Entries["a:443"] = Entry{Host: "a", Port: 443, Severity: certcheck.SeverityOK}
	results := []certcheck.Result{{Host: "a", Port: 443, Severity: certcheck.SeverityCritical}}
	diffs := Compare(previous, results)
	if len(diffs) != 1 || !diffs[0].New {
		t.Fatalf("expected new problem, got %+v", diffs)
	}
	if diffs[0].Resolved {
		t.Fatal("should not be resolved")
	}
}

func TestCompare_ResolvedProblem(t *testing.T) {
	previous := New()
	previous.Entries["a:443"] = Entry{Host: "a", Port: 443, Severity: certcheck.SeverityCritical}
	results := []certcheck.Result{{Host: "a", Port: 443, Severity: certcheck.SeverityOK}}
	diffs := Compare(previous, results)
	if len(diffs) != 1 || !diffs[0].Resolved {
		t.Fatalf("expected resolved problem, got %+v", diffs)
	}
	if diffs[0].New {
		t.Fatal("should not be new")
	}
}

func TestCompare_FirstSeenHostWithProblemIsNew(t *testing.T) {
	previous := New()
	results := []certcheck.Result{{Host: "a", Port: 443, Severity: certcheck.SeverityWarning}}
	diffs := Compare(previous, results)
	if !diffs[0].New || !diffs[0].FirstSeen {
		t.Fatalf("expected new+first-seen, got %+v", diffs[0])
	}
}

func TestCompare_FirstSeenHostOKIsNotNew(t *testing.T) {
	previous := New()
	results := []certcheck.Result{{Host: "a", Port: 443, Severity: certcheck.SeverityOK}}
	diffs := Compare(previous, results)
	if diffs[0].New {
		t.Fatal("first-seen OK host should not count as new problem")
	}
}

func TestCompare_CAChanged(t *testing.T) {
	previous := New()
	previous.Entries["a:443"] = Entry{Host: "a", Port: 443, Severity: certcheck.SeverityOK, Issuer: "CN=Old CA", SerialNumber: "1"}
	results := []certcheck.Result{{Host: "a", Port: 443, Severity: certcheck.SeverityOK, Issuer: "CN=New CA", SerialNumber: "2"}}
	diffs := Compare(previous, results)
	if !diffs[0].CAChanged {
		t.Fatal("expected CA change detected")
	}
	if !diffs[0].SerialChanged {
		t.Fatal("expected serial change detected")
	}
	if !diffs[0].Changed() {
		t.Fatal("expected Changed() true")
	}
}

func TestCompare_SameCADoesNotFlag(t *testing.T) {
	previous := New()
	previous.Entries["a:443"] = Entry{Host: "a", Port: 443, Severity: certcheck.SeverityOK, Issuer: "CN=CA", SerialNumber: "1"}
	results := []certcheck.Result{{Host: "a", Port: 443, Severity: certcheck.SeverityOK, Issuer: "CN=CA", SerialNumber: "1"}}
	diffs := Compare(previous, results)
	if diffs[0].CAChanged || diffs[0].SerialChanged {
		t.Fatal("expected no change flagged")
	}
	if diffs[0].Changed() {
		t.Fatal("expected Changed() false for stable host")
	}
}

func TestCompare_ErroredHostDoesNotFlagCAChange(t *testing.T) {
	previous := New()
	previous.Entries["a:443"] = Entry{Host: "a", Port: 443, Severity: certcheck.SeverityOK, Issuer: "CN=CA", SerialNumber: "1"}
	results := []certcheck.Result{{Host: "a", Port: 443, Severity: certcheck.SeverityError, Error: "timeout"}}
	diffs := Compare(previous, results)
	if diffs[0].CAChanged || diffs[0].SerialChanged {
		t.Fatal("errored host should not report CA/serial changes")
	}
}

func TestCompare_NoChangeForStableOK(t *testing.T) {
	previous := New()
	previous.Entries["a:443"] = Entry{Host: "a", Port: 443, Severity: certcheck.SeverityOK, Issuer: "CN=CA", SerialNumber: "1"}
	results := []certcheck.Result{{Host: "a", Port: 443, Severity: certcheck.SeverityOK, Issuer: "CN=CA", SerialNumber: "1"}}
	diffs := Compare(previous, results)
	if diffs[0].Changed() {
		t.Fatal("expected no changes for a stable healthy host")
	}
}
