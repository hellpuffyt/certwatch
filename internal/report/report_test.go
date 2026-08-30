package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"certwatch/internal/certcheck"
)

func sampleResults() []certcheck.Result {
	now := time.Now()
	return []certcheck.Result{
		{Host: "ok.example.com", Port: 443, Severity: certcheck.SeverityOK, DaysRemaining: 90, Issuer: "CN=CA", CheckedAt: now},
		{Host: "crit.example.com", Port: 443, Severity: certcheck.SeverityCritical, DaysRemaining: 3, Issuer: "CN=CA", CheckedAt: now},
		{Host: "bad.example.com", Port: 443, Severity: certcheck.SeverityError, Error: "dial tcp: timeout", CheckedAt: now},
		{Host: "mismatch.example.com", Port: 443, Severity: certcheck.SeverityWarning, DaysRemaining: 10, SANMismatch: true, CheckedAt: now},
	}
}

func TestWriteTable_ContainsAllHosts(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTable(&buf, sampleResults()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, host := range []string{"ok.example.com", "crit.example.com", "bad.example.com", "mismatch.example.com"} {
		if !strings.Contains(out, host) {
			t.Errorf("expected table to contain %s, got:\n%s", host, out)
		}
	}
}

func TestWriteTable_WorstSeverityFirst(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTable(&buf, sampleResults()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	// lines[0] is header; the first data row should be the ERROR host
	// (highest severity rank), and OK should be last.
	if !strings.Contains(lines[1], "bad.example.com") {
		t.Fatalf("expected error host first, got: %s", lines[1])
	}
	last := lines[len(lines)-1]
	if !strings.Contains(last, "ok.example.com") {
		t.Fatalf("expected ok host last, got: %s", last)
	}
}

func TestWriteTable_FlagsShown(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTable(&buf, sampleResults()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "san-mismatch") {
		t.Fatalf("expected san-mismatch flag in output:\n%s", buf.String())
	}
}

func TestWriteTable_DoesNotMutateInput(t *testing.T) {
	results := sampleResults()
	firstHostBefore := results[0].Host
	var buf bytes.Buffer
	_ = WriteTable(&buf, results)
	if results[0].Host != firstHostBefore {
		t.Fatal("expected WriteTable to not mutate input order")
	}
}

func TestWriteJSON_RoundTrips(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleResults()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded []certcheck.Result
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("expected valid JSON: %v\n%s", err, buf.String())
	}
	if len(decoded) != 4 {
		t.Fatalf("expected 4 results, got %d", len(decoded))
	}
}

func TestWriteJSON_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(buf.String()) != "null" && strings.TrimSpace(buf.String()) != "[]" {
		t.Fatalf("unexpected output for empty results: %s", buf.String())
	}
}

func TestWritePrometheus_Format(t *testing.T) {
	var buf bytes.Buffer
	if err := WritePrometheus(&buf, sampleResults()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	want := `certwatch_days_remaining{host="crit.example.com",port="443"}	3`
	if !strings.Contains(out, want) {
		t.Fatalf("expected metric line %q in:\n%s", want, out)
	}
	if strings.Contains(out, `certwatch_days_remaining{host="bad.example.com"`) {
		t.Fatal("expected errored host to be excluded from days_remaining metric")
	}
	if !strings.Contains(out, `certwatch_check_success{host="bad.example.com",port="443"}	0`) {
		t.Fatalf("expected failure metric for bad host, got:\n%s", out)
	}
	if !strings.Contains(out, `certwatch_check_success{host="ok.example.com",port="443"}	1`) {
		t.Fatalf("expected success metric for ok host, got:\n%s", out)
	}
	if !strings.Contains(out, "# HELP certwatch_days_remaining") {
		t.Fatal("expected HELP comment for days_remaining")
	}
	if !strings.Contains(out, "# TYPE certwatch_days_remaining gauge") {
		t.Fatal("expected TYPE comment for days_remaining")
	}
}

func TestWritePrometheus_BooleanFlags(t *testing.T) {
	var buf bytes.Buffer
	if err := WritePrometheus(&buf, sampleResults()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `certwatch_san_mismatch{host="mismatch.example.com",port="443"}	1`) {
		t.Fatalf("expected san_mismatch=1 for mismatch host:\n%s", out)
	}
	if !strings.Contains(out, `certwatch_san_mismatch{host="ok.example.com",port="443"}	0`) {
		t.Fatalf("expected san_mismatch=0 for ok host:\n%s", out)
	}
}

func TestWritePrometheus_ValidMetricNameChars(t *testing.T) {
	var buf bytes.Buffer
	_ = WritePrometheus(&buf, sampleResults())
	for _, line := range strings.Split(buf.String(), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name := strings.SplitN(line, "{", 2)[0]
		if strings.ContainsAny(name, " \t") {
			t.Fatalf("metric name contains invalid whitespace: %q", name)
		}
	}
}
