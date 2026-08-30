package certcheck

import "testing"

func TestSeverityString(t *testing.T) {
	cases := map[Severity]string{
		SeverityOK:          "ok",
		SeverityNotice:      "notice",
		SeverityWarning:     "warning",
		SeverityCritical:    "critical",
		SeverityNotYetValid: "not-yet-valid",
		SeverityExpired:     "expired",
		SeverityError:       "error",
	}
	for sev, want := range cases {
		if got := sev.String(); got != want {
			t.Errorf("Severity(%d).String() = %q, want %q", sev, got, want)
		}
	}
}

func TestSeverityString_Unknown(t *testing.T) {
	if got := Severity(99).String(); got != "unknown" {
		t.Fatalf("expected unknown, got %q", got)
	}
}

func TestParseSeverity(t *testing.T) {
	for _, name := range []string{"ok", "notice", "warning", "critical", "not-yet-valid", "expired", "error"} {
		sev, ok := ParseSeverity(name)
		if !ok {
			t.Fatalf("expected %q to parse", name)
		}
		if sev.String() != name {
			t.Fatalf("round-trip failed for %q: got %q", name, sev.String())
		}
	}
}

func TestParseSeverity_Invalid(t *testing.T) {
	if _, ok := ParseSeverity("bogus"); ok {
		t.Fatal("expected bogus severity to fail parsing")
	}
}

func TestSeverityOrdering(t *testing.T) {
	ordered := []Severity{SeverityOK, SeverityNotice, SeverityWarning, SeverityCritical, SeverityNotYetValid, SeverityExpired, SeverityError}
	for i := 1; i < len(ordered); i++ {
		if !(ordered[i-1] < ordered[i]) {
			t.Fatalf("expected %s < %s", ordered[i-1], ordered[i])
		}
	}
}
