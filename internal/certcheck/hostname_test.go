package certcheck

import "testing"

func TestMatchHostname_Exact(t *testing.T) {
	if !MatchHostname("example.com", "example.com") {
		t.Fatal("expected exact match")
	}
}

func TestMatchHostname_CaseInsensitive(t *testing.T) {
	if !MatchHostname("Example.COM", "example.com") {
		t.Fatal("expected case-insensitive match")
	}
}

func TestMatchHostname_TrailingDot(t *testing.T) {
	if !MatchHostname("example.com.", "example.com") {
		t.Fatal("expected trailing dot to be ignored")
	}
}

func TestMatchHostname_Mismatch(t *testing.T) {
	if MatchHostname("example.com", "other.com") {
		t.Fatal("expected mismatch")
	}
}

func TestMatchHostname_Wildcard(t *testing.T) {
	if !MatchHostname("*.example.com", "api.example.com") {
		t.Fatal("expected wildcard match")
	}
}

func TestMatchHostname_WildcardDoesNotMatchBareDomain(t *testing.T) {
	if MatchHostname("*.example.com", "example.com") {
		t.Fatal("wildcard should not match bare apex domain")
	}
}

func TestMatchHostname_WildcardDoesNotMatchMultipleLabels(t *testing.T) {
	if MatchHostname("*.example.com", "a.b.example.com") {
		t.Fatal("wildcard should not match multiple sub-levels")
	}
}

func TestMatchHostname_WildcardOnlyLeftmost(t *testing.T) {
	if MatchHostname("api.*.com", "api.example.com") {
		t.Fatal("only leftmost label wildcard should be supported")
	}
}

func TestMatchHostname_EmptyInputs(t *testing.T) {
	if MatchHostname("", "example.com") {
		t.Fatal("empty SAN should never match")
	}
	if MatchHostname("example.com", "") {
		t.Fatal("empty host should never match")
	}
}

func TestAnyHostnameMatch(t *testing.T) {
	sans := []string{"other.com", "*.example.com"}
	if !AnyHostnameMatch(sans, "api.example.com") {
		t.Fatal("expected match against second SAN")
	}
	if AnyHostnameMatch(sans, "nomatch.org") {
		t.Fatal("expected no match")
	}
}

func TestAnyHostnameMatch_Empty(t *testing.T) {
	if AnyHostnameMatch(nil, "example.com") {
		t.Fatal("no SANs should never match")
	}
}
