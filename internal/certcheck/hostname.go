package certcheck

import "strings"

// MatchHostname reports whether host matches the SAN entry, supporting a
// single leftmost wildcard label ("*.example.com") per RFC 6125 as commonly
// implemented by browsers and Go's crypto/x509. It is case-insensitive and
// strips a single trailing dot from both sides.
func MatchHostname(san, host string) bool {
	san = strings.ToLower(strings.TrimSuffix(san, "."))
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if san == "" || host == "" {
		return false
	}
	if !strings.Contains(san, "*") {
		return san == host
	}

	sanLabels := strings.Split(san, ".")
	hostLabels := strings.Split(host, ".")
	if len(sanLabels) != len(hostLabels) {
		return false
	}
	if sanLabels[0] != "*" {
		// Only a full-label leftmost wildcard is supported, matching
		// standard TLS validator behavior (no partial-label wildcards).
		return false
	}
	for i := 1; i < len(sanLabels); i++ {
		if sanLabels[i] != hostLabels[i] {
			return false
		}
	}
	// Wildcards must not match the bare label position being empty and
	// must not match multiple sub-levels (handled above via label count).
	return hostLabels[0] != ""
}

// AnyHostnameMatch reports whether host matches any of the given SAN
// entries.
func AnyHostnameMatch(sans []string, host string) bool {
	for _, s := range sans {
		if MatchHostname(s, host) {
			return true
		}
	}
	return false
}
