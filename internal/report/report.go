// Package report renders certwatch check results as a human table, JSON,
// or Prometheus textfile metrics.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"certwatch/internal/certcheck"
)

// WriteTable renders results as an aligned, human-readable table sorted by
// severity (worst first) then host name.
func WriteTable(w io.Writer, results []certcheck.Result) error {
	sorted := sortedForDisplay(results)

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tPORT\tSEVERITY\tDAYS\tISSUER\tFLAGS")
	for _, r := range sorted {
		flags := flagString(r)
		days := fmt.Sprintf("%d", r.DaysRemaining)
		issuer := r.Issuer
		if r.Severity == certcheck.SeverityError {
			days = "-"
			issuer = r.Error
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\n", r.Host, r.Port, strings.ToUpper(r.Severity.String()), days, issuer, flags)
	}
	return tw.Flush()
}

func flagString(r certcheck.Result) string {
	var flags []string
	if r.SANMismatch {
		flags = append(flags, "san-mismatch")
	}
	if r.SelfSigned {
		flags = append(flags, "self-signed")
	}
	if r.ChainIncomplete {
		flags = append(flags, "chain-incomplete")
	}
	if len(flags) == 0 {
		return "-"
	}
	return strings.Join(flags, ",")
}

// sortedForDisplay returns a copy of results ordered worst-severity-first,
// then alphabetically by host, without mutating the input slice.
func sortedForDisplay(results []certcheck.Result) []certcheck.Result {
	sorted := make([]certcheck.Result, len(results))
	copy(sorted, results)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Severity != sorted[j].Severity {
			return sorted[i].Severity > sorted[j].Severity
		}
		if sorted[i].Host != sorted[j].Host {
			return sorted[i].Host < sorted[j].Host
		}
		return sorted[i].Port < sorted[j].Port
	})
	return sorted
}

// WriteJSON renders results as a JSON array with stable, indented
// formatting suitable for both human inspection and machine consumption.
func WriteJSON(w io.Writer, results []certcheck.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

// WritePrometheus renders results as Prometheus textfile-collector metrics
// for node_exporter. It emits certwatch_days_remaining, a per-severity
// certwatch_check_severity gauge (1 for the active severity, encoded as its
// rank), and boolean flags for SAN mismatch, self-signed, and incomplete
// chain, each labeled by host and port.
func WritePrometheus(w io.Writer, results []certcheck.Result) error {
	sorted := sortedForDisplay(results)

	fmt.Fprintln(w, "# HELP certwatch_days_remaining Days until certificate expiry (negative if already expired).")
	fmt.Fprintln(w, "# TYPE certwatch_days_remaining gauge")
	for _, r := range sorted {
		if r.Severity == certcheck.SeverityError {
			continue
		}
		fmt.Fprintf(w, "certwatch_days_remaining{host=%q,port=%q}\t%d\n", r.Host, portLabel(r.Port), r.DaysRemaining)
	}

	fmt.Fprintln(w, "# HELP certwatch_check_success Whether the certificate check for this host succeeded (1) or failed (0).")
	fmt.Fprintln(w, "# TYPE certwatch_check_success gauge")
	for _, r := range sorted {
		v := 1
		if r.Severity == certcheck.SeverityError {
			v = 0
		}
		fmt.Fprintf(w, "certwatch_check_success{host=%q,port=%q}\t%d\n", r.Host, portLabel(r.Port), v)
	}

	fmt.Fprintln(w, "# HELP certwatch_severity_rank Severity of the certificate check, as an ordinal rank (0=ok ... 6=error).")
	fmt.Fprintln(w, "# TYPE certwatch_severity_rank gauge")
	for _, r := range sorted {
		fmt.Fprintf(w, "certwatch_severity_rank{host=%q,port=%q,severity=%q}\t%d\n", r.Host, portLabel(r.Port), r.Severity.String(), int(r.Severity))
	}

	fmt.Fprintln(w, "# HELP certwatch_san_mismatch Whether the requested hostname is absent from the certificate's SANs.")
	fmt.Fprintln(w, "# TYPE certwatch_san_mismatch gauge")
	for _, r := range sorted {
		fmt.Fprintf(w, "certwatch_san_mismatch{host=%q,port=%q}\t%s\n", r.Host, portLabel(r.Port), boolMetric(r.SANMismatch))
	}

	fmt.Fprintln(w, "# HELP certwatch_self_signed Whether the certificate is self-signed.")
	fmt.Fprintln(w, "# TYPE certwatch_self_signed gauge")
	for _, r := range sorted {
		fmt.Fprintf(w, "certwatch_self_signed{host=%q,port=%q}\t%s\n", r.Host, portLabel(r.Port), boolMetric(r.SelfSigned))
	}

	fmt.Fprintln(w, "# HELP certwatch_chain_incomplete Whether the server served the leaf certificate without intermediates.")
	fmt.Fprintln(w, "# TYPE certwatch_chain_incomplete gauge")
	for _, r := range sorted {
		fmt.Fprintf(w, "certwatch_chain_incomplete{host=%q,port=%q}\t%s\n", r.Host, portLabel(r.Port), boolMetric(r.ChainIncomplete))
	}

	return nil
}

func portLabel(p int) string {
	return fmt.Sprintf("%d", p)
}

func boolMetric(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
