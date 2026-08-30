// Command certwatch monitors TLS certificate expiry across a fleet of
// hosts, applies tiered lead-time severities, tracks state between runs,
// and reports in table, JSON, or Prometheus textfile format.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"certwatch/internal/certcheck"
	"certwatch/internal/inventory"
	"certwatch/internal/report"
	"certwatch/internal/state"
)

const version = "0.1.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("certwatch", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		inventoryPath  = fs.String("inventory", "", "path to the inventory file (YAML or JSON) [required]")
		statePath      = fs.String("state", "certwatch-state.json", "path to the state file used to diff against the previous run")
		noState        = fs.Bool("no-state", false, "skip loading/saving state (disables new/resolved/CA-change tracking)")
		format         = fs.String("format", "table", "output format: table, json, or prometheus")
		outputPath     = fs.String("output", "", "write primary output to this file instead of stdout")
		prometheusOut  = fs.String("prometheus-out", "", "additionally write Prometheus textfile metrics to this path")
		concurrency    = fs.Int("concurrency", 10, "maximum concurrent host checks")
		hostTimeout    = fs.Duration("host-timeout", 10*time.Second, "per-host check timeout")
		deadline       = fs.Duration("deadline", 60*time.Second, "overall deadline for the whole run")
		failOn         = fs.String("fail-on", "critical", "minimum severity that causes a non-zero exit code (ok, notice, warning, critical, not-yet-valid, expired, error)")
		onlyChanged    = fs.Bool("only-changed", false, "suppress table/json output when nothing changed since the last run")
		showVersion    = fs.Bool("version", false, "print version and exit")
		nowOverrideStr = fs.String("now", "", "override the reference time (RFC3339) for evaluation; primarily for testing")
	)

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		fmt.Fprintln(stdout, "certwatch", version)
		return 0
	}

	if *inventoryPath == "" {
		fmt.Fprintln(stderr, "certwatch: -inventory is required")
		fs.Usage()
		return 2
	}

	failSeverity, ok := certcheck.ParseSeverity(*failOn)
	if !ok {
		fmt.Fprintf(stderr, "certwatch: invalid -fail-on value %q\n", *failOn)
		return 2
	}

	now := time.Now()
	if *nowOverrideStr != "" {
		parsed, err := time.Parse(time.RFC3339, *nowOverrideStr)
		if err != nil {
			fmt.Fprintf(stderr, "certwatch: invalid -now value: %v\n", err)
			return 2
		}
		now = parsed
	}

	inv, err := inventory.Load(*inventoryPath)
	if err != nil {
		fmt.Fprintf(stderr, "certwatch: %v\n", err)
		return 2
	}

	var prevState *state.State
	if *noState {
		prevState = state.New()
	} else {
		prevState, err = state.Load(*statePath)
		if err != nil {
			fmt.Fprintf(stderr, "certwatch: %v\n", err)
			return 2
		}
	}

	fetcher := certcheck.TLSFetcher{DialTimeout: *hostTimeout}
	opts := certcheck.RunOptions{
		Concurrency:    *concurrency,
		PerHostTimeout: *hostTimeout,
		Deadline:       *deadline,
		Defaults:       inv.Defaults,
		Now:            now,
	}

	results := certcheck.Run(context.Background(), fetcher, inv.Hosts, opts)
	diffs := state.Compare(prevState, results)

	if !*noState {
		next := state.MergeForward(prevState, results)
		if err := next.Save(*statePath); err != nil {
			fmt.Fprintf(stderr, "certwatch: %v\n", err)
			return 2
		}
	}

	anyChanged := false
	for _, d := range diffs {
		if d.Changed() {
			anyChanged = true
			break
		}
	}

	suppress := *onlyChanged && !anyChanged

	if !suppress {
		out := stdout
		var closeFn func()
		if *outputPath != "" {
			f, err := os.Create(*outputPath)
			if err != nil {
				fmt.Fprintf(stderr, "certwatch: %v\n", err)
				return 2
			}
			out = f
			closeFn = func() { f.Close() }
		}

		var writeErr error
		switch *format {
		case "table":
			writeErr = report.WriteTable(out, results)
		case "json":
			writeErr = report.WriteJSON(out, results)
		case "prometheus":
			writeErr = report.WritePrometheus(out, results)
		default:
			fmt.Fprintf(stderr, "certwatch: unknown -format %q (want table, json, or prometheus)\n", *format)
			if closeFn != nil {
				closeFn()
			}
			return 2
		}
		if closeFn != nil {
			closeFn()
		}
		if writeErr != nil {
			fmt.Fprintf(stderr, "certwatch: writing output: %v\n", writeErr)
			return 2
		}
	}

	if *prometheusOut != "" {
		f, err := os.Create(*prometheusOut)
		if err != nil {
			fmt.Fprintf(stderr, "certwatch: %v\n", err)
			return 2
		}
		werr := report.WritePrometheus(f, results)
		cerr := f.Close()
		if werr != nil {
			fmt.Fprintf(stderr, "certwatch: writing prometheus metrics: %v\n", werr)
			return 2
		}
		if cerr != nil {
			fmt.Fprintf(stderr, "certwatch: %v\n", cerr)
			return 2
		}
	}

	for _, r := range results {
		if r.Severity >= failSeverity {
			return 1
		}
	}
	return 0
}
