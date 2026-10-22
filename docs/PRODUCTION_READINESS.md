# Production readiness — certwatch

Audit of the `audit/production-readiness` branch. Evidence only; the
classification at the end is a proposal for the maintainer to confirm.

- Tested commit: `ca377cc18bfb7980c682f5b4c6d3c868cd14350c` (this file was
  added in the next commit and changes no code)
- Date: 2026-10-22
- Host: macOS 27 (Apple Silicon), Go 1.27.3. `go.mod` declares `go 1.22`.

## Scope

A CLI that checks TLS certificate expiry for an inventory of hosts
concurrently, classifies each into severity tiers, flags SAN mismatch,
self-signed and leaf-only chains, keeps a state file to report new /
resolved / CA-or-serial changes between runs, and writes table, JSON or
Prometheus textfile output with a threshold-based exit code. One external
dependency (`gopkg.in/yaml.v3`). It does not send alerts or audit TLS
configuration.

## Platforms and prerequisites

- Go 1.22+. Verified locally on macOS arm64.
- CI: Go 1.22/1.23 on ubuntu and Windows, Go 1.23 on macOS; not yet run on
  this branch.
- No network access is needed for `go test ./...`: every TLS test uses a
  listener on 127.0.0.1 with certificates generated in memory. The CI
  `smoke` job (real public hosts) is separate from the test job.

## Clean-clone verification

Fresh clone of the branch into an empty scratch directory; README "Build
from source" and "Testing" followed literally, then the CLI against a
local `openssl s_server` (self-signed, 20 days, SAN `localhost` +
`127.0.0.1`) plus a port where nothing listens:

| Command | Exit | Result |
|---|---|---|
| `go build -o certwatch ./cmd/certwatch` | 0 | |
| `go build ./...`, `go vet ./...` | 0 | |
| `go test ./...` | 0 | 115 passed, 0 failed, 0 skipped (tests and subtests) |
| `gofmt -l .` | 0 | no output |
| `certwatch -inventory inv.yaml -state state.json -fail-on critical` | 1 | `WARNING 19 CN=localhost self-signed`; `ERROR ... connection refused` (error ranks above critical) |
| same with `-only-changed` | 1 | no output (nothing changed) |
| `... -format json -fail-on warning -prometheus-out m.prom` | 1 | JSON with `san_mismatch: false` for the IP host; metrics file written |
| `ls -l` | 0 | `state.json` `-rw-------`, `m.prom` `-rw-r--r--` |

`go install certwatch/cmd/certwatch@latest` (the README command before the
audit) fails with `malformed module path ... missing dot in first path
element`; `go install ./cmd/certwatch` with the corrected module path
builds a working binary (`certwatch 0.1.0`). The `@latest` form resolves
only once this branch is on the default branch.

## Commands executed (working clone)

| Command | Exit | Outcome |
|---|---|---|
| `go build ./...`, `go vet ./...`, `gofmt -l .` | 0 | clean |
| `go test -race -count=1 -v ./...` (baseline) | 0 | 105 passed, 0 failed, 0 skipped |
| `go test -race -count=1 -v ./...` (after) | 0 | 115 passed, 0 failed, 0 skipped |
| `go run honnef.co/go/tools/cmd/staticcheck@latest ./...` (v0.8.2) | 0 | no findings |
| `go run golang.org/x/vuln/cmd/govulncheck@latest ./...` (v1.9.0) | 0 | No vulnerabilities found |
| `go mod verify` | 0 | all modules verified |
| `go run github.com/zricethezav/gitleaks/v8@latest git --redact .` | 0 | no leaks in any commit |

Each regression test below was run against the pre-fix code and failed.

## CI status

- Default branch (`main`): last run `success`.
- Audit branch: pending until pushed.

## Bugs found and fixed

| # | Severity | Bug | Fix | Regression test |
|---|---|---|---|---|
| 1 | High (install broken) | Module path `certwatch`: the README's `go install` cannot work. | Module path `github.com/hellpuffyt/certwatch`. | build + `go install ./cmd/certwatch` |
| 2 | Medium (wrong result) | Hosts addressed by IP were always `san-mismatch` (only DNS SANs consulted); the existing CLI tests worked around it with `sni: localhost`. | Match IP targets against IP SANs. | `TestMatchesTargetUsesIPSANsForIPTargets`, `TestRun_IPHostMatchesIPSAN` |
| 3 | Medium (lost alerts) | An invalid `-format`, or a failed `-output` / `-prometheus-out` write, was detected after the state file had been rewritten, so that run's changes were never reported. | Validate `-format` first; save state last. | `TestRun_StateNotSavedWhenOutputFails` |
| 4 | Medium (data loss) | State and metrics written in place: a crash mid-write left a truncated state file (every later run exits 2) and node_exporter could read partial metrics. | Temp file + rename. | `TestWriteFailureLeavesOldFile`, `TestWriteReplacesAndKeepsPermissions` |
| 5 | Medium (alert noise) | An unreachable host was reported as a new problem on every run, defeating `-only-changed`. | Record outages in state as `error`, keeping certificate history. One existing test expectation changed (justified in the test). | `TestOutageIsReportedOnceThenResolved`, `TestRun_OnlyChangedQuietDuringOutage` |
| 6 | Docs | README said metrics files are written `0600` (they are `0644`, which node_exporter needs). | README corrected. | clean-clone `ls -l` |

Coverage added for advertised behaviour that had no direct test: the real
`TLSFetcher` against loopback listeners (full chain vs leaf-only, expired,
not-yet-valid, wrong name, silent server timing out).

## Security review

- Outbound connections only to inventory hosts; verification disabled by
  design and documented; no data sent after the handshake.
- Inputs: inventory (trusted operator input), state file (own output).
  JSON inventories reject unknown fields; YAML ignores them (documented).
- Files: state `0600`, metrics `0644`, both atomic.
- Resource use: bounded worker pool, per-host timeout, run deadline
  (`TestTLSFetcherTimesOutOnSilentServer`, runner tests).
- Secrets: none in tree or history (gitleaks). Test keys are generated in
  memory at run time.
- Added `SECURITY.md` with the private advisory link.

## Known limitations

- Only the leaf's expiry is evaluated; intermediates are not.
- `chain-incomplete` is a heuristic (no chain building).
- Severity escalation inside the problem range (warning → critical) is not
  reported by `-only-changed`; the exit code still reflects it.
- Prometheus label values are written with Go quoting; host names with
  control characters would produce invalid exposition text.
- Linux/Windows rely on CI.

## Acceptance checklist

| Item | Expected behaviour | Command / test | Result | Actual | Reference |
|---|---|---|---|---|---|
| Install | Documented install/build works | clean clone; `go install ./cmd/certwatch` | pass | binary prints `certwatch 0.1.0` | `go.mod` |
| Severity tiers | Boundaries per lead times; expired / not-yet-valid states | `evaluate_test.go`, `severity_test.go`, `TestTLSFetcherFetchesBrokenCertificates` | pass | | `evaluate.go` |
| SAN matching | Wildcards; IP SANs for IP hosts | `hostname_test.go`, `TestRun_IPHostMatchesIPSAN` | pass | | `hostname.go` |
| Self-signed / leaf-only chain | Flags set from a real handshake | `TestTLSFetcherReportsChainCompleteness`, CLI run | pass | `self-signed` flag on s_server cert | `fetch.go` |
| Concurrency and timeouts | One bad host never stalls the run | runner tests, `TestTLSFetcherTimesOutOnSilentServer`, `TestRun_UnreachableHostDoesNotCrash` | pass | | `runner.go` |
| State diffing | New / resolved / CA / serial change; outages reported once | `state_test.go`, `TestRun_OnlyChangedQuietDuringOutage` | pass | | `state.go` |
| Output formats | Table, JSON, Prometheus | report tests, CLI JSON/Prometheus tests, clean-clone run | pass | | `report.go` |
| Exit codes | 0 / 1 by `-fail-on`, 2 on usage or I/O error | CLI tests | pass | | `main.go` |
| No public network in tests | `go test ./...` uses loopback only | code review of tests | pass | all listeners on 127.0.0.1 | `*_test.go` |
| Static analysis / deps | vet, staticcheck, govulncheck clean | above | pass | | |

## Classification proposal

**Production-Ready for Its Documented Scope** — proposed, pending
independent verification and the CI matrix on this branch.
