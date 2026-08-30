# certwatch

Monitor TLS certificate expiry across a fleet of hosts, with tiered lead
times, state tracking between runs, and alerting-friendly output.

## What

certwatch checks a whole inventory of hosts concurrently, classifies each
certificate's remaining validity into a configurable severity tier
(critical / warning / notice / ok, plus dedicated expired and
not-yet-valid states), flags hostname mismatches, self-signed leafs, and
incomplete certificate chains, and tracks state between runs so it can
report what's newly broken, what got fixed, and whether a certificate was
unexpectedly re-issued by a different CA.

It outputs a human-readable table, JSON for other tooling, and Prometheus
textfile-collector metrics for node_exporter, and exits non-zero when
anything is at or above a configurable severity threshold — so it drops
straight into cron or a CI pipeline.

## Why

Certificate expiry still takes down production regularly. The failure mode
is almost never "nobody knew certificates expire" — it's that the alert
arrived on the day it expired, or it went to a mailbox nobody reads, or
the one-off script that used to check this quietly stopped being run.
certwatch is built to be the thing that actually runs on a schedule, checks
everything, gives enough lead time to rotate before it's an emergency, and
is quiet the rest of the time.

## How it differs from a one-shot TLS checker

This is deliberately **not** a deep single-endpoint TLS auditor. If you
want chain validation depth, cipher suite analysis, protocol version
checks, and weak-algorithm detection for one endpoint at a time, use a tool
built for that (in this author's other projects, that's `tlsprobe`).

certwatch's job is different: **breadth over depth**. It exists to answer
"across my whole fleet, on a schedule, what's about to expire, what
changed since last time, and who do I tell?" It checks many hosts
concurrently, tracks state between runs, and routes results toward alerting
and monitoring systems (Prometheus, exit codes, JSON for a notifier). It
does not attempt to grade your TLS configuration.

## Features

- **Inventory file** (YAML or JSON): hosts with optional port, SNI
  override, owner/team tags, and per-host lead-time overrides.
- **Concurrent checks** with a bounded worker pool, a per-host timeout, and
  a total run deadline. One unreachable host never stalls or fails the
  rest of the run.
- **Tiered severity by days remaining**, configurable per-inventory and
  per-host, defaulting to critical < 7 days, warning < 30 days, notice <
  60 days — plus dedicated `expired` and `not-yet-valid` states (a real and
  confusing failure mode when a certificate is issued with a future
  `notBefore`).
- **Hostname/SAN mismatch detection**, including wildcard SAN matching.
- **Self-signed certificate detection.**
- **Incomplete chain detection** (server presents only the leaf, no
  intermediates, despite being CA-issued).
- **CA/serial change detection** between runs, catching an unexpected
  re-issue even when the new certificate is otherwise perfectly healthy.
- **State file** between runs enabling new-problem / resolved-problem /
  CA-change reporting — this is what makes it a monitor, not a one-shot
  script.
- **Table, JSON, and Prometheus textfile output.**
- **`--only-changed`** so a scheduled run stays quiet when nothing changed.
- **Configurable `--fail-on` exit code threshold** for cron/CI.

## Architecture

```
cmd/certwatch        CLI entry point: flag parsing, orchestration, exit code
internal/inventory   Inventory file model, YAML/JSON loading, validation
internal/certcheck   Fetcher interface + real TLS fetcher, severity
                      evaluation, SAN matching, concurrent runner
internal/state       Persisted state file, new/resolved/CA-change diffing
internal/report      Table, JSON, and Prometheus output rendering
```

Certificate fetching lives behind a small `Fetcher` interface
(`Fetch(ctx, Host) (CertInfo, error)`). Everything downstream of that
boundary — severity tiering, SAN matching, self-signed/chain-incomplete
classification, state diffing, and reporting — is plain data transformation
and is unit-tested without any network access, using certificates generated
in-memory with `crypto/x509` and `crypto/ecdsa`. The real fetcher
(`certcheck.TLSFetcher`) dials over TLS with certificate verification
disabled (on purpose — evaluating a broken certificate is the whole point)
and hands the parsed leaf to the same evaluation code.

## Installation

Requires Go 1.22+.

```sh
go install certwatch/cmd/certwatch@latest
```

Or build from source:

```sh
git clone https://github.com/hellpuffyt/certwatch.git
cd certwatch
go build -o certwatch ./cmd/certwatch
```

## Usage

```sh
certwatch -inventory inventory.yaml [flags]
```

| Flag              | Default                | Description                                                                 |
|-------------------|-------------------------|-------------------------------------------------------------------------------|
| `-inventory`      | *(required)*             | Path to the inventory file (YAML or JSON).                                    |
| `-state`          | `certwatch-state.json`  | Path to the state file used to diff against the previous run.                 |
| `-no-state`       | `false`                 | Skip loading/saving state (disables new/resolved/CA-change tracking).         |
| `-format`         | `table`                  | Output format: `table`, `json`, or `prometheus`.                              |
| `-output`         | *(stdout)*               | Write primary output to a file instead of stdout.                             |
| `-prometheus-out` | *(none)*                 | Additionally write Prometheus textfile metrics to this path.                  |
| `-concurrency`    | `10`                     | Maximum concurrent host checks.                                               |
| `-host-timeout`   | `10s`                    | Per-host check timeout.                                                       |
| `-deadline`       | `60s`                    | Overall deadline for the whole run.                                           |
| `-fail-on`        | `critical`               | Minimum severity that causes a non-zero exit: `ok`, `notice`, `warning`, `critical`, `not-yet-valid`, `expired`, `error`. |
| `-only-changed`   | `false`                  | Suppress table/json output when nothing changed since the last run.           |
| `-version`        | —                        | Print version and exit.                                                       |

Exit codes: `0` nothing at or above the fail-on threshold, `1` something
is, `2` usage or configuration error (bad flags, unreadable inventory,
unwritable state file).

## Inventory format

```yaml
defaults:
  critical_days: 7
  warning_days: 30
  notice_days: 60

hosts:
  - name: example.com          # required: dial target and default SNI
    owner: platform-team       # optional: free-text owner tag
    team: platform             # optional: free-text team tag

  - name: lb-internal.example.net
    port: 8443                 # optional: default 443
    sni: checkout.example.com  # optional: override SNI / expected hostname
    owner: payments-team
    lead_times:                # optional: per-host override of defaults
      critical_days: 14
      warning_days: 45
      notice_days: 90
```

JSON inventories use the same shape (`{"defaults": {...}, "hosts": [...]}`)
and are selected automatically by a `.json` file extension.

See [`examples/inventory.yaml`](examples/inventory.yaml) for a fuller
example.

## Alerting

certwatch doesn't send alerts itself — it's designed to be the check step
in something that does:

- **Cron + exit code**: run on a schedule with `-fail-on critical`; a
  non-zero exit from cron is picked up by whatever your cron wrapper
  already does with failures (mail, a dead-man's-switch ping, etc).
- **CI pipeline**: same idea — fail the job, let your existing pipeline
  notification path carry it.
- **`-format json`**: pipe into a small script or webhook call that posts
  to Slack/PagerDuty/etc, keyed on `severity` and `host`.
- **`-only-changed`**: run frequently without spamming — output (and thus
  whatever's downstream of it) is only produced when something is newly
  broken, newly resolved, or the CA/serial changed.

## Prometheus

`-format prometheus` or `-prometheus-out <path>` writes node_exporter
textfile-collector-compatible metrics:

```
# HELP certwatch_days_remaining Days until certificate expiry (negative if already expired).
# TYPE certwatch_days_remaining gauge
certwatch_days_remaining{host="example.com",port="443"} 42
# HELP certwatch_check_success Whether the certificate check for this host succeeded (1) or failed (0).
# TYPE certwatch_check_success gauge
certwatch_check_success{host="example.com",port="443"} 1
# HELP certwatch_severity_rank Severity of the certificate check, as an ordinal rank (0=ok ... 6=error).
# TYPE certwatch_severity_rank gauge
certwatch_severity_rank{host="example.com",port="443",severity="ok"} 0
# HELP certwatch_san_mismatch Whether the requested hostname is absent from the certificate's SANs.
# TYPE certwatch_san_mismatch gauge
certwatch_san_mismatch{host="example.com",port="443"} 0
# HELP certwatch_self_signed Whether the certificate is self-signed.
# TYPE certwatch_self_signed gauge
certwatch_self_signed{host="example.com",port="443"} 0
# HELP certwatch_chain_incomplete Whether the server served the leaf certificate without intermediates.
# TYPE certwatch_chain_incomplete gauge
certwatch_chain_incomplete{host="example.com",port="443"} 0
```

Point node_exporter's `--collector.textfile.directory` at wherever
`-prometheus-out` writes, on a matching schedule.

## Examples

Check a fleet, print a table, and fail CI on anything critical or worse:

```sh
certwatch -inventory inventory.yaml -fail-on critical
```

Quiet cron run that only produces output when something changed, plus a
metrics file for node_exporter:

```sh
certwatch -inventory inventory.yaml \
  -state /var/lib/certwatch/state.json \
  -only-changed \
  -prometheus-out /var/lib/node_exporter/textfile/certwatch.prom
```

Machine-readable output for a custom alert router:

```sh
certwatch -inventory inventory.yaml -format json -output results.json
```

## Testing

```sh
go build ./...
go vet ./...
go test ./...
gofmt -l .   # must print nothing
```

All severity, tiering, hostname-matching, state-diffing, and reporting
logic is tested offline using certificates generated at test time with
`crypto/x509` and `crypto/ecdsa` — no network access or committed key
material is required. A handful of `cmd/certwatch` tests spin up a local
loopback TLS listener to exercise the CLI end to end; CI additionally runs
a smoke job against real public hosts to confirm the network path works.

## Security

- certwatch's real fetcher connects with certificate verification disabled
  on purpose (`InsecureSkipVerify`) — its entire job is to evaluate
  certificates that may be invalid, expired, or otherwise broken. It does
  no other TLS configuration analysis and should not be used as a
  substitute for a properly verifying HTTP client elsewhere in your stack.
- No private key material is ever generated for or required by production
  use; test certificates are generated in-memory per test run and never
  written to disk.
- State and metrics files are written with `0600` permissions.
- certwatch makes outbound network connections only to the hosts you list
  in your inventory.

## License

MIT. See [LICENSE](LICENSE).
