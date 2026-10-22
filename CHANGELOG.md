# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Fixed

- `go install` now works: the module path is
  `github.com/hellpuffyt/certwatch` (it was `certwatch`, which the Go tool
  rejects as a module path).
- Hosts addressed by IP address are matched against the certificate's IP
  SANs; they were always reported as `san-mismatch`.
- An invalid `-format` is rejected before any host is checked, and the
  state file is written only after all output succeeded, so a failed run no
  longer swallows that run's new/resolved/CA-change events.
- The state file and `-prometheus-out` are written atomically
  (temp file + rename).

### Changed

- README: corrected the file-permission statement (metrics are `0644`, not
  `0600`) and added a Limitations section.

### Added

- Loopback TLS tests for the real fetcher (chain completeness, expired,
  not-yet-valid, wrong name, silent server).

## [0.1.0] - 2026-08-30

### Added

- Initial release of certwatch.
- Concurrent inventory checking with a bounded worker pool, per-host
  timeout, and overall run deadline.
- Tiered severity classification (critical/warning/notice/ok) with
  configurable, per-host-overridable lead times, plus dedicated expired and
  not-yet-valid states.
- Hostname/SAN mismatch, self-signed, and incomplete-chain detection.
- State file tracking between runs: new problems, resolved problems, and
  CA/serial change detection.
- Table, JSON, and Prometheus textfile output formats.
- `--only-changed` for quiet scheduled runs.
- `--fail-on` configurable exit-code threshold for cron/CI use.
