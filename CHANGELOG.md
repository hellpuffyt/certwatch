# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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
