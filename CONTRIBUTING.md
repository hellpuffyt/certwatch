# Contributing

Thanks for considering a contribution to certwatch.

## Development setup

certwatch is a standard Go module; you need Go 1.22 or later.

```sh
go build ./...
go vet ./...
go test ./...
gofmt -l .   # must print nothing
```

## Guidelines

- Keep certificate-fetching behind the `certcheck.Fetcher` interface. All
  severity, tiering, state-diffing, and SAN-matching logic should be
  testable without a network connection.
- Never commit private keys or real certificate material. Tests generate
  their own throwaway certificates at runtime with `crypto/x509` and
  `crypto/ecdsa`.
- Add tests for new behavior, especially at severity tier boundaries (e.g.
  exactly N vs N+1 days remaining) and for concurrency/failure handling.
- Run `gofmt -l .` before submitting; CI enforces it.
- Keep changes scoped: certwatch is a fleet-wide expiry monitor, not a
  single-endpoint TLS configuration auditor. Deep protocol/cipher/chain
  analysis belongs in a different tool.

## Submitting changes

1. Fork the repository and create a feature branch.
2. Make your change with tests.
3. Ensure `go build ./...`, `go vet ./...`, `go test ./...`, and
   `gofmt -l .` all pass cleanly.
4. Open a pull request describing the change and why it's needed.

## Reporting issues

Please include your Go version, OS, a redacted inventory snippet if
relevant, and the exact command you ran.
