# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's advisory form:
https://github.com/hellpuffyt/certwatch/security/advisories/new

Include the certwatch version (`certwatch -version`), the command line, and
a minimal inventory that reproduces the problem. Please do not open a
public issue for a suspected vulnerability.

## Security model

- certwatch connects only to the hosts listed in the inventory you give it.
  The inventory is trusted input: whoever can edit it decides where
  certwatch connects.
- TLS verification is disabled on purpose (`InsecureSkipVerify`) because
  the tool must inspect expired, self-signed and mismatched certificates.
  No application data is sent over those connections; certwatch closes the
  connection after the handshake.
- No private keys are read or generated in normal operation. Tests
  generate throwaway keys in memory.
- The state file (`0600`) records host names, issuers, serial numbers and
  expiry dates. Metrics files (`0644`) contain host names and flags.

Only the latest release receives fixes.
