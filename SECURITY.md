# Security policy

## Supported version

The current `3.x` release line receives security fixes. Pre-release candidates
receive best-effort fixes until a corresponding release is published.

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue, discussion, or pull
request. Use the private security-reporting facility on the canonical repository
host. If that facility is unavailable, contact a maintainer through an existing
private project channel and request a secure reporting route before sharing
sensitive details.

The committed post-public hardening policy enables private vulnerability
reporting, dependency alerts and security updates, Advanced Security, secret
scanning, and push protection. See
[docs/publication-hardening.md](docs/publication-hardening.md).

Include:

- the affected package and exact version or commit;
- a minimal reproduction or malformed artifact;
- the expected and observed security properties;
- the practical impact and any known preconditions; and
- whether the report contains private identity material or live credentials.

Remove real voter data, private keys, access tokens, and production attestations
unless a maintainer explicitly provides an approved encrypted channel. Synthetic
artifacts are strongly preferred.

Maintainers will acknowledge a complete report as soon as practical, assess
severity, coordinate a fix and disclosure window, and credit reporters who want
attribution. No response-time guarantee is made.

## Security-sensitive changes

Changes to canonicalization, hash construction, signature verification, WebAuthn
binding, certificate validation, policy pinning, transparency proofs, or tally
replay need focused tests and review. Compatibility must never be restored by
silently accepting ambiguous encodings or unknown signed fields.
