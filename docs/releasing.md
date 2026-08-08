# Release process

Releases are prepared from a clean source checkout. The scripts in this
repository build and inspect artifacts but never publish them.

`PUBLICATION-PROVENANCE.json` binds this standalone projection to the exact
private controller revision for the mapped protocol and verifier paths. The
repository-local publication controls are separately included in its source-tree
digest. That digest excludes only the provenance manifest itself, avoiding a
self-reference, while the topology verifier embeds and checks the same contract.

`PUBLICATION-HARDENING.json` separately binds the exact public GitHub repository
identity and post-visibility security policy. See
[publication hardening](publication-hardening.md) before changing repository
visibility.

1. Confirm package versions and the Bun version in `package.json`.
2. Install exactly the locked dependency graph with
   `bun install --frozen-lockfile`.
3. Run `bun run ci`, `bun run audit`, and `bun run gitleaks` with the required
   Gitleaks 8.30.1 binary. The scanner self-test must detect its canary before
   the exact current source tree is scanned.
4. Run `bun run pack`.
5. Inspect the two tarballs in `artifacts/packages/` and record their SHA-256
   digests.
6. Test the tarballs in a clean consumer project with Node.js 20 or newer.
7. Review schema and conformance-vector changes for compatibility.
8. Publish only through an approved release workflow with registry provenance
   enabled and least-privilege credentials.

`bun run pack:check` performs the same package-file allowlist checks in a
temporary directory. Generated `dist/`, `artifacts/`, and tarballs are not source
files and must not be committed.

A release is blocked by any failed test, type error, formatting error, boundary
violation, secret finding, disallowed dependency license, vulnerability at the
project's release threshold, unexpected packed file, or unreviewed protocol
compatibility change.

## Repository publication

Keep the repository private while preparing the parentless publication root.
Confirm that the exact `main` commit has successful checks named
`CI / Build, test, and inspect packages` and
`Secret Scan / Gitleaks 8.30.1 exact-tree scan`. Pre-arm the sole temporary
repository secret `PUBLICATION_HARDENING_TOKEN` as documented, then leave the
visibility change to the repository owner. The resulting `public` event applies
and audits the committed policy, proves the stored secret is gone, disables the
hardening workflow, and proves that retirement state. No script here changes
repository visibility.
