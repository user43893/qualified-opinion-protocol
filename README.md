# Qualified Opinion Protocol

Run a vote among a vetted group and publish results anyone can re-check —
without revealing who voted for what. This repository holds the protocol
specification, its TypeScript implementation, and a command-line verifier
that works completely offline.

The idea in one paragraph: who may vote is published as a signed list, so
anyone can audit the electorate. Each ballot is recorded with a chain of
signatures proving it was cast by an authorized voter, for exactly one
question, and accepted into a tamper-evident log. The published record never
contains a voter's name or anything that links their ballots across
questions. From the published files alone, an auditor can recompute the
tally and confirm it matches the announced result.

Two packages:

| Package | Purpose |
| --- | --- |
| `@qualified-opinion/protocol` | data formats, signing, hash trees, tally recomputation |
| `@qualified-opinion/verifier` | offline verification library and the `qualified-opinion-verify` CLI |

## How trust works

A vote proof on its own shows a ballot was accepted at some point; a signed
tally snapshot pins its final state, since a ballot may later be replaced or
withdrawn. The verifier never takes a server's word for anything: you give
it the deployment's verification policy, obtained through a separate
channel, and it refuses to run without that file's exact checksum. Read
[the threat model](docs/threat-model.md) and
[verification guide](docs/verification.md) before integrating.

## Development

Requires Bun 1.3 (1.3.12+); published packages run on Node.js 20+.

```sh
bun install --frozen-lockfile
bun run check
bun run build
bun run smoke
```

`bun run ci` runs the full release pipeline; `bun run pack` writes package
tarballs to `artifacts/packages/` without publishing anything. Deterministic
test vectors live in `vectors/v3/`.

The data formats are compatibility boundaries: any change that would alter
signed bytes or how tallies are computed requires a new protocol version,
never a silent reinterpretation of the current one (v3).

## Related repositories

- [gcs-attested-registration-voting](https://github.com/konsensus-platform/gcs-attested-registration-voting)
  — a reference backend that produces these proofs inside attested cloud
  hardware
- [konsensus](https://github.com/konsensus-platform/konsensus) — a web frontend that
  displays and verifies them for readers

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
