# Offline verification

The verifier checks a downloaded public proof using only supplied artifacts and
an independently anchored policy. It performs no trust-on-first-use enrollment
and does not fetch replacement keys or certificates from proof-controlled URLs.

## Required inputs

- a `PublicVoteProofBundleV3` JSON document;
- an `OfflineVerificationPolicyV3` JSON document;
- the lowercase hexadecimal SHA-256 digest of the exact policy JSON, obtained
  through an independent trusted channel; and
- optionally, a signed tally snapshot with its replay supplement.

The policy pins accepted identity-attestation workloads, certificate roots,
audiences, protocol bindings, transparency log, witness configuration, and
time-bounded Ed25519 eligibility and receipt keys.

Every question authorization must carry an independently signed directory-witness
envelope. The verifier checks its signature and external key fingerprint, GCP
provider, source revision, trust root, log, application origin, exact checkpoint
hash, and freshness at authorization issuance. Complete tally verification repeats
the check for every authorization in the tally, so a valid target proof cannot hide
an invalid non-target ballot.

## CLI

```sh
qualified-opinion-verify \
  --bundle vote-proof.json \
  --policy verification-policy.json \
  --expected-policy-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Set `QUALIFIED_OPINION_POLICY_SHA256` instead of the command-line option when the
environment is itself a trusted distribution channel.

Add `--tally-snapshot tally.json --require-counted` when the caller requires a
verified counted state at a signed checkpoint. Use `--json` for stable
machine-readable output.

Add `--latest-question-head head.json` with an independently obtained signed head
to reject an otherwise valid but smaller stale checkpoint.

`--allow-unpinned-policy` is only for explicit inspection. A structurally and
cryptographically valid result in that mode is labeled `UNANCHORED`, is never
trusted, and exits with status 4.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Cryptographically valid under the pinned policy and any requested counted-state requirement |
| 1 | Cryptographic, structural, policy, or proof-link failure |
| 2 | Invalid arguments or unreadable input |
| 3 | Valid inclusion evidence, but no verified counted state when `--require-counted` was requested |
| 4 | Valid under the supplied policy, but the policy was intentionally unanchored |

## Interpreting results

An initial acceptance with valid transparency inclusion proves that the service
accepted and logged the event. It does not prove that no later event or
adjudication changed the question nullifier's state. Only deterministic replay at
a verified signed tally checkpoint establishes the event's state at that
checkpoint.

Treat any failed check as fatal. Do not recover by dropping unknown fields,
normalizing malformed encodings, trying an unbounded key set, or replacing the
independently pinned policy with proof-supplied data.
