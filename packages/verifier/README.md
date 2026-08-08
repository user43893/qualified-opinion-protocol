# @qualified-opinion/verifier

Policy-anchored offline verification for Qualified Opinion V3 registrations,
active eligibility directories, public vote proofs, Google Confidential Space
attestations, independent directory witnesses, transparency inclusions, and signed
tally checkpoints.

```sh
npm install @qualified-opinion/verifier
```

## Library

```ts
import { verifyDownloadedVoteProof } from "@qualified-opinion/verifier";

const result = await verifyDownloadedVoteProof({
  bundle,
  policy,
  expectedPolicySha256:
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  tallyCheckpoint,
});

if (!result.verificationTrusted || !result.counted) {
  throw new Error(result.errors.join("; "));
}
```

The expected policy digest must come from an independent trusted channel. Proof
contents are not a trust anchor.

`verifyActiveEligibilityDirectoryRecordV3` verifies a registration receipt,
Confidential Space attestation, signed eligibility assertion and decision,
directory checkpoint, and RFC 6962 membership path. Supply an independently
witnessed current directory head when the result must mean current rather than
as-of.

Vote-proof verification checks the embedded directory witness for the target
authorization and, during tally replay, for every non-target authorization too.

## CLI

```sh
qualified-opinion-verify \
  --bundle vote-proof.json \
  --policy verification-policy.json \
  --expected-policy-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --tally-snapshot tally.json \
  --require-counted
```

Use `--json` for machine-readable output. `--allow-unpinned-policy` is an unsafe
inspection mode: it prints `UNANCHORED`, never marks the result trusted, and exits
with status 4.

Exit status 0 means verified under the pinned policy, 1 means invalid, 2 means
input error, 3 means a counted checkpoint was required but not proven, and 4
means the supplied policy was intentionally unanchored.

Licensed under Apache-2.0. See `LICENSE` and `NOTICE`.
