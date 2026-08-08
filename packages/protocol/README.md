# @qualified-opinion/protocol

Canonical V3 protocol types, builders, exact validators, RFC 8785 JSON
canonicalization, SHA-256 encoding, active eligibility-directory commitments,
deterministic question logs, RFC 6962 Merkle proofs, and tally replay for
Qualified Opinion.

```sh
npm install @qualified-opinion/protocol
```

The default ESM entry point is runtime-neutral:

```ts
import {
  buildVoteEventV3,
  canonicalJsonSha256,
  verifyPublicVoteProofBundleV3Integrity,
} from "@qualified-opinion/protocol";
```

Node.js signature, WebAuthn, and cryptographic tally verification helpers use a
separate entry point:

```ts
import {
  verifyEd25519SignedPayload,
  verifyP256SignedPayload,
  verifyTallySnapshotCryptographicallyV3,
} from "@qualified-opinion/protocol/node";
```

Integrity checks establish exact structure and internal cryptographic links. They
do not establish signer trust. Use independently pinned public-key and
attestation policies, or use `@qualified-opinion/verifier` for complete offline
vote-proof verification.

The directory and question-log APIs include
`buildActiveEligibilityDirectoryCheckpointV3`,
`buildActiveEligibilityDirectoryRecordProofV3`,
`verifyActiveEligibilityDirectoryBundleIntegrityV3`, and
`questionVoteLogIdV3`.

Only V3 schemas are accepted. Unknown fields on signed protocol objects fail
validation.

Licensed under Apache-2.0. See `LICENSE` and `NOTICE`.
