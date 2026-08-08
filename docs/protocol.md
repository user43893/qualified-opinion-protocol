# Protocol boundary

Qualified Opinion V3 defines exact JSON artifacts and cryptographic links for
question-scoped voting evidence. This document is an integration overview; the
exported TypeScript types and validators are the executable definition.

## Canonical data

Signed and hashed JSON is canonicalized with RFC 8785 JSON Canonicalization
Scheme rules. Inputs must be I-JSON values with plain objects, dense arrays,
finite numbers, and well-formed Unicode. Unknown fields are rejected on signed
protocol objects.

Binary values use unpadded base64url unless a field explicitly requires
hexadecimal text or PEM/SPKI encoding. Hash fields identify SHA-256 digests.
Timestamps are normalized UTC ISO 8601 strings with millisecond precision.

## Artifact flow

1. The eligibility issuer signs registration assertions and decisions. A signed
   active-directory checkpoint commits to the complete sorted current set.
2. An issuer signs a ballot manifest whose binding fixes the deployment,
   audience, origin, and eligibility, tally, and trust policies.
3. An attested authorization issuer validates private eligibility material and
   emits a public, question-scoped authorization. Its attestation nonce binds the
   canonical authorization payload hash. The payload commits to the exact
   active-directory checkpoint and its independently signed witness envelope.
4. The voter signs a vote event with the authorization's one-question P-256 key.
   The event binds the complete ballot manifest and the same protocol binding.
5. The service emits a signed counted acceptance and publishes the event and
   acceptance in the deterministic question log derived by
   `questionVoteLogIdV3`.
6. A deterministic tally replay selects the final event for each question
   nullifier under the pinned tally policy.
7. A signed tally snapshot plus its complete contiguous question-log prefix
   establishes state at a particular tree head.

## Eligibility directory

`ActiveEligibilityDirectoryCheckpointV3` signs the RFC 6962 root of the complete
sorted current directory. A full bundle proves completeness; a record proof proves
one member's inclusion without downloading every record body. Historical
checkpoints are as-of evidence unless the caller supplies an independently
witnessed current head.

Directory records contain public registration and qualification evidence. They do
not contain a question nullifier or vote event. Conversely, question-scoped vote
proofs contain no public voter ID, name, email address, registration proof,
qualification subject, root credential, or reusable delegation.

## Public proof boundary

`PublicVoteProofBundleV3` contains:

- a question-scoped authorization and its attestation token;
- the signed ballot manifest;
- the voter-signed event;
- the signed initial counted acceptance; and
- inclusion proofs with signed transparency tree heads.

It deliberately excludes global voter identifiers, names, email addresses,
registry evidence, reusable credentials, root-key delegations, and private
signing keys. Optional public attribution is a separately signed, removable
artifact and is not part of the immutable vote proof.

## Private transport boundary

Eligibility evidence, reusable delegation, and pre-signing requests cross a
private authenticated channel. They must not be copied into a public proof,
transparency leaf, conformance vector, or diagnostic log. Exact public validators
make accidental extra fields fail closed.

## Compatibility

Schema constants ending in `.v3` identify the only application protocol accepted
here. Validators require exact schema strings and reject extra keys. A change to
field meaning, canonical bytes, signature input, selection rules, or trust
semantics requires a new protocol version.
