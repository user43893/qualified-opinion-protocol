# Threat model

## Security goals

The protocol is designed so that an independent verifier can:

- detect alteration of signed protocol artifacts;
- bind a vote event to one ballot, question, deployment, origin, and policy set;
- verify that the event used a question-scoped key authorized by a pinned
  Confidential Space workload;
- verify the active-directory registration chain and the independently witnessed
  checkpoint committed into every authorization;
- verify append-only transparency inclusion;
- replay tally inputs deterministically; and
- avoid requiring reusable voter identity material in the public proof.

## Trust assumptions

Verification depends on an independently distributed policy digest, correct
policy contents, the security of configured signing keys and attested workloads,
the correctness of the local cryptographic runtime, independently observed
directory and question-log heads, and complete tally inputs at the selected
checkpoint. The protocol does not make a proof-controlled trust anchor safe.

The attestation policy must pin workload identity, audience, purpose,
certificate roots, and relevant claim constraints. Server signing-key history
must be time bounded. The tally policy and protocol binding must be fixed before
evidence is interpreted.

## Adversaries considered

- a party that modifies downloaded JSON or substitutes a different ballot;
- a service that supplies an attacker-selected verification policy;
- replay across deployments, origins, audiences, questions, or policy sets;
- ambiguous JSON, base64url, ECDSA, WebAuthn, certificate, or time encodings;
- omission or mutation of transparency and tally evidence;
- a stale, forged, or source-substituted eligibility-directory witness;
- publication of unexpected identity-linked fields; and
- a compromised current signing key attempting to validate artifacts outside
  its configured validity window.

Exact schemas, canonical bytes, domain-separated Merkle hashing, explicit key
algorithms, and pinned policy selection address these threats. The verifier
fails closed on ambiguity and unknown signed fields.

## Out of scope

The repository does not provide endpoint authentication, secure policy
distribution, voter-device malware protection, traffic-analysis resistance,
denial-of-service protection, threshold custody, key recovery, or a guarantee
that an operator publishes every eligible vote. It cannot prove the absence of a
later event without a complete verified checkpoint.

Confidentiality of private eligibility and delegation transport is an application
responsibility. Public question nullifiers intentionally allow events for the
same question-scoped voter to be linked for deterministic replacement semantics.
Active-directory records are intentionally public membership evidence and can
contain names, email addresses, and qualification evidence supplied by a
deployment. The protocol prevents those records from being copied into vote
proofs; it cannot prevent observers from retaining a previously published
directory record.

## Operational guidance

- Distribute policy hashes separately from vote-proof downloads.
- Keep issuer and server signing keys isolated and rotate with explicit validity
  windows.
- Monitor transparency consistency and retain signed tree heads.
- Retain independently fetched directory-witness statements and current directory
  heads.
- Verify complete checkpoint inputs before presenting final counted status.
- Never log reusable credentials, private requests, raw identity evidence, or
  private signing material.
- Treat cryptographic or policy-check failures as security events, not
  recoverable formatting errors.
