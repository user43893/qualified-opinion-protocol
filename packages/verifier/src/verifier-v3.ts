import {
  type PublicVoteProofBundleV3,
  VOTE_EVENT_SCHEMA_V3,
  canonicalizeJson,
  sha256Base64Url,
  verifyPublicVoteProofBundleV3Integrity,
} from "@qualified-opinion/protocol";
import {
  verifyEd25519SignedPayload,
  verifyP256SignedPayload,
} from "@qualified-opinion/protocol/node";
import {
  type OfflineAttestationVerification,
  attestationIssuedAt,
  verifyQuestionVotingAuthorizationPkiAttestation,
} from "./attestation";
import { verifyEligibilityDirectoryWitnessForAuthorization } from "./authorization-witness-v3";
import {
  type IdentityAttestationPolicyV3,
  type OfflineVerificationPolicyV3,
  type ServerVerificationKeyV3,
  selectIdentityPolicyCandidates,
  selectServerKey,
  selectVotingPolicyForBinding,
} from "./policy";
import {
  type VoteStateAtCheckpointV3,
  verifyVoteTallyCheckpointV3,
} from "./tally-checkpoint-v3";

export { verifyEligibilityDirectoryWitnessForAuthorization } from "./authorization-witness-v3";

export type V3VoteProofCheck = {
  id: string;
  ok: boolean;
  error?: string;
};

export type V3VoteProofVerificationParts = {
  attestation: OfflineAttestationVerification | null;
  checks: V3VoteProofCheck[];
  tallyCheckpointState: VoteStateAtCheckpointV3 | null;
};

export async function verifyPublicVoteProofV3(input: {
  bundle: PublicVoteProofBundleV3;
  latestQuestionTreeHead?: unknown;
  policy: OfflineVerificationPolicyV3;
  tallyCheckpoint?: unknown;
}): Promise<V3VoteProofVerificationParts> {
  const checks: V3VoteProofCheck[] = [];
  const integrity = await verifyPublicVoteProofBundleV3Integrity(input.bundle);
  checks.push(
    integrity.ok
      ? { id: "bundle_structure_and_links", ok: true }
      : {
          id: "bundle_structure_and_links",
          ok: false,
          error: integrity.errors.join("; "),
        },
  );
  if (!integrity.ok) {
    return { attestation: null, checks, tallyCheckpointState: null };
  }

  let attestation: OfflineAttestationVerification | null = null;
  let attestationPolicy: IdentityAttestationPolicyV3 | null = null;
  await check(checks, "question_authorization_attestation", async () => {
    const verified = await verifyQuestionAuthorizationAttestation({
      bundle: input.bundle,
      policy: input.policy,
    });
    attestation = verified.attestation;
    attestationPolicy = verified.policy;
  });
  await check(checks, "eligibility_directory_witness", () => {
    if (!attestationPolicy) {
      throw new Error("eligibility_directory_witness_policy_unavailable");
    }
    verifyEligibilityDirectoryWitnessForAuthorization({
      authorization: input.bundle.questionAuthorization.payload,
      attestationPolicy,
    });
  });
  await check(checks, "voting_policy", async () => {
    await verifyV3VotingPolicy({
      bundle: input.bundle,
      policy: input.policy,
      attestationPolicy,
    });
  });
  await check(checks, "question_signature", () =>
    verifyServerSignature({
      envelope: input.bundle.questionManifest,
      policy: input.policy,
      purpose: "receipt",
      time: input.bundle.questionManifest.payload.publishedAt,
    }),
  );
  await check(checks, "question_vote_signature", async () => {
    const authorization = input.bundle.questionAuthorization.payload;
    const valid = await verifyP256SignedPayload({
      envelope: input.bundle.voteEvent,
      publicKeySpki: authorization.questionKey.publicKeySpki,
      expectedKeyId: authorization.questionKey.keyId,
    });
    if (!valid) throw new Error("invalid_question_vote_signature");
  });
  await check(checks, "acceptance_signature", () =>
    verifyServerSignature({
      envelope: input.bundle.acceptance,
      policy: input.policy,
      purpose: "receipt",
      time: input.bundle.acceptance.payload.receivedAt,
    }),
  );
  await check(checks, "event_transparency_signature", () =>
    verifyServerSignature({
      envelope: input.bundle.voteEventTransparency.treeHead,
      policy: input.policy,
      purpose: "receipt",
      time: input.bundle.voteEventTransparency.treeHead.payload.issuedAt,
    }),
  );
  await check(checks, "acceptance_transparency_signature", () =>
    verifyServerSignature({
      envelope: input.bundle.acceptanceTransparency.treeHead,
      policy: input.policy,
      purpose: "receipt",
      time: input.bundle.acceptanceTransparency.treeHead.payload.issuedAt,
    }),
  );

  let tallyCheckpointState: VoteStateAtCheckpointV3 | null = null;
  if (input.tallyCheckpoint !== undefined) {
    if (checks.every((entry) => entry.ok)) {
      const checkpoint = await verifyVoteTallyCheckpointV3({
        bundle: input.bundle,
        latestQuestionTreeHead: input.latestQuestionTreeHead,
        policy: input.policy,
        supplement: input.tallyCheckpoint,
      });
      if (checkpoint.ok) {
        tallyCheckpointState = checkpoint.state;
        checks.push({ id: "tally_checkpoint", ok: true });
      } else {
        checks.push({
          id: "tally_checkpoint",
          ok: false,
          error: checkpoint.errors.join("; "),
        });
      }
    } else {
      checks.push({
        id: "tally_checkpoint",
        ok: false,
        error: "vote proof bundle verification failed",
      });
    }
  }
  return { attestation, checks, tallyCheckpointState };
}

async function verifyQuestionAuthorizationAttestation(input: {
  bundle: PublicVoteProofBundleV3;
  policy: OfflineVerificationPolicyV3;
}) {
  const authorization = input.bundle.questionAuthorization;
  const issuedAt = attestationIssuedAt(authorization.attestationToken);
  const candidates = selectIdentityPolicyCandidates(input.policy, issuedAt);
  const matches: Array<{
    attestation: OfflineAttestationVerification;
    policy: IdentityAttestationPolicyV3;
  }> = [];
  let singleCandidateError: unknown;
  for (const candidate of candidates) {
    try {
      matches.push({
        attestation: await verifyQuestionVotingAuthorizationPkiAttestation({
          token: authorization.attestationToken,
          payload: authorization.payload,
          payloadSha256: authorization.payloadSha256,
          policy: candidate,
        }),
        policy: candidate,
      });
    } catch (error) {
      singleCandidateError = error;
    }
  }
  if (matches.length !== 1) {
    if (candidates.length === 1 && singleCandidateError instanceof Error) {
      throw singleCandidateError;
    }
    throw new Error(
      matches.length === 0
        ? "question_authorization_attestation_policy_not_found"
        : "question_authorization_attestation_policy_ambiguous",
    );
  }
  const match = matches[0];
  if (!match) throw new Error("question_authorization_attestation_unavailable");
  return match;
}

async function verifyV3VotingPolicy(input: {
  attestationPolicy: IdentityAttestationPolicyV3 | null;
  bundle: PublicVoteProofBundleV3;
  policy: OfflineVerificationPolicyV3;
}) {
  const binding = input.bundle.voteEvent.payload.binding;
  const bindingSha256 = await sha256Base64Url(canonicalizeJson(binding));
  for (const [label, time] of [
    ["question_manifest", input.bundle.questionManifest.payload.publishedAt],
    ["question_authorization", input.bundle.questionAuthorization.payload.issuedAt],
    ["vote_event", input.bundle.voteEvent.payload.issuedAt],
    ["acceptance", input.bundle.acceptance.payload.receivedAt],
    [
      "vote_event_tree_head",
      input.bundle.voteEventTransparency.treeHead.payload.issuedAt,
    ],
    [
      "acceptance_tree_head",
      input.bundle.acceptanceTransparency.treeHead.payload.issuedAt,
    ],
  ] as Array<[string, string]>) {
    const selected = selectVotingPolicyForBinding(input.policy, {
      protocolBindingSha256: bindingSha256,
      protocolVersion: VOTE_EVENT_SCHEMA_V3,
      time,
    });
    if (selected.voteServiceAudience !== binding.audience) {
      throw new Error(`${label}:untrusted_vote_service_audience`);
    }
  }
  if (
    input.bundle.questionAuthorization.payload.issuerAttestation.audience !==
    input.attestationPolicy?.audience
  ) {
    throw new Error("question_authorization_attestation_audience_mismatch");
  }
  if (
    !input.attestationPolicy ||
    binding.origin !== input.attestationPolicy.webauthnOrigin
  ) {
    throw new Error("protocol_binding_origin_mismatch");
  }
}

async function verifyServerSignature<T>(input: {
  envelope: {
    payload: T;
    payloadSha256: string;
    signature: {
      algorithm: "Ed25519" | "ES256";
      keyId: string;
      value: string;
    };
  };
  policy: OfflineVerificationPolicyV3;
  purpose: ServerVerificationKeyV3["purpose"];
  time: string;
}) {
  const key = selectServerKey(input.policy, {
    keyId: input.envelope.signature.keyId,
    purpose: input.purpose,
    time: input.time,
  });
  const valid = await verifyEd25519SignedPayload({
    envelope: input.envelope,
    publicKeySpki: key.publicKeySpki,
    expectedKeyId: key.keyId,
  });
  if (!valid) throw new Error(`invalid_${input.purpose}_signature`);
}

async function check(
  checks: V3VoteProofCheck[],
  id: string,
  operation: () => void | Promise<void>,
) {
  try {
    await operation();
    checks.push({ id, ok: true });
  } catch (error) {
    checks.push({
      id,
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    });
  }
}
