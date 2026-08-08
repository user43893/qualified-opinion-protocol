import {
  PUBLIC_VOTE_PROOF_BUNDLE_SCHEMA_V3,
  type PublicVoteProofBundleV3,
  VOTE_EVENT_SCHEMA_V3,
  validatePublicVoteProofBundleV3,
} from "@qualified-opinion/protocol";
import type { OfflineAttestationVerification } from "./attestation";
import {
  type OfflineVerificationPolicyV3,
  parseVerificationPolicy,
  verificationPolicySha256,
} from "./policy";
import type { VoteStateAtCheckpointV3 } from "./tally-checkpoint-v3";
import { verifyPublicVoteProofV3 } from "./verifier-v3";

export type VerifiedVoteStatus =
  | "counted"
  | "not_counted_at_checkpoint"
  | "superseded_at_checkpoint"
  | "not_observed_at_checkpoint"
  | "checkpoint_unverified"
  | "invalid";

export type IncludedVoteReceiptStatus = "counted";

export type VoteProofCheck = {
  id: string;
  ok: boolean;
  error?: string;
};

export type OfflineVoteProofVerification = {
  bundleId: string | null;
  checks: VoteProofCheck[];
  completeness: "inclusion-only" | "tally-checkpoint";
  /** True only for the target event in a verified signed tally checkpoint. */
  counted: boolean;
  cryptographicallyValid: boolean;
  errors: string[];
  questionAuthorizationAttestation: OfflineAttestationVerification | null;
  includedReceiptCounted: boolean;
  includedReceiptStatus: IncludedVoteReceiptStatus | null;
  outcome:
    | "verified_counted"
    | "verified_not_counted"
    | "verified_inclusion_only"
    | "unanchored_counted"
    | "unanchored_not_counted"
    | "unanchored_inclusion_only"
    | "unanchored_invalid"
    | "invalid";
  /** True only when the caller supplied an independently obtained policy hash. */
  policyAnchored: boolean;
  policyId: string;
  policySha256: string;
  protocolVersion: typeof VOTE_EVENT_SCHEMA_V3 | null;
  status: VerifiedVoteStatus;
  tallyCheckpointState: VoteStateAtCheckpointV3 | null;
  /** False for every unpinned result, even if its internal checks pass. */
  verificationTrusted: boolean;
  warnings: string[];
};

type VerificationPolicyAnchor =
  | {
      allowUnpinnedPolicy: true;
      expectedPolicySha256?: never;
    }
  | {
      allowUnpinnedPolicy?: never;
      expectedPolicySha256: string;
    };

export async function verifyDownloadedVoteProof(
  input: {
    bundle: unknown;
    latestQuestionTreeHead?: unknown;
    policy: unknown;
    tallyCheckpoint?: unknown;
  } & VerificationPolicyAnchor,
): Promise<OfflineVoteProofVerification> {
  if (input.allowUnpinnedPolicy && input.expectedPolicySha256) {
    throw new Error("verification_policy_anchor_mode_ambiguous");
  }
  const policyAnchored = !input.allowUnpinnedPolicy;
  if (policyAnchored && !/^[0-9a-f]{64}$/i.test(input.expectedPolicySha256 ?? "")) {
    throw new Error("verification_policy_sha256_invalid");
  }
  const policyHash = await verificationPolicySha256(input.policy);
  if (
    input.expectedPolicySha256 &&
    input.expectedPolicySha256.toLowerCase() !== policyHash
  ) {
    throw new Error("verification_policy_sha256_mismatch");
  }
  const policy = parseVerificationPolicy(input.policy);
  const parsed = validatePublicVoteProofBundleV3(input.bundle);
  if (!parsed.ok) {
    return verificationResult({
      attestation: null,
      bundle: null,
      checks: [
        {
          id: "bundle_structure_and_links",
          ok: false,
          error: parsed.errors.join("; "),
        },
      ],
      policy,
      policyAnchored,
      policyHash,
      protocolRecognized:
        bundleSchema(input.bundle) === PUBLIC_VOTE_PROOF_BUNDLE_SCHEMA_V3,
    });
  }
  const verified = await verifyPublicVoteProofV3({
    bundle: parsed.value,
    latestQuestionTreeHead: input.latestQuestionTreeHead,
    policy,
    tallyCheckpoint: input.tallyCheckpoint,
  });
  return verificationResult({
    attestation: verified.attestation,
    bundle: parsed.value,
    checks: verified.checks,
    policy,
    policyAnchored,
    policyHash,
    protocolRecognized: true,
    tallyCheckpointState: verified.tallyCheckpointState,
  });
}

function verificationResult(input: {
  attestation: OfflineAttestationVerification | null;
  bundle: PublicVoteProofBundleV3 | null;
  checks: VoteProofCheck[];
  policy: OfflineVerificationPolicyV3;
  policyAnchored: boolean;
  policyHash: string;
  protocolRecognized: boolean;
  tallyCheckpointState?: VoteStateAtCheckpointV3 | null;
}): OfflineVoteProofVerification {
  const cryptographicallyValid = input.checks.every((entry) => entry.ok);
  const checkpointVerified =
    cryptographicallyValid &&
    input.tallyCheckpointState !== null &&
    input.tallyCheckpointState !== undefined;
  const counted =
    checkpointVerified &&
    input.tallyCheckpointState?.status === "counted_at_checkpoint";
  const status: VerifiedVoteStatus = !cryptographicallyValid
    ? "invalid"
    : !checkpointVerified
      ? "checkpoint_unverified"
      : input.tallyCheckpointState?.status === "counted_at_checkpoint"
        ? "counted"
        : (input.tallyCheckpointState?.status ?? "checkpoint_unverified");
  return {
    bundleId: input.bundle?.bundleId ?? null,
    checks: input.checks,
    completeness: checkpointVerified ? "tally-checkpoint" : "inclusion-only",
    counted,
    cryptographicallyValid,
    errors: input.checks
      .filter((entry) => !entry.ok)
      .map((entry) => `${entry.id}: ${entry.error ?? "failed"}`),
    questionAuthorizationAttestation: input.attestation,
    includedReceiptCounted:
      cryptographicallyValid && input.bundle?.acceptance.payload.status === "counted",
    includedReceiptStatus: input.bundle?.acceptance.payload.status ?? null,
    outcome: !cryptographicallyValid
      ? input.policyAnchored
        ? "invalid"
        : "unanchored_invalid"
      : input.policyAnchored
        ? counted
          ? "verified_counted"
          : checkpointVerified
            ? "verified_not_counted"
            : "verified_inclusion_only"
        : counted
          ? "unanchored_counted"
          : checkpointVerified
            ? "unanchored_not_counted"
            : "unanchored_inclusion_only",
    policyAnchored: input.policyAnchored,
    policyId: input.policy.policyId,
    policySha256: input.policyHash,
    protocolVersion: input.protocolRecognized ? VOTE_EVENT_SCHEMA_V3 : null,
    status,
    tallyCheckpointState: input.tallyCheckpointState ?? null,
    verificationTrusted: input.policyAnchored && cryptographicallyValid,
    warnings: [
      ...(!input.policyAnchored
        ? [
            "UNANCHORED: the supplied policy was not checked against an independently obtained SHA-256. This is not a trusted verification result.",
          ]
        : []),
      ...(checkpointVerified
        ? [
            "Counted state is scoped to the signed V3 question snapshot in tallyCheckpointState. The snapshot contains the complete contiguous prefix of its deterministic question log and recomputes the signed RFC 6962 root.",
          ]
        : [
            "This V3 bundle proves an initial counted acceptance and inclusion by the signed tree heads. It does not prove that the question nullifier has no later replacement, withdrawal, or adjudication.",
          ]),
    ],
  };
}

function bundleSchema(value: unknown) {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as { schema?: unknown }).schema
    : null;
}
