import { createHash } from "node:crypto";
import { canonicalizeJson } from "@qualified-opinion/protocol";
import {
  type SignedTransparencyWitnessStatusV3,
  verifyWitnessStatusEnvelope,
} from "./witness-status-v3";

export const ELIGIBILITY_DIRECTORY_CHECKPOINT_ENTRY_TYPE =
  "eligibility_directory_checkpoint" as const;

export type EligibilityDirectoryWitnessPolicyV3 = {
  logId: string;
  maximumAgeSeconds: number;
  origin: string;
  publicKeySpkiSha256: string;
  sourceRevision: string;
  trustRootSha256: string;
  witnessId: string;
};

export type VerifiedEligibilityDirectoryWitnessV3 = {
  canonicalEnvelope: string;
  checkpointEntry: {
    entryId: string;
    entryPayloadHash: string;
    entryType: typeof ELIGIBILITY_DIRECTORY_CHECKPOINT_ENTRY_TYPE;
    leafIndex: number;
  };
  envelope: SignedTransparencyWitnessStatusV3;
  envelopeSha256: string;
};

/**
 * Verifies the independently signed witness statement committed into one
 * question authorization. Verification time is authorization issuance time,
 * so a stored authorization remains auditable after the status ages.
 */
export function verifyEligibilityDirectoryWitnessStatusV3(input: {
  expectedCheckpointSha256?: string;
  policy: EligibilityDirectoryWitnessPolicyV3;
  value: unknown;
  verificationTime: Date;
}): VerifiedEligibilityDirectoryWitnessV3 {
  validatePolicy(input.policy);
  if (!Number.isFinite(input.verificationTime.getTime())) {
    throw new Error("eligibility_directory_witness_time_invalid");
  }

  const envelope = verifyWitnessStatusEnvelope(
    input.value,
    input.policy.publicKeySpkiSha256,
  );
  const { statement } = envelope;
  const latest = statement.latestVerified;
  const checkpointEntry =
    latest?.latestEntryByType[ELIGIBILITY_DIRECTORY_CHECKPOINT_ENTRY_TYPE];
  const observedAt = Date.parse(latest?.observedAt ?? "");
  const lastAttemptAt = Date.parse(statement.lastAttemptAt);
  const lastSuccessAt = Date.parse(statement.lastSuccessAt ?? "");
  const checkpoint = latest?.checkpoint;
  const maximumAgeMs = input.policy.maximumAgeSeconds * 1_000;
  if (
    statement.status !== "verified" ||
    statement.provider !== "gcp-cloud-run" ||
    statement.witnessId !== input.policy.witnessId ||
    statement.sourceRevision !== input.policy.sourceRevision ||
    statement.trustRootSha256 !== input.policy.trustRootSha256 ||
    statement.logId !== input.policy.logId ||
    statement.origin !== input.policy.origin ||
    !latest ||
    !checkpoint ||
    !checkpointEntry ||
    checkpointEntry.entryType !== ELIGIBILITY_DIRECTORY_CHECKPOINT_ENTRY_TYPE ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      checkpointEntry.entryId,
    ) ||
    !/^[A-Za-z0-9_-]{43}$/.test(checkpointEntry.entryPayloadHash) ||
    (input.expectedCheckpointSha256 !== undefined &&
      checkpointEntry.entryPayloadHash !== input.expectedCheckpointSha256) ||
    !Number.isSafeInteger(checkpointEntry.leafIndex) ||
    checkpointEntry.leafIndex < 0 ||
    checkpoint.payload.logId !== input.policy.logId ||
    !Number.isSafeInteger(checkpoint.payload.treeSize) ||
    checkpoint.payload.treeSize <= checkpointEntry.leafIndex ||
    !Number.isFinite(observedAt) ||
    !Number.isFinite(lastAttemptAt) ||
    !Number.isFinite(lastSuccessAt) ||
    latest.observedAt !== statement.lastSuccessAt ||
    latest.observedAt !== statement.lastAttemptAt ||
    observedAt > input.verificationTime.getTime() + 60_000 ||
    input.verificationTime.getTime() - observedAt > maximumAgeMs
  ) {
    throw new Error("eligibility_directory_witness_invalid");
  }

  const canonicalEnvelope = canonicalizeJson(envelope);
  return {
    canonicalEnvelope,
    checkpointEntry: {
      entryId: checkpointEntry.entryId,
      entryPayloadHash: checkpointEntry.entryPayloadHash,
      entryType: ELIGIBILITY_DIRECTORY_CHECKPOINT_ENTRY_TYPE,
      leafIndex: checkpointEntry.leafIndex,
    },
    envelope,
    envelopeSha256: sha256Base64Url(canonicalEnvelope),
  };
}

function validatePolicy(policy: EligibilityDirectoryWitnessPolicyV3) {
  let origin: URL;
  try {
    origin = new URL(policy.origin);
  } catch {
    throw new Error("eligibility_directory_witness_policy_invalid");
  }
  if (
    !Number.isSafeInteger(policy.maximumAgeSeconds) ||
    policy.maximumAgeSeconds < 1 ||
    policy.maximumAgeSeconds > 3_600 ||
    !policy.logId ||
    !policy.witnessId ||
    !/^[0-9a-f]{40}$/.test(policy.sourceRevision) ||
    !/^[0-9a-f]{64}$/.test(policy.publicKeySpkiSha256) ||
    !/^[0-9a-f]{64}$/.test(policy.trustRootSha256) ||
    origin.protocol !== "https:" ||
    origin.origin !== policy.origin
  ) {
    throw new Error("eligibility_directory_witness_policy_invalid");
  }
}

function sha256Base64Url(value: string) {
  return createHash("sha256").update(value).digest("base64url");
}
