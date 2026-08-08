import {
  type MerkleTreeHeadV3,
  type PublicVoteProofBundleV3,
  type ReplayedTallyV3,
  type SignedPayload,
  type TallyInputSetV3,
  type TallySnapshotV3,
  VOTE_ACCEPTANCE_SCHEMA_V3,
  VOTE_EVENT_SCHEMA_V3,
  assertMerkleTreeHeadV3,
  assertTallyInputSetV3,
  assertTallySnapshotV3,
  canonicalizeJson,
  replayTallyV3,
  sha256Base64Url,
} from "@qualified-opinion/protocol";
import {
  type ResolveTallyTrustedSigningKeyV3,
  verifyTallySnapshotCryptographicallyV3,
} from "@qualified-opinion/protocol/node";
import {
  attestationIssuedAt,
  verifyQuestionVotingAuthorizationPkiAttestation,
} from "./attestation";
import { verifyEligibilityDirectoryWitnessForAuthorization } from "./authorization-witness-v3";
import {
  type OfflineVerificationPolicyV3,
  type VotingPolicyV3,
  selectIdentityPolicyCandidates,
  selectServerKey,
  selectVotingPolicyForBinding,
} from "./policy";

export const VOTE_STATE_AT_CHECKPOINT_SCHEMA_V3 =
  "qualified-voting.vote-state-at-checkpoint.v3" as const;

export type VoteStateAtCheckpointV3 = {
  schema: typeof VOTE_STATE_AT_CHECKPOINT_SCHEMA_V3;
  status:
    | "counted_at_checkpoint"
    | "not_counted_at_checkpoint"
    | "superseded_at_checkpoint"
    | "not_observed_at_checkpoint";
  /**
   * The signed snapshot contains the exact contiguous prefix of the
   * deterministic question log and recomputes its signed RFC 6962 root.
   */
  completenessScope: "complete_question_log_prefix";
  target: {
    eventId: string;
    payloadSha256: string;
    questionNullifier: string;
  };
  checkpoint: {
    generatedAt: string;
    logId: string;
    questionId: string;
    rootHash: string;
    snapshotId: string;
    snapshotPayloadSha256: string;
    treeHeadPayloadSha256: string;
    treeSize: number;
  };
  targetEvent: CheckpointEventV3 | null;
  targetReceipt: CheckpointReceiptV3 | null;
  latestEventForQuestionNullifier: CheckpointEventV3 | null;
  latestReceiptForQuestionNullifier: CheckpointReceiptV3 | null;
  countedVote: {
    choiceId: string;
    decisionId: string;
    decisionPayloadSha256: string;
    eventId: string;
    eventPayloadSha256: string;
  } | null;
};

type CheckpointEventV3 = {
  eventId: string;
  eventType: "cast" | "replace" | "withdraw";
  payloadSha256: string;
  sequence: number;
  choiceId: string | null;
};

type CheckpointReceiptV3 = {
  receiptId: string;
  payloadSha256: string;
  status: "counted" | "pending_eligibility" | "rejected" | "excluded";
};

export type TallyCheckpointSupplementV3 = {
  inputSet: TallyInputSetV3;
  snapshot: SignedPayload<TallySnapshotV3>;
};

export type VerifiedVoteTallyCheckpointV3 =
  | {
      ok: true;
      state: VoteStateAtCheckpointV3;
      supplement: TallyCheckpointSupplementV3;
    }
  | {
      ok: false;
      errors: string[];
      state?: VoteStateAtCheckpointV3;
    };

/**
 * Verifies a signed, question-only V3 tally replay, including the complete
 * contiguous question-log prefix and its recomputed signed RFC 6962 root.
 */
export async function verifyVoteTallyCheckpointV3(input: {
  bundle: PublicVoteProofBundleV3;
  latestQuestionTreeHead?: unknown;
  policy: OfflineVerificationPolicyV3;
  supplement: unknown;
}): Promise<VerifiedVoteTallyCheckpointV3> {
  let supplement: TallyCheckpointSupplementV3;
  let latestQuestionTreeHead: SignedPayload<MerkleTreeHeadV3> | undefined;
  try {
    supplement = parseTallyCheckpointSupplementV3(input.supplement);
    latestQuestionTreeHead =
      input.latestQuestionTreeHead === undefined
        ? undefined
        : parseSignedQuestionTreeHeadV3(input.latestQuestionTreeHead);
  } catch (error) {
    return { ok: false, errors: [message(error)] };
  }

  const targetErrors = verifyTargetIncluded(input.bundle, supplement);
  if (targetErrors.length > 0) {
    return { ok: false, errors: targetErrors };
  }
  const policyErrors = await verifyQuestionTallyPolicyBindingV3({
    inputSet: supplement.inputSet,
    policy: input.policy,
    snapshot: supplement.snapshot,
  });
  if (policyErrors.length > 0) {
    return { ok: false, errors: policyErrors };
  }

  const resolveTrustedKey: ResolveTallyTrustedSigningKeyV3 = (request) => {
    try {
      if (request.algorithm !== "Ed25519") return null;
      const key = selectServerKey(input.policy, {
        keyId: request.keyId,
        purpose: "receipt",
        time: request.signedAt,
      });
      return {
        algorithm: "Ed25519",
        keyId: key.keyId,
        publicKeySpki: key.publicKeySpki,
        purpose: "receipt",
        validFrom: key.validFrom,
        validUntil: key.validUntil,
      };
    } catch {
      return null;
    }
  };
  const cryptographic = await verifyTallySnapshotCryptographicallyV3({
    snapshot: supplement.snapshot,
    inputSet: supplement.inputSet,
    expectedLatestQuestionTreeHead: latestQuestionTreeHead,
    resolveTrustedKey,
    verifyQuestionAuthorization: async ({ authorization }) => {
      try {
        const identityPolicy = await verifyAuthorizationAttestation(
          authorization,
          input.policy,
        );
        if (authorization.payload.binding.origin !== identityPolicy.webauthnOrigin) {
          throw new Error("protocol_binding_origin_mismatch");
        }
        verifyEligibilityDirectoryWitnessForAuthorization({
          attestationPolicy: identityPolicy,
          authorization: authorization.payload,
        });
        return { ok: true };
      } catch (error) {
        return { ok: false, errors: [message(error)] };
      }
    },
  });
  if (!cryptographic.ok) {
    return { ok: false, errors: cryptographic.errors };
  }

  try {
    const replay = await replayTallyV3(
      supplement.snapshot.payload.policy.payload,
      supplement.inputSet,
    );
    return {
      ok: true,
      state: deriveVoteStateAtCheckpointV3({
        bundle: input.bundle,
        replay,
        supplement,
      }),
      supplement,
    };
  } catch (error) {
    return { ok: false, errors: [message(error)] };
  }
}

export function parseSignedQuestionTreeHeadV3(
  value: unknown,
): SignedPayload<MerkleTreeHeadV3> {
  const envelope = object(value, "latest question tree head");
  exactKeys(
    envelope,
    ["payload", "payloadSha256", "signature"],
    "latest question tree head",
  );
  const signature = object(envelope.signature, "latest question tree head signature");
  exactKeys(
    signature,
    ["algorithm", "keyId", "value"],
    "latest question tree head signature",
  );
  if (signature.algorithm !== "Ed25519") {
    throw new Error("signed latest question tree head required");
  }
  assertMerkleTreeHeadV3(envelope.payload);
  return value as SignedPayload<MerkleTreeHeadV3>;
}

export function parseTallyCheckpointSupplementV3(
  value: unknown,
): TallyCheckpointSupplementV3 {
  const wrapper = object(value, "tally checkpoint supplement");
  exactKeys(wrapper, ["inputSet", "snapshot"], "tally checkpoint supplement");
  const snapshot = object(wrapper.snapshot, "tally checkpoint snapshot");
  exactKeys(
    snapshot,
    ["payload", "payloadSha256", "signature"],
    "tally checkpoint snapshot",
  );
  const signature = object(snapshot.signature, "tally checkpoint snapshot signature");
  exactKeys(
    signature,
    ["algorithm", "keyId", "value"],
    "tally checkpoint snapshot signature",
  );
  if (signature.algorithm !== "Ed25519") {
    throw new Error("signed V3 tally snapshot required");
  }
  assertTallySnapshotV3(snapshot.payload);
  assertTallyInputSetV3(wrapper.inputSet);
  return {
    inputSet: wrapper.inputSet,
    snapshot: wrapper.snapshot as SignedPayload<TallySnapshotV3>,
  };
}

export async function verifyQuestionTallyPolicyBindingV3(input: {
  inputSet: TallyInputSetV3;
  policy: OfflineVerificationPolicyV3;
  snapshot: SignedPayload<TallySnapshotV3>;
}) {
  const errors: string[] = [];
  const binding = input.inputSet.questionManifest.payload.binding;
  const bindingSha256 = await sha256Base64Url(canonicalizeJson(binding));
  const logId = input.inputSet.checkpoint.logId;
  const requireAt = (label: string, time: string) =>
    requireBoundVotingPolicy(
      input.policy,
      {
        protocolBindingSha256: bindingSha256,
        protocolVersion: VOTE_EVENT_SCHEMA_V3,
        time,
      },
      binding.audience,
      label,
      errors,
    );

  requireAt("selected_manifest", input.inputSet.questionManifest.payload.publishedAt);
  requireAt("snapshot", input.snapshot.payload.generatedAt);
  requireAt("checkpoint_tree_head", input.inputSet.treeHead.payload.issuedAt);
  for (const manifest of input.inputSet.ballotManifests) {
    const hash = await sha256Base64Url(canonicalizeJson(manifest.payload.binding));
    requireBoundVotingPolicy(
      input.policy,
      {
        protocolBindingSha256: hash,
        protocolVersion: VOTE_EVENT_SCHEMA_V3,
        time: manifest.payload.publishedAt,
      },
      manifest.payload.binding.audience,
      `ballot_manifest:${manifest.payload.manifestId}`,
      errors,
    );
  }
  for (const authorization of input.inputSet.questionVotingAuthorizations) {
    const hash = await sha256Base64Url(canonicalizeJson(authorization.payload.binding));
    requireBoundVotingPolicy(
      input.policy,
      {
        protocolBindingSha256: hash,
        protocolVersion: VOTE_EVENT_SCHEMA_V3,
        time: authorization.payload.issuedAt,
      },
      authorization.payload.binding.audience,
      `question_authorization:${authorization.payloadSha256}`,
      errors,
    );
  }
  const eventBindingByHash = new Map(
    input.inputSet.voteEvents.map((entry) => [
      entry.envelope.payloadSha256,
      entry.envelope.payload.binding,
    ]),
  );
  for (const entry of input.inputSet.voteEvents) {
    const event = entry.envelope.payload;
    const hash = await sha256Base64Url(canonicalizeJson(event.binding));
    for (const [label, time] of [
      ["issued", event.issuedAt],
      ["checkpoint_inclusion", input.inputSet.treeHead.payload.issuedAt],
    ] as Array<[string, string]>) {
      requireBoundVotingPolicy(
        input.policy,
        {
          protocolBindingSha256: hash,
          protocolVersion: VOTE_EVENT_SCHEMA_V3,
          time,
        },
        event.binding.audience,
        `vote_event_${label}:${event.eventId}`,
        errors,
      );
    }
  }
  for (const entry of input.inputSet.voteReceipts) {
    const receipt = entry.envelope.payload;
    const eventBinding = eventBindingByHash.get(receipt.voteEventSha256);
    if (!eventBinding) {
      errors.push(`vote_receipt:${receipt.receiptId}:bound_vote_event_missing`);
      continue;
    }
    const hash = await sha256Base64Url(canonicalizeJson(eventBinding));
    for (const [label, time] of [
      ["received", receipt.receivedAt],
      ["checkpoint_inclusion", input.inputSet.treeHead.payload.issuedAt],
    ] as Array<[string, string]>) {
      requireBoundVotingPolicy(
        input.policy,
        {
          protocolBindingSha256: hash,
          protocolVersion: VOTE_EVENT_SCHEMA_V3,
          time,
        },
        eventBinding.audience,
        `vote_receipt_${label}:${receipt.receiptId}`,
        errors,
      );
    }
    if (receipt.logId !== logId) {
      errors.push(`vote_receipt:${receipt.receiptId}:checkpoint_log_mismatch`);
    }
  }
  return errors;
}

function verifyTargetIncluded(
  bundle: PublicVoteProofBundleV3,
  supplement: TallyCheckpointSupplementV3,
) {
  const errors: string[] = [];
  const exactIncludes = <T>(values: T[], expected: T) =>
    values.some(
      (candidate) => canonicalizeJson(candidate) === canonicalizeJson(expected),
    );
  if (
    supplement.inputSet.questionId !== bundle.voteEvent.payload.questionId ||
    supplement.snapshot.payload.questionId !== bundle.voteEvent.payload.questionId
  ) {
    errors.push("target vote question does not match V3 tally checkpoint");
  }
  if (!exactIncludes(supplement.inputSet.ballotManifests, bundle.questionManifest)) {
    errors.push("target question manifest is not in V3 tally checkpoint");
  }
  if (
    !exactIncludes(
      supplement.inputSet.questionVotingAuthorizations,
      bundle.questionAuthorization,
    )
  ) {
    errors.push("target question authorization is not in V3 tally checkpoint");
  }
  if (
    !exactIncludes(
      supplement.inputSet.voteEvents.map((entry) => entry.envelope),
      bundle.voteEvent,
    )
  ) {
    errors.push("target vote event is not in V3 tally checkpoint");
  }
  if (
    !exactIncludes(
      supplement.inputSet.voteReceipts.map((entry) => entry.envelope),
      bundle.acceptance,
    )
  ) {
    errors.push("target acceptance is not in V3 tally checkpoint");
  }
  return errors;
}

function deriveVoteStateAtCheckpointV3(input: {
  bundle: PublicVoteProofBundleV3;
  replay: ReplayedTallyV3;
  supplement: TallyCheckpointSupplementV3;
}): VoteStateAtCheckpointV3 {
  const targetHash = input.bundle.voteEvent.payloadSha256;
  const targetId = input.bundle.voteEvent.payload.eventId;
  const targetNullifier = input.bundle.voteEvent.payload.questionNullifier;
  const idMatches = input.supplement.inputSet.voteEvents.filter(
    (entry) => entry.envelope.payload.eventId === targetId,
  );
  const hashMatches = input.supplement.inputSet.voteEvents.filter(
    (entry) => entry.envelope.payloadSha256 === targetHash,
  );
  if (
    idMatches.some((entry) => entry.envelope.payloadSha256 !== targetHash) ||
    hashMatches.some((entry) => entry.envelope.payload.eventId !== targetId)
  ) {
    throw new Error("target vote identity does not match V3 replay");
  }
  const target = idMatches.find((entry) => entry.envelope.payloadSha256 === targetHash);
  const nullifierEvents = input.supplement.inputSet.voteEvents
    .filter(
      (entry) =>
        entry.envelope.payload.questionId ===
          input.bundle.voteEvent.payload.questionId &&
        entry.envelope.payload.questionNullifier === targetNullifier,
    )
    .sort(
      (left, right) => left.envelope.payload.sequence - right.envelope.payload.sequence,
    );
  const latest = nullifierEvents.at(-1) ?? null;
  const counted =
    input.replay.acceptedDirectVotes.find(
      (entry) => entry.questionNullifier === targetNullifier,
    ) ?? null;
  const targetReceipt = target
    ? latestReceipt(input.supplement.inputSet, target.envelope.payloadSha256)
    : null;
  const latestReceiptValue = latest
    ? latestReceipt(input.supplement.inputSet, latest.envelope.payloadSha256)
    : null;
  const status = !target
    ? "not_observed_at_checkpoint"
    : latest?.envelope.payloadSha256 !== target.envelope.payloadSha256
      ? "superseded_at_checkpoint"
      : counted?.voteEventPayloadSha256 === target.envelope.payloadSha256
        ? "counted_at_checkpoint"
        : "not_counted_at_checkpoint";
  return {
    schema: VOTE_STATE_AT_CHECKPOINT_SCHEMA_V3,
    status,
    completenessScope: "complete_question_log_prefix",
    target: {
      eventId: targetId,
      payloadSha256: targetHash,
      questionNullifier: targetNullifier,
    },
    checkpoint: {
      generatedAt: input.supplement.snapshot.payload.generatedAt,
      logId: input.supplement.snapshot.payload.checkpoint.logId,
      questionId: input.supplement.snapshot.payload.questionId,
      rootHash: input.supplement.snapshot.payload.checkpoint.rootHash,
      snapshotId: input.supplement.snapshot.payload.snapshotId,
      snapshotPayloadSha256: input.supplement.snapshot.payloadSha256,
      treeHeadPayloadSha256:
        input.supplement.snapshot.payload.checkpoint.treeHeadPayloadSha256,
      treeSize: input.supplement.snapshot.payload.checkpoint.treeSize,
    },
    targetEvent: target ? checkpointEvent(target) : null,
    targetReceipt: targetReceipt ? checkpointReceipt(targetReceipt) : null,
    latestEventForQuestionNullifier: latest ? checkpointEvent(latest) : null,
    latestReceiptForQuestionNullifier: latestReceiptValue
      ? checkpointReceipt(latestReceiptValue)
      : null,
    countedVote: counted
      ? {
          choiceId: counted.choiceId,
          decisionId: counted.decisionId,
          decisionPayloadSha256: counted.decisionPayloadSha256,
          eventId: counted.voteEventId,
          eventPayloadSha256: counted.voteEventPayloadSha256,
        }
      : null,
  };
}

function checkpointEvent(
  entry: TallyInputSetV3["voteEvents"][number],
): CheckpointEventV3 {
  return {
    eventId: entry.envelope.payload.eventId,
    eventType: entry.envelope.payload.eventType,
    payloadSha256: entry.envelope.payloadSha256,
    sequence: entry.envelope.payload.sequence,
    choiceId: entry.envelope.payload.choiceId,
  };
}

function latestReceipt(inputSet: TallyInputSetV3, eventHash: string) {
  return inputSet.voteReceipts
    .filter((entry) => entry.envelope.payload.voteEventSha256 === eventHash)
    .sort((left, right) => receiptSequence(left) - receiptSequence(right))
    .at(-1)?.envelope;
}

function receiptSequence(entry: TallyInputSetV3["voteReceipts"][number]) {
  return entry.envelope.payload.schema === VOTE_ACCEPTANCE_SCHEMA_V3
    ? 1
    : entry.envelope.payload.sequence;
}

function checkpointReceipt(
  envelope: TallyInputSetV3["voteReceipts"][number]["envelope"],
): CheckpointReceiptV3 {
  return {
    receiptId: envelope.payload.receiptId,
    payloadSha256: envelope.payloadSha256,
    status: envelope.payload.status,
  };
}

async function verifyAuthorizationAttestation(
  authorization: PublicVoteProofBundleV3["questionAuthorization"],
  policy: OfflineVerificationPolicyV3,
) {
  const issuedAt = attestationIssuedAt(authorization.attestationToken);
  const matches: OfflineVerificationPolicyV3["identityAttestationPolicies"] = [];
  for (const candidate of selectIdentityPolicyCandidates(policy, issuedAt)) {
    try {
      await verifyQuestionVotingAuthorizationPkiAttestation({
        token: authorization.attestationToken,
        payload: authorization.payload,
        payloadSha256: authorization.payloadSha256,
        policy: candidate,
      });
      matches.push(candidate);
    } catch {
      // Only the exact immutable image/environment policy may match.
    }
  }
  if (matches.length !== 1) {
    throw new Error(
      matches.length === 0
        ? "question_authorization_attestation_policy_not_found"
        : "question_authorization_attestation_policy_ambiguous",
    );
  }
  return matches[0] as OfflineVerificationPolicyV3["identityAttestationPolicies"][number];
}

function requireBoundVotingPolicy(
  policy: OfflineVerificationPolicyV3,
  selection: {
    protocolBindingSha256: string;
    protocolVersion: string;
    time: string;
  },
  expectedAudience: string,
  label: string,
  errors: string[],
): VotingPolicyV3 | null {
  try {
    const selected = selectVotingPolicyForBinding(policy, selection);
    if (selected.voteServiceAudience !== expectedAudience) {
      errors.push(`${label}:untrusted_vote_service_audience`);
      return null;
    }
    return selected;
  } catch (error) {
    errors.push(`${label}:${message(error)}`);
    return null;
  }
}

function exactKeys(value: Record<string, unknown>, keys: string[], label: string) {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (canonicalizeJson(actual) !== canonicalizeJson(expected)) {
    throw new Error(`${label} must contain only ${expected.join(", ")}`);
  }
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function message(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}
