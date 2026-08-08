import { canonicalizeJson } from "./canonical";
import { base64UrlEncode, canonicalJsonSha256, isSha256Base64Url } from "./encoding";
import { computeMerkleRootFromLeafHashes, merkleLeafHash } from "./merkle";
import { questionVoteLogIdV3 } from "./question-vote-log-v3";
import type { MerkleTreeHeadV3, SignedPayload, VoteReceiptV3 } from "./types";
import {
  BALLOT_MANIFEST_SCHEMA_V3,
  type BallotManifestV3,
  type ProtocolBindingV3,
  QUESTION_VOTING_AUTHORIZATION_SCHEMA_V3,
  type QuestionVotingAuthorizationV3,
  VOTE_EVENT_SCHEMA_V3,
  type VoteEventV3,
} from "./v3-types";
import {
  assertBallotManifestV3,
  assertQuestionVotingAuthorizationV3,
  assertVoteEventV3,
  validateProtocolBindingV3,
  verifyQuestionVotingAuthorizationV3Integrity,
  verifyVoteEventV3AuthorizationBinding,
} from "./v3-validate";
import {
  assertMerkleTreeHeadV3,
  assertVoteAcceptanceV3,
  assertVoteAdjudicationV3,
} from "./validate";

export const TALLY_POLICY_SCHEMA_V3 = "qualified-voting.tally-policy.v3" as const;
export const TALLY_INPUT_SET_SCHEMA_V3 = "qualified-voting.tally-input-set.v3" as const;
export const TALLY_SNAPSHOT_SCHEMA_V3 = "qualified-voting.tally-snapshot.v3" as const;

export type TallyTransparencyCheckpointV3 = {
  logId: string;
  treeSize: number;
  rootHash: string;
  treeHeadPayloadSha256: string;
};

/** One entry in the complete, contiguous question-scoped log prefix. */
export type TallyQuestionLogLeafV3 = {
  leafIndex: number;
  entryType: "vote_event" | "vote_adjudication";
  entryId: string;
  entryPayloadSha256: string;
  leafHash: string;
};

export type TallyVoteEventInputV3 = {
  proofVersion: "qualified-v3";
  envelope: SignedPayload<VoteEventV3>;
};

export type TallyVoteReceiptInputV3 = {
  envelope: SignedPayload<VoteReceiptV3>;
};

/**
 * Public-source material is deliberately identity-free at the tally layer.
 * Direct ballots and scraped positions are independent channels in V3: a
 * source row cannot carry a person key, qualification subject, vote nullifier,
 * or a flag revealing that its known speaker also cast a private ballot.
 */
export type TallySourcePositionInputV3 = {
  inputKind: "source_position";
  positionId: string;
  questionId: string;
  choiceId: string;
  positionType: string;
  credentialClass: string | null;
  status: string;
  isCurrent: boolean;
  countWeight: string;
};

export type TallyGroupResultV3 = {
  groupCode: string;
  count: number;
  weightedCount: number;
};

export type TallyChoiceResultV3 = {
  choiceId: string;
  count: number;
  weightedCount: number;
  rawPercentage: number;
  weightedPercentage: number;
  groups: TallyGroupResultV3[];
};

export type TallyResultV3 = {
  totalCount: number;
  totalWeight: number;
  directVoteCount: number;
  sourcePositionCount: number;
  disputedCount: number;
  groups: TallyGroupResultV3[];
  choices: TallyChoiceResultV3[];
};

export type TallyPolicyV3 = {
  schema: typeof TALLY_POLICY_SCHEMA_V3;
  policyId: string;
  instanceId: string;
  calculationVersion: string;
  positionEligibility: {
    requiredStatus: "counted";
    requireCurrent: true;
    requirePositiveCountWeight: true;
  };
  directVote: {
    precedence: "latest_event_per_nullifier_and_question";
    deduplicationKey: "question_nullifier_and_question_id";
    eventSelection: "highest_sequence";
    adjudicationSelection: "highest_sequence";
    countedDecision: "counted";
    countedEventTypes: Array<"cast" | "replace">;
    groupCode: string;
    weight: number;
  };
  qualifiedVote: {
    eventSchema: typeof VOTE_EVENT_SCHEMA_V3;
    authorizationSchema: typeof QUESTION_VOTING_AUTHORIZATION_SCHEMA_V3;
    authorizationVerification: "pinned_confidential_space_attestation";
    eventSignature: "question_scoped_es256_key";
    /**
     * The attested issuer may only publish this policy-defined classification.
     * Treating the claim as arbitrary public text would leave a path for a
     * buggy issuer to place identity material in an otherwise private
     * authorization.
     */
    eligibilityClaim: string;
  };
  crossChannelPrecedence: {
    /**
     * This is a privacy property, not merely a counting preference. Recreating
     * Same-person suppression would publish a link from a known source speaker
     * to participation in the private-ballot set.
     */
    mode: "independent_channels";
  };
  sourcePositionRules: Array<{
    ruleId: string;
    positionTypes: string[];
    credentialClasses: string[] | null;
    groupCode: string;
    weight: number;
  }>;
  unmatchedSourcePositionTreatment: "exclude";
  rounding: {
    method: "decimal_to_fixed";
    percentageDecimalPlaces: number;
  };
  publishedAt: string;
};

export type TallyInputSetV3 = {
  schema: typeof TALLY_INPUT_SET_SCHEMA_V3;
  questionId: string;
  questionManifest: SignedPayload<BallotManifestV3>;
  ballotManifests: Array<SignedPayload<BallotManifestV3>>;
  questionVotingAuthorizations: QuestionVotingAuthorizationV3[];
  checkpoint: TallyTransparencyCheckpointV3;
  treeHead: SignedPayload<MerkleTreeHeadV3>;
  questionLogLeaves: TallyQuestionLogLeafV3[];
  voteEvents: TallyVoteEventInputV3[];
  voteReceipts: TallyVoteReceiptInputV3[];
  sourcePositions: TallySourcePositionInputV3[];
};

export type TallySnapshotV3 = {
  schema: typeof TALLY_SNAPSHOT_SCHEMA_V3;
  snapshotId: string;
  issueId: string;
  questionId: string;
  questionManifestSha256: string;
  policy: {
    policyId: string;
    payloadSha256: string;
    payload: TallyPolicyV3;
  };
  checkpoint: TallyTransparencyCheckpointV3;
  treeHead: SignedPayload<MerkleTreeHeadV3>;
  inputSet: {
    payloadSha256: string;
    directVoteCount: number;
    sourcePositionCount: number;
  };
  result: TallyResultV3;
  generatedAt: string;
  issuerKeyId: string;
};

export type ReplayedTallyV3 = {
  result: TallyResultV3;
  acceptedDirectVotes: Array<{
    questionNullifier: string;
    voteEventId: string;
    voteEventPayloadSha256: string;
    voteEventSequence: number;
    decisionId: string;
    decisionPayloadSha256: string;
    choiceId: string;
    proofVersion: "qualified-v3";
    groupCode: string;
    weight: number;
  }>;
};

export type TallyVerificationResultV3 =
  | { ok: true; result: TallyResultV3 }
  | { ok: false; errors: string[] };

export class TallyProtocolV3Error extends TypeError {
  readonly errors: string[];

  constructor(errors: string[]) {
    super(`Invalid V3 tally material:\n- ${errors.join("\n- ")}`);
    this.name = "TallyProtocolV3Error";
    this.errors = errors;
  }
}

export function buildTallyPolicyV3(
  input: Omit<TallyPolicyV3, "schema" | "publishedAt"> & {
    publishedAt: Date | string;
  },
): TallyPolicyV3 {
  const policy: TallyPolicyV3 = {
    schema: TALLY_POLICY_SCHEMA_V3,
    ...structuredClone(input),
    policyId: requiredString(input.policyId, "policyId"),
    instanceId: requiredString(input.instanceId, "instanceId"),
    calculationVersion: requiredString(input.calculationVersion, "calculationVersion"),
    directVote: {
      ...structuredClone(input.directVote),
      countedEventTypes: (["cast", "replace"] as const).filter((kind) =>
        input.directVote.countedEventTypes.includes(kind),
      ),
      groupCode: requiredString(input.directVote.groupCode, "groupCode"),
    },
    qualifiedVote: {
      ...structuredClone(input.qualifiedVote),
      eligibilityClaim: requiredString(
        input.qualifiedVote.eligibilityClaim,
        "eligibilityClaim",
      ),
    },
    sourcePositionRules: input.sourcePositionRules
      .map((rule) => ({
        ...structuredClone(rule),
        ruleId: requiredString(rule.ruleId, "ruleId"),
        positionTypes: canonicalStrings(rule.positionTypes),
        credentialClasses:
          rule.credentialClasses === null
            ? null
            : canonicalStrings(rule.credentialClasses),
        groupCode: requiredString(rule.groupCode, "groupCode"),
      }))
      .sort((left, right) => left.ruleId.localeCompare(right.ruleId)),
    publishedAt: normalizedTimestamp(input.publishedAt, "publishedAt"),
  };
  assertTallyPolicyV3(policy);
  return policy;
}

export function buildTallyInputSetV3(
  input: Omit<TallyInputSetV3, "schema">,
): TallyInputSetV3 {
  const inputSet: TallyInputSetV3 = {
    schema: TALLY_INPUT_SET_SCHEMA_V3,
    questionId: requiredString(input.questionId, "questionId"),
    questionManifest: structuredClone(input.questionManifest),
    ballotManifests: input.ballotManifests
      .map((value) => structuredClone(value))
      .sort((left, right) => left.payloadSha256.localeCompare(right.payloadSha256)),
    questionVotingAuthorizations: input.questionVotingAuthorizations
      .map((value) => structuredClone(value))
      .sort((left, right) => left.payloadSha256.localeCompare(right.payloadSha256)),
    checkpoint: { ...input.checkpoint },
    treeHead: structuredClone(input.treeHead),
    questionLogLeaves: input.questionLogLeaves
      .map((value) => structuredClone(value))
      .sort((left, right) => left.leafIndex - right.leafIndex),
    voteEvents: input.voteEvents
      .map((value) => structuredClone(value))
      .sort((left, right) => {
        const a = left.envelope.payload;
        const b = right.envelope.payload;
        return (
          a.questionNullifier.localeCompare(b.questionNullifier) ||
          a.sequence - b.sequence
        );
      }),
    voteReceipts: input.voteReceipts
      .map((value) => structuredClone(value))
      .sort((left, right) =>
        left.envelope.payloadSha256.localeCompare(right.envelope.payloadSha256),
      ),
    sourcePositions: input.sourcePositions
      .map((value) => structuredClone(value))
      .sort((left, right) => left.positionId.localeCompare(right.positionId)),
  };
  assertTallyInputSetV3(inputSet);
  return inputSet;
}

export async function replayTallyV3(
  policy: TallyPolicyV3,
  inputSet: TallyInputSetV3,
): Promise<ReplayedTallyV3> {
  assertTallyPolicyV3(policy);
  assertTallyInputSetV3(inputSet);
  const graph = await validateReplayGraphV3(policy, inputSet);
  if (graph.errors.length > 0) {
    throw new TallyProtocolV3Error(graph.errors);
  }

  const choices = inputSet.questionManifest.payload.meaning.choices
    .filter((choice) => choice.isCounted)
    .sort(
      (left, right) =>
        left.displayOrder - right.displayOrder || left.id.localeCompare(right.id),
    );
  const choiceIds = new Set(choices.map((choice) => choice.id));
  const latestByNullifier = new Map<string, TallyVoteEventInputV3>();
  for (const entry of inputSet.voteEvents) {
    const event = entry.envelope.payload;
    const previous = latestByNullifier.get(event.questionNullifier);
    if (!previous || event.sequence > previous.envelope.payload.sequence) {
      latestByNullifier.set(event.questionNullifier, entry);
    }
  }

  const acceptedDirectVotes: ReplayedTallyV3["acceptedDirectVotes"] = [];
  const counted: CountedInputV3[] = [];
  for (const entry of latestByNullifier.values()) {
    const event = entry.envelope.payload;
    const receipts = graph.receiptsByEventHash.get(entry.envelope.payloadSha256);
    const latestReceipt = receipts?.at(-1);
    if (
      !latestReceipt ||
      latestReceipt.envelope.payload.status !== policy.directVote.countedDecision ||
      !policy.directVote.countedEventTypes.includes(
        event.eventType as "cast" | "replace",
      ) ||
      event.choiceId === null ||
      !choiceIds.has(event.choiceId)
    ) {
      continue;
    }
    counted.push({
      choiceId: event.choiceId,
      groupCode: policy.directVote.groupCode,
      kind: "direct_vote",
      weight: policy.directVote.weight,
    });
    acceptedDirectVotes.push({
      questionNullifier: event.questionNullifier,
      voteEventId: event.eventId,
      voteEventPayloadSha256: entry.envelope.payloadSha256,
      voteEventSequence: event.sequence,
      decisionId: latestReceipt.envelope.payload.receiptId,
      decisionPayloadSha256: latestReceipt.envelope.payloadSha256,
      choiceId: event.choiceId,
      proofVersion: "qualified-v3",
      groupCode: policy.directVote.groupCode,
      weight: policy.directVote.weight,
    });
  }
  acceptedDirectVotes.sort((left, right) =>
    left.questionNullifier.localeCompare(right.questionNullifier),
  );

  for (const position of inputSet.sourcePositions) {
    if (!isCountablePosition(position) || !choiceIds.has(position.choiceId)) {
      continue;
    }
    const rule = matchingSourceRules(policy, position)[0];
    if (!rule) continue;
    counted.push({
      choiceId: position.choiceId,
      groupCode: rule.groupCode,
      kind: "source_position",
      weight: rule.weight,
    });
  }

  const totalWeight = counted.reduce((sum, entry) => sum + entry.weight, 0);
  const resultChoices: TallyChoiceResultV3[] = choices.map((choice) => {
    const matching = counted.filter((entry) => entry.choiceId === choice.id);
    const weightedCount = matching.reduce((sum, entry) => sum + entry.weight, 0);
    return {
      choiceId: choice.id,
      count: matching.length,
      weightedCount,
      rawPercentage: percentage(
        matching.length,
        counted.length,
        policy.rounding.percentageDecimalPlaces,
      ),
      weightedPercentage: percentage(
        weightedCount,
        totalWeight,
        policy.rounding.percentageDecimalPlaces,
      ),
      groups: aggregateGroups(matching),
    };
  });
  const result: TallyResultV3 = {
    totalCount: counted.length,
    totalWeight,
    directVoteCount: counted.filter((entry) => entry.kind === "direct_vote").length,
    sourcePositionCount: counted.filter((entry) => entry.kind === "source_position")
      .length,
    disputedCount: inputSet.sourcePositions.filter(
      (position) =>
        position.questionId === inputSet.questionId && position.status === "disputed",
    ).length,
    groups: aggregateGroups(counted),
    choices: resultChoices,
  };
  return { acceptedDirectVotes, result };
}

export async function buildTallySnapshotV3(input: {
  snapshotId: string;
  issueId: string;
  policy: TallyPolicyV3;
  inputSet: TallyInputSetV3;
  generatedAt: Date | string;
  issuerKeyId: string;
}): Promise<TallySnapshotV3> {
  const replay = await replayTallyV3(input.policy, input.inputSet);
  const snapshot: TallySnapshotV3 = {
    schema: TALLY_SNAPSHOT_SCHEMA_V3,
    snapshotId: requiredString(input.snapshotId, "snapshotId"),
    issueId: requiredString(input.issueId, "issueId"),
    questionId: input.inputSet.questionId,
    questionManifestSha256: input.inputSet.questionManifest.payloadSha256,
    policy: {
      policyId: input.policy.policyId,
      payloadSha256: await canonicalJsonSha256(input.policy),
      payload: structuredClone(input.policy),
    },
    checkpoint: { ...input.inputSet.checkpoint },
    treeHead: structuredClone(input.inputSet.treeHead),
    inputSet: {
      payloadSha256: await canonicalJsonSha256(input.inputSet),
      directVoteCount: replay.result.directVoteCount,
      sourcePositionCount: replay.result.sourcePositionCount,
    },
    result: replay.result,
    generatedAt: normalizedTimestamp(input.generatedAt, "generatedAt"),
    issuerKeyId: requiredString(input.issuerKeyId, "issuerKeyId"),
  };
  assertTallySnapshotV3(snapshot);
  return snapshot;
}

export async function verifyTallySnapshotStructureV3(input: {
  snapshot: TallySnapshotV3 | SignedPayload<TallySnapshotV3>;
  policy?: TallyPolicyV3;
  inputSet: TallyInputSetV3;
  /**
   * Independently obtained latest head (for example from a witness). Supplying
   * it makes a previously valid but now stale snapshot fail offline.
   */
  expectedLatestQuestionTreeHead?: SignedPayload<MerkleTreeHeadV3>;
}): Promise<TallyVerificationResultV3> {
  const envelope = isSignedEnvelope(input.snapshot) ? input.snapshot : null;
  const snapshot = envelope?.payload ?? input.snapshot;
  const errors: string[] = [];
  try {
    assertTallySnapshotV3(snapshot);
    assertTallyInputSetV3(input.inputSet);
    const policy = input.policy ?? snapshot.policy.payload;
    assertTallyPolicyV3(policy);
    const [policyHash, inputSetHash] = await Promise.all([
      canonicalJsonSha256(policy),
      canonicalJsonSha256(input.inputSet),
    ]);
    if (
      snapshot.policy.policyId !== policy.policyId ||
      snapshot.policy.payloadSha256 !== policyHash ||
      canonicalizeJson(snapshot.policy.payload) !== canonicalizeJson(policy)
    ) {
      errors.push("snapshot policy does not match the supplied V3 policy");
    }
    if (snapshot.inputSet.payloadSha256 !== inputSetHash) {
      errors.push("snapshot input-set hash does not match replay material");
    }
    if (
      snapshot.questionId !== input.inputSet.questionId ||
      snapshot.questionManifestSha256 !== input.inputSet.questionManifest.payloadSha256
    ) {
      errors.push("snapshot question does not match replay material");
    }
    if (
      canonicalizeJson(snapshot.checkpoint) !==
        canonicalizeJson(input.inputSet.checkpoint) ||
      canonicalizeJson(snapshot.treeHead) !== canonicalizeJson(input.inputSet.treeHead)
    ) {
      errors.push("snapshot checkpoint does not match replay material");
    }
    if (input.expectedLatestQuestionTreeHead) {
      const latest = input.expectedLatestQuestionTreeHead;
      assertMerkleTreeHeadV3(latest.payload);
      if (
        (await canonicalJsonSha256(latest.payload)) !== latest.payloadSha256 ||
        latest.payload.issuerKeyId !== latest.signature.keyId
      ) {
        errors.push("expected latest question tree head is malformed");
      } else if (
        latest.payload.logId !== snapshot.checkpoint.logId ||
        latest.payload.treeSize !== snapshot.checkpoint.treeSize ||
        latest.payload.rootHash !== snapshot.checkpoint.rootHash ||
        latest.payloadSha256 !== snapshot.checkpoint.treeHeadPayloadSha256
      ) {
        errors.push(
          "snapshot does not match the independently supplied latest question tree head",
        );
      }
    }
    if (envelope) {
      if ((await canonicalJsonSha256(snapshot)) !== envelope.payloadSha256) {
        errors.push("snapshot payload hash is invalid");
      }
      if (snapshot.issuerKeyId !== envelope.signature.keyId) {
        errors.push("snapshot issuer and signature key do not match");
      }
    }
    const replay = await replayTallyV3(policy, input.inputSet);
    if (canonicalizeJson(snapshot.result) !== canonicalizeJson(replay.result)) {
      errors.push("snapshot result does not match deterministic V3 replay");
    }
    if (
      snapshot.inputSet.directVoteCount !== replay.result.directVoteCount ||
      snapshot.inputSet.sourcePositionCount !== replay.result.sourcePositionCount
    ) {
      errors.push("snapshot input counts do not match deterministic V3 replay");
    }
    return errors.length > 0
      ? { ok: false, errors }
      : { ok: true, result: replay.result };
  } catch (error) {
    return { ok: false, errors: [...errors, ...errorMessages(error)] };
  }
}

export function assertTallyPolicyV3(value: unknown): asserts value is TallyPolicyV3 {
  const errors: string[] = [];
  if (!record(value)) {
    throw new TallyProtocolV3Error(["policy must be an object"]);
  }
  exactKeys(
    value,
    [
      "schema",
      "policyId",
      "instanceId",
      "calculationVersion",
      "positionEligibility",
      "directVote",
      "qualifiedVote",
      "crossChannelPrecedence",
      "sourcePositionRules",
      "unmatchedSourcePositionTreatment",
      "rounding",
      "publishedAt",
    ],
    "policy",
    errors,
  );
  if (value.schema !== TALLY_POLICY_SCHEMA_V3) {
    errors.push("unsupported V3 tally policy schema");
  }
  for (const key of ["policyId", "instanceId", "calculationVersion"]) {
    nonEmpty(value[key], `policy.${key}`, errors);
  }
  timestamp(value.publishedAt, "policy.publishedAt", errors);
  exactConstantObject(
    value.positionEligibility,
    {
      requiredStatus: "counted",
      requireCurrent: true,
      requirePositiveCountWeight: true,
    },
    "policy.positionEligibility",
    errors,
  );
  exactConstantObject(
    value.crossChannelPrecedence,
    { mode: "independent_channels" },
    "policy.crossChannelPrecedence",
    errors,
  );
  if (!record(value.qualifiedVote)) {
    errors.push("policy.qualifiedVote must be an object");
  } else {
    exactKeys(
      value.qualifiedVote,
      [
        "eventSchema",
        "authorizationSchema",
        "authorizationVerification",
        "eventSignature",
        "eligibilityClaim",
      ],
      "policy.qualifiedVote",
      errors,
    );
    constants(
      value.qualifiedVote,
      {
        eventSchema: VOTE_EVENT_SCHEMA_V3,
        authorizationSchema: QUESTION_VOTING_AUTHORIZATION_SCHEMA_V3,
        authorizationVerification: "pinned_confidential_space_attestation",
        eventSignature: "question_scoped_es256_key",
      },
      "policy.qualifiedVote",
      errors,
    );
    nonEmpty(
      value.qualifiedVote.eligibilityClaim,
      "policy.qualifiedVote.eligibilityClaim",
      errors,
    );
  }
  if (!record(value.directVote)) {
    errors.push("policy.directVote must be an object");
  } else {
    exactKeys(
      value.directVote,
      [
        "precedence",
        "deduplicationKey",
        "eventSelection",
        "adjudicationSelection",
        "countedDecision",
        "countedEventTypes",
        "groupCode",
        "weight",
      ],
      "policy.directVote",
      errors,
    );
    constants(
      value.directVote,
      {
        precedence: "latest_event_per_nullifier_and_question",
        deduplicationKey: "question_nullifier_and_question_id",
        eventSelection: "highest_sequence",
        adjudicationSelection: "highest_sequence",
        countedDecision: "counted",
      },
      "policy.directVote",
      errors,
    );
    nonEmpty(value.directVote.groupCode, "policy.directVote.groupCode", errors);
    positiveNumber(value.directVote.weight, "policy.directVote.weight", errors);
    if (
      !Array.isArray(value.directVote.countedEventTypes) ||
      value.directVote.countedEventTypes.length !== 2 ||
      value.directVote.countedEventTypes[0] !== "cast" ||
      value.directVote.countedEventTypes[1] !== "replace"
    ) {
      errors.push("policy.directVote.countedEventTypes must be exactly cast,replace");
    }
  }
  if (!Array.isArray(value.sourcePositionRules)) {
    errors.push("policy.sourcePositionRules must be an array");
  } else {
    const ruleIds = new Set<string>();
    for (const [index, candidate] of value.sourcePositionRules.entries()) {
      const path = `policy.sourcePositionRules[${index}]`;
      if (!record(candidate)) {
        errors.push(`${path} must be an object`);
        continue;
      }
      exactKeys(
        candidate,
        ["ruleId", "positionTypes", "credentialClasses", "groupCode", "weight"],
        path,
        errors,
      );
      nonEmpty(candidate.ruleId, `${path}.ruleId`, errors);
      if (typeof candidate.ruleId === "string") {
        if (ruleIds.has(candidate.ruleId)) {
          errors.push(`${path}.ruleId must be unique`);
        }
        ruleIds.add(candidate.ruleId);
      }
      stringArray(candidate.positionTypes, `${path}.positionTypes`, errors);
      if (candidate.credentialClasses !== null) {
        stringArray(candidate.credentialClasses, `${path}.credentialClasses`, errors);
      }
      nonEmpty(candidate.groupCode, `${path}.groupCode`, errors);
      positiveNumber(candidate.weight, `${path}.weight`, errors);
    }
  }
  if (value.unmatchedSourcePositionTreatment !== "exclude") {
    errors.push("policy.unmatchedSourcePositionTreatment must equal exclude");
  }
  if (!record(value.rounding)) {
    errors.push("policy.rounding must be an object");
  } else {
    exactKeys(
      value.rounding,
      ["method", "percentageDecimalPlaces"],
      "policy.rounding",
      errors,
    );
    if (value.rounding.method !== "decimal_to_fixed") {
      errors.push("policy.rounding.method must equal decimal_to_fixed");
    }
    integer(
      value.rounding.percentageDecimalPlaces,
      "policy.rounding.percentageDecimalPlaces",
      errors,
      0,
      6,
    );
  }
  if (errors.length > 0) throw new TallyProtocolV3Error(errors);
}

export function assertTallyInputSetV3(
  value: unknown,
): asserts value is TallyInputSetV3 {
  const errors: string[] = [];
  if (!record(value)) {
    throw new TallyProtocolV3Error(["inputSet must be an object"]);
  }
  exactKeys(
    value,
    [
      "schema",
      "questionId",
      "questionManifest",
      "ballotManifests",
      "questionVotingAuthorizations",
      "checkpoint",
      "treeHead",
      "questionLogLeaves",
      "voteEvents",
      "voteReceipts",
      "sourcePositions",
    ],
    "inputSet",
    errors,
  );
  if (value.schema !== TALLY_INPUT_SET_SCHEMA_V3) {
    errors.push("unsupported V3 tally input-set schema");
  }
  nonEmpty(value.questionId, "inputSet.questionId", errors);
  signedEnvelope(
    value.questionManifest,
    "inputSet.questionManifest",
    errors,
    assertBallotManifestV3,
    "Ed25519",
  );
  arrayOf(
    value.ballotManifests,
    "inputSet.ballotManifests",
    errors,
    (candidate, path) =>
      signedEnvelope(candidate, path, errors, assertBallotManifestV3, "Ed25519"),
  );
  arrayOf(
    value.questionVotingAuthorizations,
    "inputSet.questionVotingAuthorizations",
    errors,
    (candidate, path) =>
      captureAssertion(
        () => assertQuestionVotingAuthorizationV3(candidate),
        path,
        errors,
      ),
  );
  checkpoint(value.checkpoint, "inputSet.checkpoint", errors);
  signedEnvelope(
    value.treeHead,
    "inputSet.treeHead",
    errors,
    assertMerkleTreeHeadV3,
    "Ed25519",
  );
  arrayOf(
    value.questionLogLeaves,
    "inputSet.questionLogLeaves",
    errors,
    (candidate, path) => questionLogLeaf(candidate, path, errors),
  );
  arrayOf(value.voteEvents, "inputSet.voteEvents", errors, (candidate, path) => {
    if (!record(candidate)) {
      errors.push(`${path} must be an object`);
      return;
    }
    exactKeys(candidate, ["proofVersion", "envelope"], path, errors);
    if (candidate.proofVersion !== "qualified-v3") {
      errors.push(`${path}.proofVersion must equal qualified-v3`);
    }
    signedEnvelope(
      candidate.envelope,
      `${path}.envelope`,
      errors,
      assertVoteEventV3,
      "ES256",
    );
  });
  arrayOf(value.voteReceipts, "inputSet.voteReceipts", errors, (candidate, path) => {
    if (!record(candidate)) {
      errors.push(`${path} must be an object`);
      return;
    }
    exactKeys(candidate, ["envelope"], path, errors);
    signedEnvelope(
      candidate.envelope,
      `${path}.envelope`,
      errors,
      assertVoteReceipt,
      "Ed25519",
    );
  });
  arrayOf(
    value.sourcePositions,
    "inputSet.sourcePositions",
    errors,
    (candidate, path) => sourcePosition(candidate, path, errors),
  );
  if (errors.length > 0) throw new TallyProtocolV3Error(errors);
}

export function assertTallySnapshotV3(
  value: unknown,
): asserts value is TallySnapshotV3 {
  const errors: string[] = [];
  if (!record(value)) {
    throw new TallyProtocolV3Error(["snapshot must be an object"]);
  }
  exactKeys(
    value,
    [
      "schema",
      "snapshotId",
      "issueId",
      "questionId",
      "questionManifestSha256",
      "policy",
      "checkpoint",
      "treeHead",
      "inputSet",
      "result",
      "generatedAt",
      "issuerKeyId",
    ],
    "snapshot",
    errors,
  );
  if (value.schema !== TALLY_SNAPSHOT_SCHEMA_V3) {
    errors.push("unsupported V3 tally snapshot schema");
  }
  for (const key of ["snapshotId", "issueId", "questionId", "issuerKeyId"]) {
    nonEmpty(value[key], `snapshot.${key}`, errors);
  }
  digest(value.questionManifestSha256, "snapshot.questionManifestSha256", errors);
  timestamp(value.generatedAt, "snapshot.generatedAt", errors);
  if (!record(value.policy)) {
    errors.push("snapshot.policy must be an object");
  } else {
    const policy = value.policy;
    exactKeys(
      policy,
      ["policyId", "payloadSha256", "payload"],
      "snapshot.policy",
      errors,
    );
    nonEmpty(policy.policyId, "snapshot.policy.policyId", errors);
    digest(policy.payloadSha256, "snapshot.policy.payloadSha256", errors);
    captureAssertion(
      () => assertTallyPolicyV3(policy.payload),
      "snapshot.policy.payload",
      errors,
    );
  }
  checkpoint(value.checkpoint, "snapshot.checkpoint", errors);
  signedEnvelope(
    value.treeHead,
    "snapshot.treeHead",
    errors,
    assertMerkleTreeHeadV3,
    "Ed25519",
  );
  if (!record(value.inputSet)) {
    errors.push("snapshot.inputSet must be an object");
  } else {
    exactKeys(
      value.inputSet,
      ["payloadSha256", "directVoteCount", "sourcePositionCount"],
      "snapshot.inputSet",
      errors,
    );
    digest(value.inputSet.payloadSha256, "snapshot.inputSet.payloadSha256", errors);
    integer(
      value.inputSet.directVoteCount,
      "snapshot.inputSet.directVoteCount",
      errors,
      0,
    );
    integer(
      value.inputSet.sourcePositionCount,
      "snapshot.inputSet.sourcePositionCount",
      errors,
      0,
    );
  }
  tallyResult(value.result, "snapshot.result", errors);
  if (errors.length > 0) throw new TallyProtocolV3Error(errors);
}

async function validateReplayGraphV3(policy: TallyPolicyV3, input: TallyInputSetV3) {
  const errors: string[] = [];
  const expectedPolicyHash = await canonicalJsonSha256(policy);
  const expectedQuestionLogId = await questionVoteLogIdV3({
    instanceId: policy.instanceId,
    questionId: input.questionId,
  });
  const selectedManifest = input.questionManifest;
  await checkEnvelopeHash(selectedManifest, "question manifest", errors);
  if (
    selectedManifest.payload.schema !== BALLOT_MANIFEST_SCHEMA_V3 ||
    selectedManifest.payload.questionId !== input.questionId
  ) {
    errors.push("selected ballot manifest does not identify the target question");
  }
  checkBindingPolicy(
    selectedManifest.payload.binding,
    policy,
    expectedPolicyHash,
    "selected ballot manifest",
    errors,
  );
  const selectedMeaning = canonicalizeJson(selectedManifest.payload.meaning.choices);

  const manifestsByHash = new Map<string, SignedPayload<BallotManifestV3>>();
  for (const manifest of input.ballotManifests) {
    await checkEnvelopeHash(manifest, "ballot manifest", errors);
    if (manifestsByHash.has(manifest.payloadSha256)) {
      errors.push(`duplicate ballot manifest ${manifest.payloadSha256}`);
    }
    manifestsByHash.set(manifest.payloadSha256, manifest);
    if (
      manifest.payload.questionId !== input.questionId ||
      manifest.payload.ballotId !== selectedManifest.payload.ballotId ||
      manifest.payload.nullifierKeyEpoch !==
        selectedManifest.payload.nullifierKeyEpoch ||
      canonicalizeJson(manifest.payload.meaning.choices) !== selectedMeaning ||
      canonicalizeJson(manifest.payload.binding) !==
        canonicalizeJson(selectedManifest.payload.binding)
    ) {
      errors.push(
        `ballot manifest ${manifest.payload.manifestId} changes the target ballot meaning or binding`,
      );
    }
    checkBindingPolicy(
      manifest.payload.binding,
      policy,
      expectedPolicyHash,
      `ballot manifest ${manifest.payload.manifestId}`,
      errors,
    );
  }
  if (!manifestsByHash.has(selectedManifest.payloadSha256)) {
    errors.push("ballotManifests must contain the selected manifest");
  }

  const authorizationsByHash = new Map<string, QuestionVotingAuthorizationV3>();
  for (const authorization of input.questionVotingAuthorizations) {
    const integrity = await verifyQuestionVotingAuthorizationV3Integrity(authorization);
    if (!integrity.ok) {
      errors.push(
        ...integrity.errors.map(
          (error) => `question authorization ${authorization.payloadSha256}: ${error}`,
        ),
      );
      continue;
    }
    if (authorizationsByHash.has(authorization.payloadSha256)) {
      errors.push(`duplicate question authorization ${authorization.payloadSha256}`);
    }
    authorizationsByHash.set(authorization.payloadSha256, authorization);
    if (
      authorization.payload.questionId !== input.questionId ||
      canonicalizeJson(authorization.payload.binding) !==
        canonicalizeJson(selectedManifest.payload.binding)
    ) {
      errors.push(
        `question authorization ${authorization.payloadSha256} is outside the target question or binding`,
      );
    }
    if (
      authorization.payload.eligibility.claim !== policy.qualifiedVote.eligibilityClaim
    ) {
      errors.push(
        `question authorization ${authorization.payloadSha256} has an eligibility claim outside the V3 tally policy`,
      );
    }
    checkBindingPolicy(
      authorization.payload.binding,
      policy,
      expectedPolicyHash,
      `question authorization ${authorization.payloadSha256}`,
      errors,
    );
  }

  const eventsByHash = new Map<string, TallyVoteEventInputV3>();
  const eventsById = new Map<string, TallyVoteEventInputV3>();
  const usedAuthorizationHashes = new Set<string>();
  for (const entry of input.voteEvents) {
    const event = entry.envelope.payload;
    await checkEnvelopeHash(entry.envelope, `vote event ${event.eventId}`, errors);
    if (
      eventsByHash.has(entry.envelope.payloadSha256) ||
      eventsById.has(event.eventId)
    ) {
      errors.push(`duplicate vote event ${event.eventId}`);
    }
    eventsByHash.set(entry.envelope.payloadSha256, entry);
    eventsById.set(event.eventId, entry);
    if (event.questionId !== input.questionId) {
      errors.push(`vote event ${event.eventId} is for another question`);
    }
    const authorization = authorizationsByHash.get(event.authorizationSha256);
    if (!authorization) {
      errors.push(`vote event ${event.eventId} has no public question authorization`);
    } else {
      usedAuthorizationHashes.add(authorization.payloadSha256);
      const binding = await verifyVoteEventV3AuthorizationBinding({
        event,
        authorization,
      });
      if (!binding.ok) {
        errors.push(
          ...binding.errors.map((error) => `vote event ${event.eventId}: ${error}`),
        );
      }
    }
    const manifest = manifestsByHash.get(event.ballotManifestSha256);
    if (
      !manifest ||
      manifest.payload.questionId !== event.questionId ||
      manifest.payload.ballotId !== event.ballotId
    ) {
      errors.push(`vote event ${event.eventId} has no matching ballot manifest`);
    } else if (
      event.choiceId !== null &&
      !manifest.payload.meaning.choices.some((choice) => choice.id === event.choiceId)
    ) {
      errors.push(`vote event ${event.eventId} names an unknown choice`);
    }
    if (
      authorization &&
      manifest &&
      authorization.payload.nullifierKeyEpoch !== manifest.payload.nullifierKeyEpoch
    ) {
      errors.push(
        `vote event ${event.eventId} authorization and ballot manifest use different nullifier epochs`,
      );
    }
    if (
      (event.eventType === "withdraw" && event.choiceId !== null) ||
      (event.eventType !== "withdraw" && event.choiceId === null)
    ) {
      errors.push(`vote event ${event.eventId} has an invalid choice shape`);
    }
  }
  for (const authorizationHash of authorizationsByHash.keys()) {
    if (!usedAuthorizationHashes.has(authorizationHash)) {
      errors.push(`unused question authorization ${authorizationHash}`);
    }
  }

  const chains = new Map<string, TallyVoteEventInputV3[]>();
  for (const entry of input.voteEvents) {
    const nullifier = entry.envelope.payload.questionNullifier;
    const chain = chains.get(nullifier) ?? [];
    chain.push(entry);
    chains.set(nullifier, chain);
  }
  for (const [nullifier, chain] of chains) {
    chain.sort(
      (left, right) => left.envelope.payload.sequence - right.envelope.payload.sequence,
    );
    for (let index = 0; index < chain.length; index += 1) {
      const entry = chain[index];
      if (!entry) continue;
      const event = entry.envelope.payload;
      const previous = chain[index - 1];
      if (
        event.sequence !== index + 1 ||
        event.eventType !==
          (index === 0
            ? "cast"
            : event.eventType === "withdraw"
              ? "withdraw"
              : "replace") ||
        event.previousEventSha256 !== (previous?.envelope.payloadSha256 ?? null)
      ) {
        errors.push(`vote chain ${nullifier} is not contiguous`);
      }
    }
  }

  const receiptsByEventHash = new Map<string, TallyVoteReceiptInputV3[]>();
  const receiptsByHash = new Map<string, TallyVoteReceiptInputV3>();
  const receiptsById = new Map<string, TallyVoteReceiptInputV3>();
  for (const receipt of input.voteReceipts) {
    const payload = receipt.envelope.payload;
    await checkEnvelopeHash(
      receipt.envelope,
      `vote receipt ${payload.receiptId}`,
      errors,
    );
    if (
      receiptsByHash.has(receipt.envelope.payloadSha256) ||
      receiptsById.has(payload.receiptId)
    ) {
      errors.push(`duplicate vote receipt ${payload.receiptId}`);
    }
    receiptsByHash.set(receipt.envelope.payloadSha256, receipt);
    receiptsById.set(payload.receiptId, receipt);
    if (!eventsByHash.has(payload.voteEventSha256)) {
      errors.push(`vote receipt ${payload.receiptId} references an unpublished event`);
    }
    if (payload.logId !== expectedQuestionLogId) {
      errors.push(
        `vote receipt ${payload.receiptId} is bound to the wrong question log`,
      );
    }
    if (
      payload.schema === "qualified-opinion.vote-adjudication.v3" &&
      (payload.eligibilityAssertionSha256 !== null ||
        payload.eligibilityDecisionSha256 !== null)
    ) {
      errors.push(
        `V3 vote receipt ${payload.receiptId} must not publish eligibility links`,
      );
    }
    const current = receiptsByEventHash.get(payload.voteEventSha256) ?? [];
    current.push(receipt);
    receiptsByEventHash.set(payload.voteEventSha256, current);
  }
  for (const [eventHash, receipts] of receiptsByEventHash) {
    receipts.sort((left, right) => receiptSequence(left) - receiptSequence(right));
    for (let index = 0; index < receipts.length; index += 1) {
      const receipt = receipts[index];
      if (!receipt) continue;
      const payload = receipt.envelope.payload;
      const previous = receipts[index - 1];
      if (
        receiptSequence(receipt) !== index + 1 ||
        (index === 0 && payload.schema !== "qualified-opinion.vote-acceptance.v3") ||
        (index > 0 &&
          (payload.schema !== "qualified-opinion.vote-adjudication.v3" ||
            payload.previousReceiptSha256 !== previous?.envelope.payloadSha256))
      ) {
        errors.push(`receipt chain for event ${eventHash} is not contiguous`);
      }
    }
  }
  for (const eventHash of eventsByHash.keys()) {
    if (!receiptsByEventHash.has(eventHash)) {
      errors.push(`vote event ${eventHash} has no receipt`);
    }
  }

  if (input.checkpoint.logId !== expectedQuestionLogId) {
    errors.push("transparency checkpoint is for the wrong question log");
  }
  if (input.questionLogLeaves.length !== input.checkpoint.treeSize) {
    errors.push(
      "question log prefix length must exactly equal the checkpoint tree size",
    );
  }
  const leafByEntry = new Map<string, TallyQuestionLogLeafV3>();
  const leafHashes = new Set<string>();
  for (let index = 0; index < input.questionLogLeaves.length; index += 1) {
    const leaf = input.questionLogLeaves[index];
    if (!leaf) continue;
    const key = `${leaf.entryType}:${leaf.entryId}`;
    if (leaf.leafIndex !== index) {
      errors.push(`question log prefix is not contiguous at leaf index ${index}`);
    }
    if (leafByEntry.has(key)) {
      errors.push(`duplicate question log entry ${key}`);
    }
    if (leafHashes.has(leaf.leafHash)) {
      errors.push(`duplicate question log leaf hash ${leaf.leafHash}`);
    }
    leafByEntry.set(key, leaf);
    leafHashes.add(leaf.leafHash);
    const expected =
      leaf.entryType === "vote_event"
        ? eventsById.get(leaf.entryId)?.envelope
        : receiptsById.get(leaf.entryId)?.envelope;
    if (!expected || expected.payloadSha256 !== leaf.entryPayloadSha256) {
      errors.push(`question log entry ${key} has no matching artifact`);
      continue;
    }
    const leafData = canonicalizeJson({
      entryId: leaf.entryId,
      entryPayloadHash: leaf.entryPayloadSha256,
      entryType: leaf.entryType,
    });
    const expectedLeafHash = base64UrlEncode(await merkleLeafHash(leafData));
    if (leaf.leafHash !== expectedLeafHash) {
      errors.push(`question log entry ${key} has an invalid leaf hash`);
    }
  }
  const recomputedRoot = base64UrlEncode(
    await computeMerkleRootFromLeafHashes(
      input.questionLogLeaves.map((leaf) => leaf.leafHash),
    ),
  );
  if (recomputedRoot !== input.checkpoint.rootHash) {
    errors.push("question log prefix does not recompute to the checkpoint root");
  }
  for (const entry of input.voteEvents) {
    const key = `vote_event:${entry.envelope.payload.eventId}`;
    if (!leafByEntry.has(key)) {
      errors.push(`vote event ${entry.envelope.payload.eventId} is not logged`);
    }
  }
  for (const entry of input.voteReceipts) {
    const key = `vote_adjudication:${entry.envelope.payload.receiptId}`;
    if (!leafByEntry.has(key)) {
      errors.push(`vote receipt ${entry.envelope.payload.receiptId} is not logged`);
    }
  }

  await checkEnvelopeHash(input.treeHead, "transparency tree head", errors);
  if (
    input.treeHead.payload.logId !== input.checkpoint.logId ||
    input.treeHead.payload.treeSize !== input.checkpoint.treeSize ||
    input.treeHead.payload.rootHash !== input.checkpoint.rootHash ||
    input.treeHead.payloadSha256 !== input.checkpoint.treeHeadPayloadSha256 ||
    input.treeHead.payload.issuerKeyId !== input.treeHead.signature.keyId
  ) {
    errors.push("transparency checkpoint does not match its signed tree head");
  }

  for (const position of input.sourcePositions) {
    if (position.questionId !== input.questionId) {
      errors.push(`source position ${position.positionId} is for another question`);
    }
    const matches = matchingSourceRules(policy, position);
    if (matches.length > 1) {
      errors.push(`source position ${position.positionId} matches multiple rules`);
    }
  }
  return { errors, receiptsByEventHash };
}

function checkBindingPolicy(
  binding: ProtocolBindingV3,
  policy: TallyPolicyV3,
  policyHash: string,
  label: string,
  errors: string[],
) {
  const valid = validateProtocolBindingV3(binding);
  if (!valid.ok) {
    errors.push(...valid.errors.map((error) => `${label}: ${error}`));
    return;
  }
  if (
    binding.instance.id !== policy.instanceId ||
    binding.tallyPolicy.id !== policy.policyId ||
    binding.tallyPolicy.sha256 !== policyHash
  ) {
    errors.push(`${label} does not bind the supplied V3 tally policy`);
  }
}

async function checkEnvelopeHash<T>(
  envelope: SignedPayload<T>,
  label: string,
  errors: string[],
) {
  if ((await canonicalJsonSha256(envelope.payload)) !== envelope.payloadSha256) {
    errors.push(`${label} payload hash is invalid`);
  }
}

function assertVoteReceipt(value: unknown): asserts value is VoteReceiptV3 {
  if (record(value) && value.schema === "qualified-opinion.vote-acceptance.v3") {
    assertVoteAcceptanceV3(value);
    return;
  }
  assertVoteAdjudicationV3(value);
}

function isSignedEnvelope<T>(value: T | SignedPayload<T>): value is SignedPayload<T> {
  return record(value) && "payload" in value && "signature" in value;
}

function signedEnvelope(
  value: unknown,
  path: string,
  errors: string[],
  assertPayload: (value: unknown) => void,
  algorithm: "Ed25519" | "ES256",
) {
  if (!record(value)) {
    errors.push(`${path} must be a signed envelope`);
    return;
  }
  exactKeys(value, ["payload", "payloadSha256", "signature"], path, errors);
  captureAssertion(() => assertPayload(value.payload), `${path}.payload`, errors);
  digest(value.payloadSha256, `${path}.payloadSha256`, errors);
  if (!record(value.signature)) {
    errors.push(`${path}.signature must be an object`);
    return;
  }
  exactKeys(
    value.signature,
    ["algorithm", "keyId", "value"],
    `${path}.signature`,
    errors,
  );
  if (value.signature.algorithm !== algorithm) {
    errors.push(`${path}.signature.algorithm must equal ${algorithm}`);
  }
  nonEmpty(value.signature.keyId, `${path}.signature.keyId`, errors);
  nonEmpty(value.signature.value, `${path}.signature.value`, errors);
}

function checkpoint(value: unknown, path: string, errors: string[]) {
  if (!record(value)) {
    errors.push(`${path} must be an object`);
    return;
  }
  exactKeys(
    value,
    ["logId", "treeSize", "rootHash", "treeHeadPayloadSha256"],
    path,
    errors,
  );
  nonEmpty(value.logId, `${path}.logId`, errors);
  integer(value.treeSize, `${path}.treeSize`, errors, 0);
  digest(value.rootHash, `${path}.rootHash`, errors);
  digest(value.treeHeadPayloadSha256, `${path}.treeHeadPayloadSha256`, errors);
}

function questionLogLeaf(value: unknown, path: string, errors: string[]) {
  if (!record(value)) {
    errors.push(`${path} must be an object`);
    return;
  }
  exactKeys(
    value,
    ["leafIndex", "entryType", "entryId", "entryPayloadSha256", "leafHash"],
    path,
    errors,
  );
  integer(value.leafIndex, `${path}.leafIndex`, errors, 0);
  if (value.entryType !== "vote_event" && value.entryType !== "vote_adjudication") {
    errors.push(`${path}.entryType is not V3 tally evidence`);
  }
  nonEmpty(value.entryId, `${path}.entryId`, errors);
  digest(value.entryPayloadSha256, `${path}.entryPayloadSha256`, errors);
  digest(value.leafHash, `${path}.leafHash`, errors);
}

function sourcePosition(value: unknown, path: string, errors: string[]) {
  if (!record(value)) {
    errors.push(`${path} must be an object`);
    return;
  }
  exactKeys(
    value,
    [
      "inputKind",
      "positionId",
      "questionId",
      "choiceId",
      "positionType",
      "credentialClass",
      "status",
      "isCurrent",
      "countWeight",
    ],
    path,
    errors,
  );
  if (value.inputKind !== "source_position") {
    errors.push(`${path}.inputKind must equal source_position`);
  }
  for (const key of [
    "positionId",
    "questionId",
    "choiceId",
    "positionType",
    "status",
    "countWeight",
  ]) {
    nonEmpty(value[key], `${path}.${key}`, errors);
  }
  if (value.credentialClass !== null && typeof value.credentialClass !== "string") {
    errors.push(`${path}.credentialClass must be a string or null`);
  }
  if (typeof value.isCurrent !== "boolean") {
    errors.push(`${path}.isCurrent must be boolean`);
  }
  if (
    typeof value.countWeight === "string" &&
    !Number.isFinite(Number(value.countWeight))
  ) {
    errors.push(`${path}.countWeight must contain a finite number`);
  }
}

function tallyResult(value: unknown, path: string, errors: string[]) {
  if (!record(value)) {
    errors.push(`${path} must be an object`);
    return;
  }
  exactKeys(
    value,
    [
      "totalCount",
      "totalWeight",
      "directVoteCount",
      "sourcePositionCount",
      "disputedCount",
      "groups",
      "choices",
    ],
    path,
    errors,
  );
  for (const key of [
    "totalCount",
    "totalWeight",
    "directVoteCount",
    "sourcePositionCount",
    "disputedCount",
  ]) {
    positiveOrZero(value[key], `${path}.${key}`, errors);
  }
  if (!Array.isArray(value.groups) || !Array.isArray(value.choices)) {
    errors.push(`${path}.groups and ${path}.choices must be arrays`);
  }
}

function matchingSourceRules(
  policy: TallyPolicyV3,
  position: TallySourcePositionInputV3,
) {
  return policy.sourcePositionRules.filter(
    (rule) =>
      rule.positionTypes.includes(position.positionType) &&
      (rule.credentialClasses === null ||
        (position.credentialClass !== null &&
          rule.credentialClasses.includes(position.credentialClass))),
  );
}

function isCountablePosition(position: {
  status: string;
  isCurrent: boolean;
  countWeight: string;
}) {
  return (
    position.status === "counted" &&
    position.isCurrent &&
    Number(position.countWeight) > 0
  );
}

function receiptSequence(receipt: TallyVoteReceiptInputV3) {
  return receipt.envelope.payload.schema === "qualified-opinion.vote-acceptance.v3"
    ? 1
    : receipt.envelope.payload.sequence;
}

type CountedInputV3 = {
  choiceId: string;
  groupCode: string;
  kind: "direct_vote" | "source_position";
  weight: number;
};

function aggregateGroups(inputs: CountedInputV3[]): TallyGroupResultV3[] {
  const groups = new Map<string, TallyGroupResultV3>();
  for (const input of inputs) {
    const current = groups.get(input.groupCode) ?? {
      groupCode: input.groupCode,
      count: 0,
      weightedCount: 0,
    };
    current.count += 1;
    current.weightedCount += input.weight;
    groups.set(input.groupCode, current);
  }
  return [...groups.values()].sort((left, right) =>
    left.groupCode.localeCompare(right.groupCode),
  );
}

function percentage(numerator: number, denominator: number, decimalPlaces: number) {
  return denominator === 0
    ? 0
    : Number(((numerator / denominator) * 100).toFixed(decimalPlaces));
}

function normalizedTimestamp(value: Date | string, field: string) {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) {
    throw new TypeError(`${field} must be a valid timestamp`);
  }
  return date.toISOString();
}

function requiredString(value: string, field: string) {
  const normalized = value.trim();
  if (!normalized) throw new TypeError(`${field} must not be empty`);
  return normalized;
}

function canonicalStrings(values: string[]) {
  return [...new Set(values.map((value) => requiredString(value, "string")))].sort(
    (left, right) => left.localeCompare(right),
  );
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(
  value: Record<string, unknown>,
  keys: string[],
  path: string,
  errors: string[],
) {
  const expected = new Set(keys);
  for (const key of Object.keys(value)) {
    if (!expected.has(key)) errors.push(`${path}.${key} is not allowed`);
  }
  for (const key of keys) {
    if (!(key in value)) errors.push(`${path}.${key} is required`);
  }
}

function exactConstantObject(
  value: unknown,
  expected: Record<string, unknown>,
  path: string,
  errors: string[],
) {
  if (!record(value)) {
    errors.push(`${path} must be an object`);
    return;
  }
  exactKeys(value, Object.keys(expected), path, errors);
  constants(value, expected, path, errors);
}

function constants(
  value: Record<string, unknown>,
  expected: Record<string, unknown>,
  path: string,
  errors: string[],
) {
  for (const [key, expectedValue] of Object.entries(expected)) {
    if (value[key] !== expectedValue) {
      errors.push(`${path}.${key} must equal ${String(expectedValue)}`);
    }
  }
}

function nonEmpty(value: unknown, path: string, errors: string[]) {
  if (typeof value !== "string" || value.trim().length === 0) {
    errors.push(`${path} must be a non-empty string`);
  }
}

function digest(value: unknown, path: string, errors: string[]) {
  if (typeof value !== "string" || !isSha256Base64Url(value)) {
    errors.push(`${path} must be a SHA-256 base64url digest`);
  }
}

function timestamp(value: unknown, path: string, errors: string[]) {
  if (
    typeof value !== "string" ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  ) {
    errors.push(`${path} must be a canonical ISO timestamp`);
  }
}

function integer(
  value: unknown,
  path: string,
  errors: string[],
  minimum: number,
  maximum = Number.MAX_SAFE_INTEGER,
) {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    errors.push(`${path} must be an integer from ${minimum} to ${maximum}`);
  }
}

function positiveNumber(value: unknown, path: string, errors: string[]) {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    errors.push(`${path} must be a positive finite number`);
  }
}

function positiveOrZero(value: unknown, path: string, errors: string[]) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    errors.push(`${path} must be a non-negative finite number`);
  }
}

function stringArray(value: unknown, path: string, errors: string[]) {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.some(
      (candidate) => typeof candidate !== "string" || candidate.trim().length === 0,
    ) ||
    new Set(value).size !== value.length
  ) {
    errors.push(`${path} must be a non-empty array of unique strings`);
  }
}

function arrayOf(
  value: unknown,
  path: string,
  errors: string[],
  validate: (value: unknown, path: string) => void,
) {
  if (!Array.isArray(value)) {
    errors.push(`${path} must be an array`);
    return;
  }
  value.forEach((candidate, index) => validate(candidate, `${path}[${index}]`));
}

function captureAssertion(action: () => void, path: string, errors: string[]) {
  try {
    action();
  } catch (error) {
    errors.push(...errorMessages(error).map((message) => `${path}: ${message}`));
  }
}

function errorMessages(error: unknown) {
  if (error instanceof TallyProtocolV3Error) return error.errors;
  if (error instanceof Error) return [error.message];
  return [String(error)];
}
