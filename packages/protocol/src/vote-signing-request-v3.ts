import { canonicalizeJson } from "./canonical";
import { canonicalJsonSha256, isBase64Url, isSha256Base64Url } from "./encoding";
import { QUESTION_SCOPED_VOTE_SESSION_MAX_ITEMS } from "./question-authorization-request-v3";
import type { SignedPayload } from "./types";
import type { BallotManifestV3, ProtocolBindingV3, VoteEventTypeV3 } from "./v3-types";
import { assertBallotManifestV3, assertProtocolBindingV3 } from "./v3-validate";

export const VOTE_SIGNING_INTENT_SCHEMA_V3 =
  "qualified-opinion.vote-signing-intent.v3" as const;
export const VOTE_SIGNING_REQUEST_BATCH_SCHEMA_V3 =
  "qualified-opinion.vote-signing-request-batch.v3" as const;

/**
 * A server-prepared vote intent. It is private transport material for the
 * attested issuer, not a public vote event. The issuer adds a question-scoped
 * nullifier, authorization hash, publication mode, fresh key and issued time
 * before the voter signs the final V3 event.
 */
export type VoteSigningIntentV3 = {
  schema: typeof VOTE_SIGNING_INTENT_SCHEMA_V3;
  eventId: string;
  eventType: VoteEventTypeV3;
  binding: ProtocolBindingV3;
  ballotManifestSha256: string;
  ballotId: string;
  questionId: string;
  choiceId: string | null;
  sequence: number;
  previousEventSha256: string | null;
  challenge: string;
  preparedAt: string;
};

export type VoteSigningRequestBatchItemV3 = {
  challengeId: string;
  canonicalIntent: string;
  intentSha256: string;
  ordinal: number;
  questionManifest: SignedPayload<BallotManifestV3>;
};

/**
 * An immutable one-question request read by the attested issuer. Identity and
 * reusable delegation material stay inside this private request and never
 * enter a public vote proof or tally.
 */
export type VoteSigningRequestBatchV3 = {
  schema: typeof VOTE_SIGNING_REQUEST_BATCH_SCHEMA_V3;
  sessionId: string;
  publicVoterId: string;
  delegationId: string;
  delegationSha256: string;
  delegatedKeyId: string;
  locale: "en" | "ku" | "tr";
  expiresAt: string;
  items: VoteSigningRequestBatchItemV3[];
};

export type VerifiedVoteSigningRequestBatchItemV3 = VoteSigningRequestBatchItemV3 & {
  intent: VoteSigningIntentV3;
};

export type VerifiedVoteSigningRequestBatchV3 = Omit<
  VoteSigningRequestBatchV3,
  "items"
> & {
  items: VerifiedVoteSigningRequestBatchItemV3[];
};

export function buildVoteSigningIntentV3(input: {
  eventId: string;
  eventType: VoteEventTypeV3;
  binding: ProtocolBindingV3;
  ballotManifestSha256: string;
  ballotId: string;
  questionId: string;
  choiceId?: string | null;
  sequence: number;
  previousEventSha256?: string | null;
  challenge: string;
  preparedAt: Date | string;
}): VoteSigningIntentV3 {
  const preparedAt =
    input.preparedAt instanceof Date ? input.preparedAt : new Date(input.preparedAt);
  if (!Number.isFinite(preparedAt.getTime())) invalid("invalid_prepared_at");
  assertProtocolBindingV3(input.binding);
  const intent: VoteSigningIntentV3 = {
    schema: VOTE_SIGNING_INTENT_SCHEMA_V3,
    eventId: input.eventId,
    eventType: input.eventType,
    binding: structuredClone(input.binding),
    ballotManifestSha256: input.ballotManifestSha256,
    ballotId: input.ballotId,
    questionId: input.questionId,
    choiceId: input.eventType === "withdraw" ? null : (input.choiceId ?? null),
    sequence: input.sequence,
    previousEventSha256: input.previousEventSha256 ?? null,
    challenge: input.challenge,
    preparedAt: preparedAt.toISOString(),
  };
  assertVoteSigningIntentV3(intent);
  return intent;
}

export function assertVoteSigningIntentV3(
  value: unknown,
): asserts value is VoteSigningIntentV3 {
  if (!record(value) || !exactKeys(value, intentKeys)) {
    invalid("invalid_vote_signing_intent");
  }
  if (
    value.schema !== VOTE_SIGNING_INTENT_SCHEMA_V3 ||
    !uuid(value.eventId) ||
    (value.eventType !== "cast" &&
      value.eventType !== "replace" &&
      value.eventType !== "withdraw") ||
    !digest(value.ballotManifestSha256) ||
    !stableId(value.ballotId) ||
    !stableId(value.questionId) ||
    !Number.isSafeInteger(value.sequence) ||
    (value.sequence as number) < 1 ||
    (value.previousEventSha256 !== null && !digest(value.previousEventSha256)) ||
    !nonce(value.challenge) ||
    !normalizedTimestamp(value.preparedAt)
  ) {
    invalid("invalid_vote_signing_intent");
  }
  if (
    (value.eventType === "withdraw" && value.choiceId !== null) ||
    (value.eventType !== "withdraw" && !stableId(value.choiceId))
  ) {
    invalid("invalid_vote_signing_intent_choice");
  }
  assertProtocolBindingV3(value.binding);
}

export function assertVoteSigningRequestBatchV3(
  value: unknown,
): asserts value is VoteSigningRequestBatchV3 {
  if (!record(value) || !exactKeys(value, batchKeys)) {
    invalid("invalid_vote_signing_request_batch");
  }
  if (
    value.schema !== VOTE_SIGNING_REQUEST_BATCH_SCHEMA_V3 ||
    !uuid(value.sessionId) ||
    !uuid(value.publicVoterId) ||
    !uuid(value.delegationId) ||
    !digest(value.delegationSha256) ||
    !digest(value.delegatedKeyId) ||
    (value.locale !== "en" && value.locale !== "ku" && value.locale !== "tr") ||
    !normalizedTimestamp(value.expiresAt) ||
    !Array.isArray(value.items) ||
    value.items.length < 1 ||
    value.items.length > QUESTION_SCOPED_VOTE_SESSION_MAX_ITEMS
  ) {
    invalid("invalid_vote_signing_request_batch");
  }

  const challenges = new Set<string>();
  const questions = new Set<string>();
  for (let ordinal = 0; ordinal < value.items.length; ordinal += 1) {
    const item = value.items[ordinal];
    if (
      !record(item) ||
      !exactKeys(item, itemKeys) ||
      item.ordinal !== ordinal ||
      !uuid(item.challengeId) ||
      challenges.has(item.challengeId as string) ||
      typeof item.canonicalIntent !== "string" ||
      utf8Length(item.canonicalIntent) > 32_768 ||
      !digest(item.intentSha256)
    ) {
      invalid("invalid_vote_signing_request_item");
    }
    challenges.add(item.challengeId as string);

    let intent: VoteSigningIntentV3;
    try {
      intent = JSON.parse(item.canonicalIntent as string);
      assertVoteSigningIntentV3(intent);
      if (canonicalizeJson(intent) !== item.canonicalIntent) {
        invalid("noncanonical_vote_signing_intent");
      }
      assertSignedManifest(item.questionManifest);
    } catch {
      invalid("invalid_vote_signing_request_item");
    }
    const manifest = item.questionManifest.payload;
    const selectedMeaning = manifest.meaning.choices.find(
      (choice) => choice.id === intent.choiceId,
    );
    const selectedPresentation = manifest.presentation.choices.find(
      (choice) => choice.id === intent.choiceId,
    );
    if (
      questions.has(intent.questionId) ||
      intent.ballotManifestSha256 !== item.questionManifest.payloadSha256 ||
      intent.ballotId !== manifest.ballotId ||
      intent.questionId !== manifest.questionId ||
      manifest.presentation.locale !== value.locale ||
      canonicalizeJson(intent.binding) !== canonicalizeJson(manifest.binding) ||
      (intent.eventType !== "withdraw" &&
        (!selectedMeaning?.isCounted || !selectedPresentation))
    ) {
      invalid("vote_signing_request_link_mismatch");
    }
    questions.add(intent.questionId);
  }
  if (utf8Length(canonicalizeJson(value)) > 512 * 1024) {
    invalid("vote_signing_request_too_large");
  }
}

export async function verifyVoteSigningRequestBatchV3(input: {
  batch: VoteSigningRequestBatchV3;
  batchSha256: string;
}): Promise<VerifiedVoteSigningRequestBatchV3> {
  assertVoteSigningRequestBatchV3(input.batch);
  if (
    !digest(input.batchSha256) ||
    (await voteSigningRequestBatchSha256V3(input.batch)) !== input.batchSha256
  ) {
    invalid("vote_signing_request_hash_mismatch");
  }
  const items: VerifiedVoteSigningRequestBatchItemV3[] = [];
  for (const item of input.batch.items) {
    const intent = JSON.parse(item.canonicalIntent) as VoteSigningIntentV3;
    if (
      (await canonicalJsonSha256(intent)) !== item.intentSha256 ||
      (await canonicalJsonSha256(item.questionManifest.payload)) !==
        item.questionManifest.payloadSha256
    ) {
      invalid("vote_signing_request_item_hash_mismatch");
    }
    items.push({ ...item, intent });
  }
  return { ...input.batch, items };
}

export function voteSigningRequestBatchSha256V3(batch: VoteSigningRequestBatchV3) {
  assertVoteSigningRequestBatchV3(batch);
  return canonicalJsonSha256(batch);
}

const intentKeys = [
  "schema",
  "eventId",
  "eventType",
  "binding",
  "ballotManifestSha256",
  "ballotId",
  "questionId",
  "choiceId",
  "sequence",
  "previousEventSha256",
  "challenge",
  "preparedAt",
] as const;

const batchKeys = [
  "schema",
  "sessionId",
  "publicVoterId",
  "delegationId",
  "delegationSha256",
  "delegatedKeyId",
  "locale",
  "expiresAt",
  "items",
] as const;

const itemKeys = [
  "challengeId",
  "canonicalIntent",
  "intentSha256",
  "ordinal",
  "questionManifest",
] as const;

function assertSignedManifest(
  value: unknown,
): asserts value is SignedPayload<BallotManifestV3> {
  if (
    !record(value) ||
    !exactKeys(value, ["payload", "payloadSha256", "signature"]) ||
    !digest(value.payloadSha256) ||
    !record(value.signature) ||
    !exactKeys(value.signature, ["algorithm", "keyId", "value"]) ||
    value.signature.algorithm !== "Ed25519" ||
    !stableId(value.signature.keyId) ||
    !base64Url(value.signature.value)
  ) {
    invalid("invalid_signed_ballot_manifest");
  }
  assertBallotManifestV3(value.payload);
  if (value.payload.issuer.keyId !== value.signature.keyId) {
    invalid("ballot_manifest_key_mismatch");
  }
}

function record(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return (
    actual.length === wanted.length &&
    actual.every((key, index) => key === wanted[index])
  );
}

function uuid(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      value,
    )
  );
}

function stableId(value: unknown): value is string {
  return (
    typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$/.test(value)
  );
}

function digest(value: unknown): value is string {
  return typeof value === "string" && isSha256Base64Url(value);
}

function base64Url(value: unknown): value is string {
  return typeof value === "string" && isBase64Url(value);
}

function nonce(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 32 &&
    value.length <= 256 &&
    isBase64Url(value)
  );
}

function normalizedTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value;
}

function utf8Length(value: string) {
  return new TextEncoder().encode(value).byteLength;
}

function invalid(message: string): never {
  throw new TypeError(message);
}
