import { canonicalizeJson } from "./canonical";
import {
  base64UrlDecode,
  canonicalJsonSha256,
  isBase64Url,
  isSha256Base64Url,
  sha256Base64Url,
} from "./encoding";
import type { SignedPayload } from "./types";
import type { VotePublicationModeV3 } from "./v3-types";

export const QUESTION_VOTING_AUTHORIZATION_REQUEST_SCHEMA_V3 =
  "qualified-opinion.question-voting-authorization-request.v3" as const;

/**
 * More than one question in a current V3 session would publish adjacent log
 * leaves, a shared tree head, and one acceptance transaction, making otherwise
 * question-scoped pseudonyms exactly linkable across public tallies.
 */
export const QUESTION_SCOPED_VOTE_SESSION_MAX_ITEMS = 1;

export type QuestionVotingAuthorizationRequestItemV3 = {
  ordinal: number;
  questionId: string;
  ballotManifestSha256: string;
  questionPublicKeySpki: string;
  questionPublicKeySha256: string;
};

/**
 * A private, short-lived request signed by the member's reusable delegated
 * key. It never enters the public tally. The batch hash binds the already
 * displayed choices; the fresh keys become public only through unlinkable
 * question authorizations.
 */
export type QuestionVotingAuthorizationRequestV3 = {
  schema: typeof QUESTION_VOTING_AUTHORIZATION_REQUEST_SCHEMA_V3;
  sessionId: string;
  requestBatchSha256: string;
  publicationMode: VotePublicationModeV3;
  issuedAt: string;
  expiresAt: string;
  items: QuestionVotingAuthorizationRequestItemV3[];
};

export type SignedQuestionVotingAuthorizationRequestV3 =
  SignedPayload<QuestionVotingAuthorizationRequestV3>;

export async function buildQuestionVotingAuthorizationRequestV3(input: {
  sessionId: string;
  requestBatchSha256: string;
  publicationMode: VotePublicationModeV3;
  issuedAt: Date | string;
  expiresAt: Date | string;
  items: Array<{
    questionId: string;
    ballotManifestSha256: string;
    questionPublicKeySpki: string;
  }>;
}): Promise<QuestionVotingAuthorizationRequestV3> {
  const request: QuestionVotingAuthorizationRequestV3 = {
    schema: QUESTION_VOTING_AUTHORIZATION_REQUEST_SCHEMA_V3,
    sessionId: input.sessionId,
    requestBatchSha256: input.requestBatchSha256,
    publicationMode: input.publicationMode,
    issuedAt: timestamp(input.issuedAt),
    expiresAt: timestamp(input.expiresAt),
    items: await Promise.all(
      input.items.map(async (item, ordinal) => ({
        ordinal,
        questionId: item.questionId,
        ballotManifestSha256: item.ballotManifestSha256,
        questionPublicKeySpki: item.questionPublicKeySpki,
        questionPublicKeySha256: await sha256Base64Url(
          base64UrlDecode(item.questionPublicKeySpki),
        ),
      })),
    ),
  };
  assertQuestionVotingAuthorizationRequestV3(request);
  return request;
}

export function assertQuestionVotingAuthorizationRequestV3(
  value: unknown,
): asserts value is QuestionVotingAuthorizationRequestV3 {
  if (!record(value) || !exactKeys(value, requestKeys)) invalid();
  if (
    value.schema !== QUESTION_VOTING_AUTHORIZATION_REQUEST_SCHEMA_V3 ||
    !uuid(value.sessionId) ||
    !digest(value.requestBatchSha256) ||
    (value.publicationMode !== "private" && value.publicationMode !== "attributed") ||
    !normalizedTimestamp(value.issuedAt) ||
    !normalizedTimestamp(value.expiresAt) ||
    Date.parse(value.expiresAt) <= Date.parse(value.issuedAt) ||
    !Array.isArray(value.items) ||
    value.items.length < 1 ||
    value.items.length > QUESTION_SCOPED_VOTE_SESSION_MAX_ITEMS
  ) {
    invalid();
  }
  const questions = new Set<string>();
  const keys = new Set<string>();
  for (let ordinal = 0; ordinal < value.items.length; ordinal += 1) {
    const item = value.items[ordinal];
    if (
      !record(item) ||
      !exactKeys(item, itemKeys) ||
      item.ordinal !== ordinal ||
      !stableId(item.questionId) ||
      questions.has(item.questionId as string) ||
      !digest(item.ballotManifestSha256) ||
      !base64(item.questionPublicKeySpki) ||
      !digest(item.questionPublicKeySha256) ||
      keys.has(item.questionPublicKeySha256 as string)
    ) {
      invalid();
    }
    questions.add(item.questionId as string);
    keys.add(item.questionPublicKeySha256 as string);
  }
}

export async function verifyQuestionVotingAuthorizationRequestV3Integrity(
  value: unknown,
): Promise<boolean> {
  try {
    assertQuestionVotingAuthorizationRequestV3(value);
    for (const item of value.items) {
      if (
        (await sha256Base64Url(base64UrlDecode(item.questionPublicKeySpki))) !==
        item.questionPublicKeySha256
      ) {
        return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}

export async function attachQuestionVotingAuthorizationRequestSignatureV3(input: {
  payload: QuestionVotingAuthorizationRequestV3;
  delegatedKeyId: string;
  signature: string;
}): Promise<SignedQuestionVotingAuthorizationRequestV3> {
  assertQuestionVotingAuthorizationRequestV3(input.payload);
  if (!digest(input.delegatedKeyId) || !canonicalP256Signature(input.signature)) {
    invalid();
  }
  return {
    payload: structuredClone(input.payload),
    payloadSha256: await canonicalJsonSha256(input.payload),
    signature: {
      algorithm: "ES256",
      keyId: input.delegatedKeyId,
      value: input.signature,
    },
  };
}

export function canonicalQuestionVotingAuthorizationRequestV3(
  value: QuestionVotingAuthorizationRequestV3,
) {
  assertQuestionVotingAuthorizationRequestV3(value);
  return canonicalizeJson(value);
}

const requestKeys = [
  "schema",
  "sessionId",
  "requestBatchSha256",
  "publicationMode",
  "issuedAt",
  "expiresAt",
  "items",
] as const;

const itemKeys = [
  "ordinal",
  "questionId",
  "ballotManifestSha256",
  "questionPublicKeySpki",
  "questionPublicKeySha256",
] as const;

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

function base64(value: unknown): value is string {
  return typeof value === "string" && isBase64Url(value);
}

function canonicalP256Signature(value: unknown): value is string {
  if (typeof value !== "string" || !isBase64Url(value)) return false;
  try {
    return base64UrlDecode(value).byteLength === 64;
  } catch {
    return false;
  }
}

function normalizedTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const date = new Date(value);
  return Number.isFinite(date.getTime()) && date.toISOString() === value;
}

function timestamp(value: Date | string) {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) invalid();
  return date.toISOString();
}

function invalid(): never {
  throw new TypeError("invalid_question_voting_authorization_request_v3");
}
