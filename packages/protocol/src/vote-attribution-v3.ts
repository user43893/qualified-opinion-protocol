import {
  base64UrlDecode,
  canonicalJsonSha256,
  isBase64Url,
  isSha256Base64Url,
} from "./encoding";
import type { SignedPayload } from "./types";
import type { ValidationResult } from "./validate";

export const PUBLIC_VOTE_ATTRIBUTION_SCHEMA_V3 =
  "qualified-opinion.public-vote-attribution.v3" as const;

/**
 * Removable proof that the identity-bound delegated key opted to associate one
 * exact vote event with its public directory entry. This envelope is never
 * placed in the immutable vote bundle or tally.
 */
export type PublicVoteAttributionPayloadV3 = {
  schema: typeof PUBLIC_VOTE_ATTRIBUTION_SCHEMA_V3;
  publicVoterId: string;
  delegationSha256: string;
  voteEventId: string;
  voteEventSha256: string;
  questionId: string;
  attributedAt: string;
};

export type PublicVoteAttributionV3 = SignedPayload<PublicVoteAttributionPayloadV3>;

export function buildPublicVoteAttributionPayloadV3(input: {
  publicVoterId: string;
  delegationSha256: string;
  voteEventId: string;
  voteEventSha256: string;
  questionId: string;
  attributedAt: Date | string;
}): PublicVoteAttributionPayloadV3 {
  const payload: PublicVoteAttributionPayloadV3 = {
    schema: PUBLIC_VOTE_ATTRIBUTION_SCHEMA_V3,
    publicVoterId: input.publicVoterId,
    delegationSha256: input.delegationSha256,
    voteEventId: input.voteEventId,
    voteEventSha256: input.voteEventSha256,
    questionId: input.questionId,
    attributedAt: timestamp(input.attributedAt),
  };
  assertPublicVoteAttributionPayloadV3(payload);
  return payload;
}

export async function attachPublicVoteAttributionSignatureV3(input: {
  payload: PublicVoteAttributionPayloadV3;
  delegatedKeyId: string;
  signature: string;
}): Promise<PublicVoteAttributionV3> {
  assertPublicVoteAttributionPayloadV3(input.payload);
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

export function assertPublicVoteAttributionPayloadV3(
  value: unknown,
): asserts value is PublicVoteAttributionPayloadV3 {
  if (!record(value) || !exactKeys(value, payloadKeys)) invalid();
  if (
    value.schema !== PUBLIC_VOTE_ATTRIBUTION_SCHEMA_V3 ||
    !uuid(value.publicVoterId) ||
    !digest(value.delegationSha256) ||
    !uuid(value.voteEventId) ||
    !digest(value.voteEventSha256) ||
    !uuid(value.questionId) ||
    !normalizedTimestamp(value.attributedAt)
  ) {
    invalid();
  }
}

export function assertPublicVoteAttributionV3(
  value: unknown,
): asserts value is PublicVoteAttributionV3 {
  if (!record(value) || !exactKeys(value, envelopeKeys)) invalid();
  assertPublicVoteAttributionPayloadV3(value.payload);
  if (
    !digest(value.payloadSha256) ||
    !record(value.signature) ||
    !exactKeys(value.signature, signatureKeys) ||
    value.signature.algorithm !== "ES256" ||
    !digest(value.signature.keyId) ||
    !canonicalP256Signature(value.signature.value)
  ) {
    invalid();
  }
}

export async function verifyPublicVoteAttributionV3Integrity(
  value: unknown,
): Promise<ValidationResult<PublicVoteAttributionV3>> {
  try {
    assertPublicVoteAttributionV3(value);
    if ((await canonicalJsonSha256(value.payload)) !== value.payloadSha256) {
      return {
        ok: false,
        errors: [
          "$.payloadSha256 must equal the canonical SHA-256 digest of $.payload",
        ],
      };
    }
    return { ok: true, value };
  } catch (error) {
    return {
      ok: false,
      errors: [error instanceof Error ? error.message : String(error)],
    };
  }
}

const payloadKeys = [
  "schema",
  "publicVoterId",
  "delegationSha256",
  "voteEventId",
  "voteEventSha256",
  "questionId",
  "attributedAt",
] as const;
const envelopeKeys = ["payload", "payloadSha256", "signature"] as const;
const signatureKeys = ["algorithm", "keyId", "value"] as const;

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

function digest(value: unknown): value is string {
  return typeof value === "string" && isSha256Base64Url(value);
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
  throw new TypeError("invalid_public_vote_attribution_v3");
}
