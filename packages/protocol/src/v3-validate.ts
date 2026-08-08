import { canonicalizeJson } from "./canonical";
import {
  base64UrlDecode,
  canonicalJsonSha256,
  isBase64Url,
  isSha256Base64Url,
  sha256Base64Url,
} from "./encoding";
import {
  BALLOT_MANIFEST_SCHEMA_V3,
  type BallotManifestV3,
  type ProtocolBindingV3,
  QUESTION_VOTING_ATTESTATION_PURPOSE_V3,
  QUESTION_VOTING_AUTHORIZATION_SCHEMA_V3,
  QUESTION_VOTING_KEY_PURPOSE_V3,
  type QuestionVotingAuthorizationPayloadV3,
  type QuestionVotingAuthorizationV3,
  VOTE_EVENT_SCHEMA_V3,
  type VoteEventV3,
} from "./v3-types";
import type { ValidationResult } from "./validate";

export function validateProtocolBindingV3(
  value: unknown,
): ValidationResult<ProtocolBindingV3> {
  return result(value, collectBindingErrors(value, "$"));
}

export function assertProtocolBindingV3(
  value: unknown,
): asserts value is ProtocolBindingV3 {
  assertValid(collectBindingErrors(value, "$"));
}

export function validateBallotManifestV3(
  value: unknown,
): ValidationResult<BallotManifestV3> {
  return result(value, collectBallotErrors(value, "$"));
}

export function assertBallotManifestV3(
  value: unknown,
): asserts value is BallotManifestV3 {
  assertValid(collectBallotErrors(value, "$"));
}

export function isBallotManifestV3(value: unknown): value is BallotManifestV3 {
  return isObject(value) && value.schema === BALLOT_MANIFEST_SCHEMA_V3;
}

export function validateQuestionVotingAuthorizationPayloadV3(
  value: unknown,
): ValidationResult<QuestionVotingAuthorizationPayloadV3> {
  return result(value, collectAuthorizationPayloadErrors(value, "$"));
}

export function assertQuestionVotingAuthorizationPayloadV3(
  value: unknown,
): asserts value is QuestionVotingAuthorizationPayloadV3 {
  assertValid(collectAuthorizationPayloadErrors(value, "$"));
}

export function validateQuestionVotingAuthorizationV3(
  value: unknown,
): ValidationResult<QuestionVotingAuthorizationV3> {
  return result(value, collectAuthorizationErrors(value, "$"));
}

export function assertQuestionVotingAuthorizationV3(
  value: unknown,
): asserts value is QuestionVotingAuthorizationV3 {
  assertValid(collectAuthorizationErrors(value, "$"));
}

export function isQuestionVotingAuthorizationV3(
  value: unknown,
): value is QuestionVotingAuthorizationV3 {
  return (
    isObject(value) &&
    isObject(value.payload) &&
    value.payload.schema === QUESTION_VOTING_AUTHORIZATION_SCHEMA_V3
  );
}

/**
 * The value supplied as the Confidential Space attestation nonce. Consumers
 * must require the verified token's eat_nonce claim to contain this exact hash.
 */
export async function expectedQuestionVotingAuthorizationAttestationNonceV3(
  payload: QuestionVotingAuthorizationPayloadV3,
) {
  const integrity = await verifyQuestionVotingAuthorizationPayloadV3Integrity(payload);
  if (!integrity.ok) {
    throw new TypeError(
      `Invalid qualified-opinion V3 authorization payload:\n${integrity.errors
        .map((error) => `- ${error}`)
        .join("\n")}`,
    );
  }
  return canonicalJsonSha256(payload);
}

export async function verifyQuestionVotingAuthorizationPayloadV3Integrity(
  value: unknown,
): Promise<ValidationResult<QuestionVotingAuthorizationPayloadV3>> {
  const structural = validateQuestionVotingAuthorizationPayloadV3(value);
  if (!structural.ok) return structural;
  return result(
    structural.value,
    await questionKeyIntegrityErrors(structural.value, "$"),
  );
}

/**
 * Verifies all locally checkable authorization integrity: exact schema,
 * canonical payload hash, SPKI hash/key ID, and an importable P-256 public key.
 * Google token signature, workload policy, audience, purpose, and eat_nonce
 * claims remain the responsibility of the attestation verifier.
 */
export async function verifyQuestionVotingAuthorizationV3Integrity(
  value: unknown,
): Promise<ValidationResult<QuestionVotingAuthorizationV3>> {
  const structural = validateQuestionVotingAuthorizationV3(value);
  if (!structural.ok) return structural;

  const payloadIntegrity = await verifyQuestionVotingAuthorizationPayloadV3Integrity(
    structural.value.payload,
  );
  const errors = payloadIntegrity.ok
    ? []
    : rebase(payloadIntegrity.errors, "$.payload");
  const expectedPayloadSha256 = await canonicalJsonSha256(structural.value.payload);
  if (structural.value.payloadSha256 !== expectedPayloadSha256) {
    errors.push("$.payloadSha256 must equal the canonical SHA-256 digest of $.payload");
  }

  return result(structural.value, errors);
}

async function questionKeyIntegrityErrors(
  payload: QuestionVotingAuthorizationPayloadV3,
  path: string,
) {
  const errors: string[] = [];
  const spki = payload.questionKey.publicKeySpki;
  let spkiBytes: Uint8Array | null = null;
  try {
    spkiBytes = base64UrlDecode(spki);
  } catch {
    errors.push(`${path}.questionKey.publicKeySpki must be valid base64url`);
  }
  if (spkiBytes) {
    const expectedSpkiSha256 = await sha256Base64Url(spkiBytes);
    if (payload.questionKey.publicKeySpkiSha256 !== expectedSpkiSha256) {
      errors.push(
        `${path}.questionKey.publicKeySpkiSha256 must match the decoded SPKI`,
      );
    }
    if (payload.questionKey.keyId !== expectedSpkiSha256) {
      errors.push(
        `${path}.questionKey.keyId must equal the decoded SPKI SHA-256 digest`,
      );
    }
    if (!(await isP256Spki(spkiBytes))) {
      errors.push(`${path}.questionKey.publicKeySpki must encode a P-256 public key`);
    }
  }
  const witness = payload.registryCheckpoint.witness;
  try {
    const parsed = JSON.parse(witness.canonicalEnvelope) as unknown;
    if (canonicalizeJson(parsed) !== witness.canonicalEnvelope) {
      errors.push(
        `${path}.registryCheckpoint.witness.canonicalEnvelope must be canonical JSON`,
      );
    }
  } catch {
    errors.push(
      `${path}.registryCheckpoint.witness.canonicalEnvelope must be valid JSON`,
    );
  }
  if ((await sha256Base64Url(witness.canonicalEnvelope)) !== witness.envelopeSha256) {
    errors.push(
      `${path}.registryCheckpoint.witness.envelopeSha256 must match canonicalEnvelope`,
    );
  }
  return errors;
}

export function validateVoteEventV3(value: unknown): ValidationResult<VoteEventV3> {
  return result(value, collectVoteEventErrors(value, "$"));
}

export function assertVoteEventV3(value: unknown): asserts value is VoteEventV3 {
  assertValid(collectVoteEventErrors(value, "$"));
}

export function isVoteEventV3(value: unknown): value is VoteEventV3 {
  return isObject(value) && value.schema === VOTE_EVENT_SCHEMA_V3;
}

/**
 * Validates the public links that make a V3 event usable only with one
 * question-scoped authorization.
 */
export async function verifyVoteEventV3AuthorizationBinding(input: {
  event: unknown;
  authorization: unknown;
}): Promise<ValidationResult<VoteEventV3>> {
  const event = validateVoteEventV3(input.event);
  const authorization = await verifyQuestionVotingAuthorizationV3Integrity(
    input.authorization,
  );
  const errors: string[] = [];
  if (!event.ok) errors.push(...rebase(event.errors, "$.event"));
  if (!authorization.ok) {
    errors.push(...rebase(authorization.errors, "$.authorization"));
  }
  if (!event.ok || !authorization.ok) {
    return { ok: false, errors };
  }

  const payload = authorization.value.payload;
  if (event.value.questionId !== payload.questionId) {
    errors.push("$.event.questionId must equal authorization questionId");
  }
  if (event.value.questionNullifier !== payload.questionNullifier) {
    errors.push("$.event.questionNullifier must equal authorization questionNullifier");
  }
  if (event.value.authorizationSha256 !== authorization.value.payloadSha256) {
    errors.push("$.event.authorizationSha256 must equal authorization payloadSha256");
  }
  if (event.value.questionKeyId !== payload.questionKey.keyId) {
    errors.push("$.event.questionKeyId must equal authorization questionKey.keyId");
  }
  if (canonicalizeJson(event.value.binding) !== canonicalizeJson(payload.binding)) {
    errors.push("$.event.binding must equal authorization binding");
  }

  const eventTime = Date.parse(event.value.issuedAt);
  const authorizationStart = Date.parse(payload.issuedAt);
  const authorizationEnd = Date.parse(payload.expiresAt);
  if (eventTime < authorizationStart || eventTime >= authorizationEnd) {
    errors.push("$.event.issuedAt must fall within the authorization validity window");
  }

  return result(event.value, errors);
}

function collectAuthorizationErrors(value: unknown, path: string) {
  const errors: string[] = [];
  const object = exactObject(
    value,
    path,
    ["payload", "payloadSha256", "attestationToken"],
    errors,
  );
  if (!object) return errors;
  errors.push(...collectAuthorizationPayloadErrors(object.payload, `${path}.payload`));
  digest(object.payloadSha256, `${path}.payloadSha256`, errors);
  nonEmpty(object.attestationToken, `${path}.attestationToken`, errors);
  return errors;
}

function collectAuthorizationPayloadErrors(value: unknown, path: string) {
  const errors: string[] = [];
  const object = exactObject(
    value,
    path,
    [
      "schema",
      "binding",
      "questionId",
      "questionNullifier",
      "nullifierKeyEpoch",
      "questionKey",
      "eligibility",
      "registryCheckpoint",
      "issuedAt",
      "expiresAt",
      "issuerAttestation",
    ],
    errors,
  );
  if (!object) return errors;
  literal(
    object.schema,
    QUESTION_VOTING_AUTHORIZATION_SCHEMA_V3,
    `${path}.schema`,
    errors,
  );
  errors.push(...bindingErrors(object.binding, `${path}.binding`));
  stableId(object.questionId, `${path}.questionId`, errors);
  digest(object.questionNullifier, `${path}.questionNullifier`, errors);
  positiveInteger(object.nullifierKeyEpoch, `${path}.nullifierKeyEpoch`, errors);

  const questionKey = exactObject(
    object.questionKey,
    `${path}.questionKey`,
    ["algorithm", "keyId", "publicKeySpki", "publicKeySpkiSha256", "purpose"],
    errors,
  );
  if (questionKey) {
    literal(questionKey.algorithm, "ES256", `${path}.questionKey.algorithm`, errors);
    digest(questionKey.keyId, `${path}.questionKey.keyId`, errors);
    base64Value(questionKey.publicKeySpki, `${path}.questionKey.publicKeySpki`, errors);
    digest(
      questionKey.publicKeySpkiSha256,
      `${path}.questionKey.publicKeySpkiSha256`,
      errors,
    );
    if (
      typeof questionKey.keyId === "string" &&
      typeof questionKey.publicKeySpkiSha256 === "string" &&
      questionKey.keyId !== questionKey.publicKeySpkiSha256
    ) {
      errors.push(
        `${path}.questionKey.keyId must equal questionKey.publicKeySpkiSha256`,
      );
    }
    literal(
      questionKey.purpose,
      QUESTION_VOTING_KEY_PURPOSE_V3,
      `${path}.questionKey.purpose`,
      errors,
    );
  }

  const eligibility = exactObject(
    object.eligibility,
    `${path}.eligibility`,
    ["claim", "policy"],
    errors,
  );
  if (eligibility) {
    stableId(eligibility.claim, `${path}.eligibility.claim`, errors);
    collectPolicyReference(eligibility.policy, `${path}.eligibility.policy`, errors);
    if (
      isObject(object.binding) &&
      canonicalizeJson(eligibility.policy) !==
        canonicalizeJson(object.binding.eligibilityPolicy)
    ) {
      errors.push(`${path}.eligibility.policy must equal binding.eligibilityPolicy`);
    }
  }

  const checkpoint = exactObject(
    object.registryCheckpoint,
    `${path}.registryCheckpoint`,
    ["id", "sha256", "witness"],
    errors,
  );
  if (checkpoint) {
    stableId(checkpoint.id, `${path}.registryCheckpoint.id`, errors);
    digest(checkpoint.sha256, `${path}.registryCheckpoint.sha256`, errors);
    const witness = exactObject(
      checkpoint.witness,
      `${path}.registryCheckpoint.witness`,
      ["canonicalEnvelope", "envelopeSha256"],
      errors,
    );
    if (witness) {
      nonEmpty(
        witness.canonicalEnvelope,
        `${path}.registryCheckpoint.witness.canonicalEnvelope`,
        errors,
      );
      digest(
        witness.envelopeSha256,
        `${path}.registryCheckpoint.witness.envelopeSha256`,
        errors,
      );
    }
  }

  timestamp(object.issuedAt, `${path}.issuedAt`, errors);
  timestamp(object.expiresAt, `${path}.expiresAt`, errors);
  orderedTimestamps(object.issuedAt, object.expiresAt, `${path}.expiresAt`, errors);

  const issuer = exactObject(
    object.issuerAttestation,
    `${path}.issuerAttestation`,
    ["audience", "purpose"],
    errors,
  );
  if (issuer) {
    nonEmpty(issuer.audience, `${path}.issuerAttestation.audience`, errors);
    literal(
      issuer.purpose,
      QUESTION_VOTING_ATTESTATION_PURPOSE_V3,
      `${path}.issuerAttestation.purpose`,
      errors,
    );
  }
  return errors;
}

function collectVoteEventErrors(value: unknown, path: string) {
  const errors: string[] = [];
  const object = exactObject(
    value,
    path,
    [
      "schema",
      "eventId",
      "eventType",
      "binding",
      "questionNullifier",
      "authorizationSha256",
      "publicationMode",
      "ballotManifestSha256",
      "ballotId",
      "questionId",
      "choiceId",
      "sequence",
      "previousEventSha256",
      "challenge",
      "issuedAt",
      "questionKeyId",
    ],
    errors,
  );
  if (!object) return errors;
  literal(object.schema, VOTE_EVENT_SCHEMA_V3, `${path}.schema`, errors);
  stableId(object.eventId, `${path}.eventId`, errors);
  oneOf(object.eventType, ["cast", "replace", "withdraw"], `${path}.eventType`, errors);
  errors.push(...bindingErrors(object.binding, `${path}.binding`));
  digest(object.questionNullifier, `${path}.questionNullifier`, errors);
  digest(object.authorizationSha256, `${path}.authorizationSha256`, errors);
  oneOf(
    object.publicationMode,
    ["private", "attributed"],
    `${path}.publicationMode`,
    errors,
  );
  digest(object.ballotManifestSha256, `${path}.ballotManifestSha256`, errors);
  stableId(object.ballotId, `${path}.ballotId`, errors);
  stableId(object.questionId, `${path}.questionId`, errors);
  positiveInteger(object.sequence, `${path}.sequence`, errors);
  nullableDigest(object.previousEventSha256, `${path}.previousEventSha256`, errors);
  nonce(object.challenge, `${path}.challenge`, errors);
  timestamp(object.issuedAt, `${path}.issuedAt`, errors);
  digest(object.questionKeyId, `${path}.questionKeyId`, errors);

  if (object.eventType === "withdraw") {
    if (object.choiceId !== null) {
      errors.push(`${path}.choiceId must be null for withdrawal`);
    }
  } else {
    stableId(object.choiceId, `${path}.choiceId`, errors);
  }
  if (object.sequence === 1) {
    if (object.eventType !== "cast") {
      errors.push(`${path}.eventType must be cast at sequence 1`);
    }
    if (object.previousEventSha256 !== null) {
      errors.push(`${path}.previousEventSha256 must be null at sequence 1`);
    }
  } else if (typeof object.sequence === "number" && object.sequence > 1) {
    digest(object.previousEventSha256, `${path}.previousEventSha256`, errors);
    if (object.eventType === "cast") {
      errors.push(`${path}.eventType must be replace or withdraw after sequence 1`);
    }
  }
  return errors;
}

function bindingErrors(value: unknown, path: string) {
  return collectBindingErrors(value, path);
}

function collectBindingErrors(value: unknown, path: string) {
  const errors: string[] = [];
  const object = exactObject(
    value,
    path,
    [
      "instance",
      "eligibilityPolicy",
      "tallyPolicy",
      "trustPolicy",
      "audience",
      "origin",
    ],
    errors,
  );
  if (!object) return errors;
  const instance = exactObject(
    object.instance,
    `${path}.instance`,
    ["id", "profileSha256"],
    errors,
  );
  if (instance) {
    stableId(instance.id, `${path}.instance.id`, errors);
    digest(instance.profileSha256, `${path}.instance.profileSha256`, errors);
  }
  collectPolicyReference(object.eligibilityPolicy, `${path}.eligibilityPolicy`, errors);
  collectPolicyReference(object.tallyPolicy, `${path}.tallyPolicy`, errors);
  collectPolicyReference(object.trustPolicy, `${path}.trustPolicy`, errors);
  nonEmpty(object.audience, `${path}.audience`, errors);
  exactOrigin(object.origin, `${path}.origin`, errors);
  return errors;
}

function collectBallotErrors(value: unknown, path: string) {
  const errors: string[] = [];
  const object = exactObject(
    value,
    path,
    [
      "schema",
      "manifestId",
      "ballotId",
      "questionId",
      "nullifierKeyEpoch",
      "revision",
      "binding",
      "meaning",
      "presentation",
      "publishedAt",
      "issuer",
    ],
    errors,
  );
  if (!object) return errors;
  literal(object.schema, BALLOT_MANIFEST_SCHEMA_V3, `${path}.schema`, errors);
  stableId(object.manifestId, `${path}.manifestId`, errors);
  stableId(object.ballotId, `${path}.ballotId`, errors);
  stableId(object.questionId, `${path}.questionId`, errors);
  positiveInteger(object.nullifierKeyEpoch, `${path}.nullifierKeyEpoch`, errors);
  positiveInteger(object.revision, `${path}.revision`, errors);
  errors.push(...collectBindingErrors(object.binding, `${path}.binding`));

  const meaning = exactObject(object.meaning, `${path}.meaning`, ["choices"], errors);
  const meaningIds: string[] = [];
  if (meaning) {
    if (!Array.isArray(meaning.choices) || meaning.choices.length < 2) {
      errors.push(`${path}.meaning.choices must contain at least two choices`);
    } else {
      const ids = new Set<string>();
      const slugs = new Set<string>();
      let previousOrder = Number.NEGATIVE_INFINITY;
      for (const [index, choice] of meaning.choices.entries()) {
        const choicePath = `${path}.meaning.choices[${index}]`;
        const item = exactObject(
          choice,
          choicePath,
          ["id", "slug", "semanticCode", "displayOrder", "isCounted"],
          errors,
        );
        if (!item) continue;
        stableId(item.id, `${choicePath}.id`, errors);
        stableId(item.slug, `${choicePath}.slug`, errors);
        nullableString(item.semanticCode, `${choicePath}.semanticCode`, errors);
        integer(item.displayOrder, `${choicePath}.displayOrder`, errors);
        booleanValue(item.isCounted, `${choicePath}.isCounted`, errors);
        if (typeof item.id === "string") {
          if (ids.has(item.id)) errors.push(`${choicePath}.id must be unique`);
          ids.add(item.id);
          meaningIds.push(item.id);
        }
        if (typeof item.slug === "string") {
          if (slugs.has(item.slug)) {
            errors.push(`${choicePath}.slug must be unique`);
          }
          slugs.add(item.slug);
        }
        if (typeof item.displayOrder === "number") {
          if (item.displayOrder < previousOrder) {
            errors.push(`${path}.meaning.choices must be ordered by displayOrder`);
          }
          previousOrder = item.displayOrder;
        }
      }
    }
  }

  const presentation = exactObject(
    object.presentation,
    `${path}.presentation`,
    ["locale", "questionText", "plainLanguageText", "choices"],
    errors,
  );
  if (presentation) {
    nonEmpty(presentation.locale, `${path}.presentation.locale`, errors);
    nonEmpty(presentation.questionText, `${path}.presentation.questionText`, errors);
    nullableString(
      presentation.plainLanguageText,
      `${path}.presentation.plainLanguageText`,
      errors,
    );
    if (!Array.isArray(presentation.choices)) {
      errors.push(`${path}.presentation.choices must be an array`);
    } else {
      const presentedIds: string[] = [];
      const seen = new Set<string>();
      for (const [index, choice] of presentation.choices.entries()) {
        const choicePath = `${path}.presentation.choices[${index}]`;
        const item = exactObject(
          choice,
          choicePath,
          ["id", "label", "description"],
          errors,
        );
        if (!item) continue;
        stableId(item.id, `${choicePath}.id`, errors);
        nonEmpty(item.label, `${choicePath}.label`, errors);
        stringValue(item.description, `${choicePath}.description`, errors);
        if (typeof item.id === "string") {
          if (seen.has(item.id)) errors.push(`${choicePath}.id must be unique`);
          seen.add(item.id);
          presentedIds.push(item.id);
        }
      }
      if (
        meaningIds.length > 0 &&
        (presentedIds.length !== meaningIds.length ||
          presentedIds.some((id, index) => id !== meaningIds[index]))
      ) {
        errors.push(
          `${path}.presentation.choices must exactly match meaning.choices order and IDs`,
        );
      }
    }
  }

  timestamp(object.publishedAt, `${path}.publishedAt`, errors);
  const issuer = exactObject(
    object.issuer,
    `${path}.issuer`,
    ["algorithm", "keyId", "purpose"],
    errors,
  );
  if (issuer) {
    literal(issuer.algorithm, "Ed25519", `${path}.issuer.algorithm`, errors);
    stableId(issuer.keyId, `${path}.issuer.keyId`, errors);
    literal(issuer.purpose, "receipt", `${path}.issuer.purpose`, errors);
  }
  return errors;
}

function collectPolicyReference(value: unknown, path: string, errors: string[]) {
  const object = exactObject(value, path, ["id", "sha256"], errors);
  if (!object) return;
  stableId(object.id, `${path}.id`, errors);
  digest(object.sha256, `${path}.sha256`, errors);
}

function exactObject(value: unknown, path: string, keys: string[], errors: string[]) {
  if (!isObject(value)) {
    errors.push(`${path} must be an object`);
    return null;
  }
  const expected = [...keys].sort();
  for (const key of expected) {
    if (!Object.hasOwn(value, key)) errors.push(`${path}.${key} is required`);
  }
  for (const key of Object.keys(value).sort()) {
    if (!expected.includes(key)) {
      errors.push(`${path}.${key} is not allowed in this schema version`);
    }
  }
  return value;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function nonEmpty(value: unknown, path: string, errors: string[]) {
  if (typeof value !== "string" || value.trim().length === 0) {
    errors.push(`${path} must be a non-empty string`);
  }
}

function stringValue(value: unknown, path: string, errors: string[]) {
  if (typeof value !== "string") errors.push(`${path} must be a string`);
}

function nullableString(value: unknown, path: string, errors: string[]) {
  if (value !== null && typeof value !== "string") {
    errors.push(`${path} must be a string or null`);
  }
}

function booleanValue(value: unknown, path: string, errors: string[]) {
  if (typeof value !== "boolean") errors.push(`${path} must be a boolean`);
}

function stableId(value: unknown, path: string, errors: string[]) {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$/.test(value)
  ) {
    errors.push(`${path} must be a stable, portable identifier`);
  }
}

function literal(value: unknown, expected: string, path: string, errors: string[]) {
  if (value !== expected) {
    errors.push(`${path} must be ${JSON.stringify(expected)}`);
  }
}

function oneOf(
  value: unknown,
  options: readonly string[],
  path: string,
  errors: string[],
) {
  if (typeof value !== "string" || !options.includes(value)) {
    errors.push(`${path} must be one of ${options.join(", ")}`);
  }
}

function digest(value: unknown, path: string, errors: string[]) {
  if (!isSha256Base64Url(value)) {
    errors.push(`${path} must be a base64url SHA-256 digest`);
  }
}

function nullableDigest(value: unknown, path: string, errors: string[]) {
  if (value !== null) digest(value, path, errors);
}

function base64Value(value: unknown, path: string, errors: string[]) {
  if (!isBase64Url(value) || value.length === 0) {
    errors.push(`${path} must be non-empty unpadded base64url`);
    return;
  }
  try {
    if (base64UrlDecode(value).length === 0) {
      errors.push(`${path} must decode to at least one byte`);
    }
  } catch {
    errors.push(`${path} must be valid unpadded base64url`);
  }
}

function nonce(value: unknown, path: string, errors: string[]) {
  if (!isBase64Url(value)) {
    errors.push(`${path} must be unpadded base64url`);
    return;
  }
  try {
    if (base64UrlDecode(value).length < 16) {
      errors.push(`${path} must contain at least 128 bits of entropy`);
    }
  } catch {
    errors.push(`${path} must be valid base64url`);
  }
}

function positiveInteger(value: unknown, path: string, errors: string[]) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    errors.push(`${path} must be a positive safe integer`);
  }
}

function integer(value: unknown, path: string, errors: string[]) {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    errors.push(`${path} must be a safe integer`);
  }
}

function timestamp(value: unknown, path: string, errors: string[]) {
  if (typeof value !== "string") {
    errors.push(`${path} must be a normalized UTC timestamp`);
    return;
  }
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) {
    errors.push(`${path} must be a normalized UTC timestamp`);
  }
}

function orderedTimestamps(
  start: unknown,
  end: unknown,
  path: string,
  errors: string[],
) {
  if (typeof start !== "string" || typeof end !== "string") return;
  const startTime = Date.parse(start);
  const endTime = Date.parse(end);
  if (Number.isFinite(startTime) && Number.isFinite(endTime) && endTime <= startTime) {
    errors.push(`${path} must be later than issuedAt`);
  }
}

function exactOrigin(value: unknown, path: string, errors: string[]) {
  if (typeof value !== "string") {
    errors.push(`${path} must be an exact HTTP(S) origin`);
    return;
  }
  try {
    const url = new URL(value);
    if (
      (url.protocol !== "https:" && url.protocol !== "http:") ||
      url.origin !== value
    ) {
      errors.push(`${path} must be an exact HTTP(S) origin`);
    }
  } catch {
    errors.push(`${path} must be an exact HTTP(S) origin`);
  }
}

async function isP256Spki(value: Uint8Array) {
  try {
    await globalThis.crypto.subtle.importKey(
      "spki",
      value.slice(),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return true;
  } catch {
    return false;
  }
}

function result<T>(value: unknown, errors: string[]): ValidationResult<T> {
  return errors.length === 0 ? { ok: true, value: value as T } : { ok: false, errors };
}

function assertValid(errors: string[]) {
  if (errors.length > 0) {
    throw new TypeError(
      `Invalid qualified-opinion V3 payload:\n${errors
        .map((error) => `- ${error}`)
        .join("\n")}`,
    );
  }
}

function rebase(errors: string[], path: string) {
  return errors.map((error) =>
    error.startsWith("$") ? `${path}${error.slice(1)}` : `${path}: ${error}`,
  );
}
