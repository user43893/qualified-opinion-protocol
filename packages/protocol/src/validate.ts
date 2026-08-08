import {
  base64UrlDecode,
  canonicalJsonSha256,
  isBase64Url,
  isSha256Base64Url,
} from "./encoding";
import {
  ELIGIBILITY_DECISION_SCHEMA_V3,
  type EligibilityDecisionV3,
  MERKLE_TREE_HEAD_SCHEMA_V3,
  type MerkleTreeHeadV3,
  ROOT_KEY_DELEGATION_SCHEMA_V3,
  type RootKeyDelegationV3,
  type SignedPayload,
  VOTE_ACCEPTANCE_SCHEMA_V3,
  VOTE_ADJUDICATION_SCHEMA_V3,
  type VoteAcceptanceV3,
  type VoteAdjudicationV3,
  type WebAuthnSignedPayload,
} from "./types";

export type ValidationResult<T> =
  | { ok: true; value: T }
  | { ok: false; errors: string[] };

export class ProofProtocolValidationError extends TypeError {
  readonly errors: string[];

  constructor(errors: string[]) {
    super(
      `Invalid qualified-opinion V3 payload:\n${errors
        .map((error) => `- ${error}`)
        .join("\n")}`,
    );
    this.name = "ProofProtocolValidationError";
    this.errors = errors;
  }
}

export function validateEligibilityDecisionV3(
  value: unknown,
): ValidationResult<EligibilityDecisionV3> {
  return validate(value, collectEligibilityDecisionErrors);
}

export function assertEligibilityDecisionV3(
  value: unknown,
): asserts value is EligibilityDecisionV3 {
  assertValid(value, collectEligibilityDecisionErrors);
}

export function validateRootKeyDelegationV3(
  value: unknown,
): ValidationResult<RootKeyDelegationV3> {
  return validate(value, collectRootKeyDelegationErrors);
}

export function assertRootKeyDelegationV3(
  value: unknown,
): asserts value is RootKeyDelegationV3 {
  assertValid(value, collectRootKeyDelegationErrors);
}

export function validateVoteAcceptanceV3(
  value: unknown,
): ValidationResult<VoteAcceptanceV3> {
  return validate(value, collectVoteAcceptanceErrors);
}

export function assertVoteAcceptanceV3(
  value: unknown,
): asserts value is VoteAcceptanceV3 {
  assertValid(value, collectVoteAcceptanceErrors);
}

export function validateVoteAdjudicationV3(
  value: unknown,
): ValidationResult<VoteAdjudicationV3> {
  return validate(value, collectVoteAdjudicationErrors);
}

export function assertVoteAdjudicationV3(
  value: unknown,
): asserts value is VoteAdjudicationV3 {
  assertValid(value, collectVoteAdjudicationErrors);
}

export function validateMerkleTreeHeadV3(
  value: unknown,
): ValidationResult<MerkleTreeHeadV3> {
  return validate(value, collectMerkleTreeHeadErrors);
}

export function assertMerkleTreeHeadV3(
  value: unknown,
): asserts value is MerkleTreeHeadV3 {
  assertValid(value, collectMerkleTreeHeadErrors);
}

export async function verifySignedPayloadHash<T>(
  envelope: Pick<SignedPayload<T>, "payload" | "payloadSha256">,
): Promise<boolean> {
  return (await canonicalJsonSha256(envelope.payload)) === envelope.payloadSha256;
}

export async function verifyWebAuthnSignedPayloadHash<T>(
  envelope: Pick<WebAuthnSignedPayload<T>, "payload" | "payloadSha256">,
): Promise<boolean> {
  return verifySignedPayloadHash(envelope);
}

function collectEligibilityDecisionErrors(value: unknown, path: string) {
  const errors: string[] = [];
  const object = exactObject(
    value,
    path,
    [
      "schema",
      "decisionId",
      "assertionSha256",
      "publicVoterId",
      "sequence",
      "status",
      "reason",
      "previousDecisionSha256",
      "effectiveAt",
      "issuerKeyId",
    ],
    errors,
  );
  if (!object) return errors;
  literal(object.schema, ELIGIBILITY_DECISION_SCHEMA_V3, `${path}.schema`, errors);
  stableId(object.decisionId, `${path}.decisionId`, errors);
  digest(object.assertionSha256, `${path}.assertionSha256`, errors);
  stableId(object.publicVoterId, `${path}.publicVoterId`, errors);
  positiveInteger(object.sequence, `${path}.sequence`, errors);
  oneOf(object.status, ["active", "revoked"], `${path}.status`, errors);
  nullableString(object.reason, `${path}.reason`, errors);
  nullableDigest(
    object.previousDecisionSha256,
    `${path}.previousDecisionSha256`,
    errors,
  );
  timestamp(object.effectiveAt, `${path}.effectiveAt`, errors);
  stableId(object.issuerKeyId, `${path}.issuerKeyId`, errors);
  if (object.sequence === 1 && object.previousDecisionSha256 !== null) {
    errors.push(`${path}.previousDecisionSha256 must be null at sequence 1`);
  } else if (
    typeof object.sequence === "number" &&
    object.sequence > 1 &&
    object.previousDecisionSha256 === null
  ) {
    errors.push(`${path}.previousDecisionSha256 is required after sequence 1`);
  }
  return errors;
}

function collectRootKeyDelegationErrors(value: unknown, path: string) {
  const errors: string[] = [];
  const object = exactObject(
    value,
    path,
    [
      "schema",
      "delegationId",
      "publicVoterId",
      "rootCredentialId",
      "delegatedKey",
      "scope",
      "nonce",
      "issuedAt",
      "expiresAt",
    ],
    errors,
  );
  if (!object) return errors;
  literal(object.schema, ROOT_KEY_DELEGATION_SCHEMA_V3, `${path}.schema`, errors);
  stableId(object.delegationId, `${path}.delegationId`, errors);
  stableId(object.publicVoterId, `${path}.publicVoterId`, errors);
  nonEmpty(object.rootCredentialId, `${path}.rootCredentialId`, errors);
  const key = exactObject(
    object.delegatedKey,
    `${path}.delegatedKey`,
    ["algorithm", "publicKeySpki"],
    errors,
  );
  if (key) {
    literal(key.algorithm, "ES256", `${path}.delegatedKey.algorithm`, errors);
    base64(key.publicKeySpki, `${path}.delegatedKey.publicKeySpki`, errors);
  }
  const scope = exactObject(
    object.scope,
    `${path}.scope`,
    ["audience", "actions", "questionIds"],
    errors,
  );
  if (scope) {
    nonEmpty(scope.audience, `${path}.scope.audience`, errors);
    stringArray(
      scope.actions,
      ["vote:cast", "vote:replace", "vote:withdraw"],
      `${path}.scope.actions`,
      errors,
    );
    if (scope.questionIds !== null) {
      stringArray(scope.questionIds, null, `${path}.scope.questionIds`, errors);
    }
  }
  nonce(object.nonce, `${path}.nonce`, errors);
  timestamp(object.issuedAt, `${path}.issuedAt`, errors);
  timestamp(object.expiresAt, `${path}.expiresAt`, errors);
  if (
    typeof object.issuedAt === "string" &&
    typeof object.expiresAt === "string" &&
    Date.parse(object.expiresAt) <= Date.parse(object.issuedAt)
  ) {
    errors.push(`${path}.expiresAt must be later than issuedAt`);
  }
  return errors;
}

function collectVoteAcceptanceErrors(value: unknown, path: string) {
  const errors: string[] = [];
  const object = exactObject(
    value,
    path,
    [
      "schema",
      "receiptId",
      "voteEventSha256",
      "status",
      "logId",
      "receivedAt",
      "issuerKeyId",
    ],
    errors,
  );
  if (!object) return errors;
  literal(object.schema, VOTE_ACCEPTANCE_SCHEMA_V3, `${path}.schema`, errors);
  stableId(object.receiptId, `${path}.receiptId`, errors);
  digest(object.voteEventSha256, `${path}.voteEventSha256`, errors);
  literal(object.status, "counted", `${path}.status`, errors);
  stableId(object.logId, `${path}.logId`, errors);
  timestamp(object.receivedAt, `${path}.receivedAt`, errors);
  stableId(object.issuerKeyId, `${path}.issuerKeyId`, errors);
  return errors;
}

function collectVoteAdjudicationErrors(value: unknown, path: string) {
  const errors: string[] = [];
  const object = exactObject(
    value,
    path,
    [
      "schema",
      "receiptId",
      "voteEventSha256",
      "sequence",
      "status",
      "reasonCode",
      "eligibilityAssertionSha256",
      "eligibilityDecisionSha256",
      "previousReceiptSha256",
      "logId",
      "receivedAt",
      "issuerKeyId",
    ],
    errors,
  );
  if (!object) return errors;
  literal(object.schema, VOTE_ADJUDICATION_SCHEMA_V3, `${path}.schema`, errors);
  stableId(object.receiptId, `${path}.receiptId`, errors);
  digest(object.voteEventSha256, `${path}.voteEventSha256`, errors);
  positiveInteger(object.sequence, `${path}.sequence`, errors);
  if (typeof object.sequence === "number" && object.sequence < 2) {
    errors.push(`${path}.sequence must start at 2`);
  }
  oneOf(object.status, ["counted", "excluded", "rejected"], `${path}.status`, errors);
  oneOf(
    object.reasonCode,
    ["authorization_revoked", "authorization_superseded", "administrative_rejection"],
    `${path}.reasonCode`,
    errors,
  );
  literal(
    object.eligibilityAssertionSha256,
    null,
    `${path}.eligibilityAssertionSha256`,
    errors,
  );
  literal(
    object.eligibilityDecisionSha256,
    null,
    `${path}.eligibilityDecisionSha256`,
    errors,
  );
  digest(object.previousReceiptSha256, `${path}.previousReceiptSha256`, errors);
  stableId(object.logId, `${path}.logId`, errors);
  timestamp(object.receivedAt, `${path}.receivedAt`, errors);
  stableId(object.issuerKeyId, `${path}.issuerKeyId`, errors);
  return errors;
}

function collectMerkleTreeHeadErrors(value: unknown, path: string) {
  const errors: string[] = [];
  const object = exactObject(
    value,
    path,
    [
      "schema",
      "logId",
      "treeSize",
      "rootHash",
      "previousTreeHeadSha256",
      "issuedAt",
      "issuerKeyId",
    ],
    errors,
  );
  if (!object) return errors;
  literal(object.schema, MERKLE_TREE_HEAD_SCHEMA_V3, `${path}.schema`, errors);
  stableId(object.logId, `${path}.logId`, errors);
  nonNegativeInteger(object.treeSize, `${path}.treeSize`, errors);
  digest(object.rootHash, `${path}.rootHash`, errors);
  nullableDigest(
    object.previousTreeHeadSha256,
    `${path}.previousTreeHeadSha256`,
    errors,
  );
  timestamp(object.issuedAt, `${path}.issuedAt`, errors);
  stableId(object.issuerKeyId, `${path}.issuerKeyId`, errors);
  return errors;
}

function validate<T>(
  value: unknown,
  collector: (value: unknown, path: string) => string[],
): ValidationResult<T> {
  const errors = collector(value, "$");
  return errors.length === 0 ? { ok: true, value: value as T } : { ok: false, errors };
}

function assertValid(
  value: unknown,
  collector: (value: unknown, path: string) => string[],
) {
  const errors = collector(value, "$");
  if (errors.length > 0) throw new ProofProtocolValidationError(errors);
}

function exactObject(
  value: unknown,
  path: string,
  keys: readonly string[],
  errors: string[],
) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    errors.push(`${path} must be an object`);
    return null;
  }
  const object = value as Record<string, unknown>;
  const expected = [...keys].sort();
  for (const key of expected) {
    if (!Object.hasOwn(object, key)) errors.push(`${path}.${key} is required`);
  }
  for (const key of Object.keys(object).sort()) {
    if (!expected.includes(key)) errors.push(`${path}.${key} is not allowed`);
  }
  return object;
}

function stableId(value: unknown, path: string, errors: string[]) {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$/.test(value)
  ) {
    errors.push(`${path} must be a stable, portable identifier`);
  }
}

function nonEmpty(value: unknown, path: string, errors: string[]) {
  if (typeof value !== "string" || value.trim().length === 0) {
    errors.push(`${path} must be a non-empty string`);
  }
}

function nullableString(value: unknown, path: string, errors: string[]) {
  if (value !== null && typeof value !== "string") {
    errors.push(`${path} must be a string or null`);
  }
}

function oneOf(
  value: unknown,
  choices: readonly string[],
  path: string,
  errors: string[],
) {
  if (typeof value !== "string" || !choices.includes(value)) {
    errors.push(`${path} must be one of ${choices.join(", ")}`);
  }
}

function literal(value: unknown, expected: unknown, path: string, errors: string[]) {
  if (value !== expected) {
    errors.push(`${path} must equal ${JSON.stringify(expected)}`);
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

function base64(value: unknown, path: string, errors: string[]) {
  if (!isBase64Url(value) || value.length === 0) {
    errors.push(`${path} must be non-empty unpadded base64url`);
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

function nonNegativeInteger(value: unknown, path: string, errors: string[]) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    errors.push(`${path} must be a nonnegative safe integer`);
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

function stringArray(
  value: unknown,
  allowed: readonly string[] | null,
  path: string,
  errors: string[],
) {
  if (!Array.isArray(value) || value.length === 0) {
    errors.push(`${path} must be a non-empty string array`);
    return;
  }
  const seen = new Set<string>();
  for (const [index, entry] of value.entries()) {
    nonEmpty(entry, `${path}[${index}]`, errors);
    if (typeof entry !== "string") continue;
    if (seen.has(entry)) errors.push(`${path}[${index}] must be unique`);
    if (allowed && !allowed.includes(entry)) {
      errors.push(`${path}[${index}] is not allowed`);
    }
    seen.add(entry);
  }
}
