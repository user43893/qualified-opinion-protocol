import { type JsonValue, canonicalizeJson } from "./canonical";
import {
  type EligibilityAssertionV3,
  assertEligibilityAssertionV3,
} from "./eligibility-v3";
import {
  base64UrlEncode,
  canonicalJsonSha256,
  isBase64Url,
  isSha256Base64Url,
} from "./encoding";
import {
  computeMerkleRoot,
  createMerkleInclusionProof,
  verifyMerkleInclusionProof,
} from "./merkle";
import type { EligibilityDecisionV3, SignedPayload } from "./types";
import { assertEligibilityDecisionV3, verifySignedPayloadHash } from "./validate";

export const ACTIVE_ELIGIBILITY_DIRECTORY_RECORD_SCHEMA_V3 =
  "qualified-opinion.active-eligibility-directory-record.v3" as const;
export const ACTIVE_ELIGIBILITY_DIRECTORY_LEAF_SCHEMA_V3 =
  "qualified-opinion.active-eligibility-directory-leaf.v3" as const;
export const ACTIVE_ELIGIBILITY_DIRECTORY_CHECKPOINT_SCHEMA_V3 =
  "qualified-opinion.active-eligibility-directory-checkpoint.v3" as const;
export const ACTIVE_ELIGIBILITY_DIRECTORY_BUNDLE_SCHEMA_V3 =
  "qualified-opinion.active-eligibility-directory-bundle.v3" as const;
export const ACTIVE_ELIGIBILITY_DIRECTORY_RECORD_PROOF_SCHEMA_V3 =
  "qualified-opinion.active-eligibility-directory-record-proof.v3" as const;

export type ActiveEligibilityDirectoryRegistrationV3 = {
  proofId: string;
  payload: JsonValue;
  payloadSha256: string;
  attestationToken: string;
};

/**
 * Minimal canonical public record for one current registration. Human-readable
 * identity and registry fields are deliberately not duplicated outside the
 * attested receipt and eligibility-signed assertion.
 */
export type ActiveEligibilityDirectoryRecordV3 = {
  schema: typeof ACTIVE_ELIGIBILITY_DIRECTORY_RECORD_SCHEMA_V3;
  publicVoterId: string;
  registration: ActiveEligibilityDirectoryRegistrationV3;
  eligibilityAssertion: SignedPayload<EligibilityAssertionV3>;
  eligibilityDecision: SignedPayload<EligibilityDecisionV3>;
};

export type ActiveEligibilityDirectoryLeafV3 = {
  schema: typeof ACTIVE_ELIGIBILITY_DIRECTORY_LEAF_SCHEMA_V3;
  publicVoterId: string;
  recordSha256: string;
};

/**
 * Signed mutable-set head. `previousCheckpointSha256` makes independently
 * observed heads monotonic, while the RFC 6962 root commits to the complete
 * deterministic list at this sequence.
 */
export type ActiveEligibilityDirectoryCheckpointV3 = {
  schema: typeof ACTIVE_ELIGIBILITY_DIRECTORY_CHECKPOINT_SCHEMA_V3;
  directoryId: string;
  instanceId: string;
  protocolBindingSha256: string;
  sequence: number;
  treeSize: number;
  rootHash: string;
  previousCheckpointSha256: string | null;
  issuedAt: string;
  issuer: {
    algorithm: "Ed25519";
    keyId: string;
    purpose: "eligibility";
  };
};

export type ActiveEligibilityDirectoryBundleV3 = {
  schema: typeof ACTIVE_ELIGIBILITY_DIRECTORY_BUNDLE_SCHEMA_V3;
  checkpoint: SignedPayload<ActiveEligibilityDirectoryCheckpointV3>;
  records: ActiveEligibilityDirectoryRecordV3[];
};

export type ActiveEligibilityDirectoryRecordProofV3 = {
  schema: typeof ACTIVE_ELIGIBILITY_DIRECTORY_RECORD_PROOF_SCHEMA_V3;
  checkpoint: SignedPayload<ActiveEligibilityDirectoryCheckpointV3>;
  record: ActiveEligibilityDirectoryRecordV3;
  recordSha256: string;
  leafIndex: number;
  auditPath: string[];
};

export async function buildActiveEligibilityDirectoryRecordV3(input: {
  publicVoterId: string;
  registration: ActiveEligibilityDirectoryRegistrationV3;
  eligibilityAssertion: SignedPayload<EligibilityAssertionV3>;
  eligibilityDecision: SignedPayload<EligibilityDecisionV3>;
}): Promise<ActiveEligibilityDirectoryRecordV3> {
  const record: ActiveEligibilityDirectoryRecordV3 = {
    schema: ACTIVE_ELIGIBILITY_DIRECTORY_RECORD_SCHEMA_V3,
    publicVoterId: input.publicVoterId,
    registration: structuredClone(input.registration),
    eligibilityAssertion: structuredClone(input.eligibilityAssertion),
    eligibilityDecision: structuredClone(input.eligibilityDecision),
  };
  assertActiveEligibilityDirectoryRecordV3(record);
  if (!(await verifyActiveEligibilityDirectoryRecordIntegrityV3(record))) {
    throw new TypeError("active eligibility directory record integrity failed");
  }
  return record;
}

export async function activeEligibilityDirectoryRecordSha256V3(
  record: ActiveEligibilityDirectoryRecordV3,
) {
  assertActiveEligibilityDirectoryRecordV3(record);
  return canonicalJsonSha256(record);
}

export async function buildActiveEligibilityDirectoryLeavesV3(
  records: readonly ActiveEligibilityDirectoryRecordV3[],
) {
  const leaves = await Promise.all(
    records.map(async (record) => {
      assertActiveEligibilityDirectoryRecordV3(record);
      return {
        schema: ACTIVE_ELIGIBILITY_DIRECTORY_LEAF_SCHEMA_V3,
        publicVoterId: record.publicVoterId,
        recordSha256: await activeEligibilityDirectoryRecordSha256V3(record),
      } satisfies ActiveEligibilityDirectoryLeafV3;
    }),
  );
  leaves.sort((left, right) => left.publicVoterId.localeCompare(right.publicVoterId));
  if (
    leaves.some(
      (leaf, index) =>
        index > 0 && leaf.publicVoterId === leaves[index - 1]?.publicVoterId,
    )
  ) {
    throw new TypeError(
      "active eligibility directory publicVoterId values must be unique",
    );
  }
  return leaves;
}

export async function buildActiveEligibilityDirectoryCheckpointV3(input: {
  directoryId: string;
  instanceId: string;
  protocolBindingSha256: string;
  sequence: number;
  previousCheckpointSha256: string | null;
  issuedAt: Date | string;
  issuerKeyId: string;
  leaves: readonly ActiveEligibilityDirectoryLeafV3[];
}): Promise<ActiveEligibilityDirectoryCheckpointV3> {
  const leaves = [...input.leaves];
  for (const leaf of leaves) assertActiveEligibilityDirectoryLeafV3(leaf);
  assertSortedUniqueLeaves(leaves);
  const payload: ActiveEligibilityDirectoryCheckpointV3 = {
    schema: ACTIVE_ELIGIBILITY_DIRECTORY_CHECKPOINT_SCHEMA_V3,
    directoryId: input.directoryId,
    instanceId: input.instanceId,
    protocolBindingSha256: input.protocolBindingSha256,
    sequence: input.sequence,
    treeSize: leaves.length,
    rootHash: base64UrlEncode(
      await computeMerkleRoot(leaves.map((leaf) => canonicalizeJson(leaf))),
    ),
    previousCheckpointSha256: input.previousCheckpointSha256,
    issuedAt: isoTimestamp(input.issuedAt),
    issuer: {
      algorithm: "Ed25519",
      keyId: input.issuerKeyId,
      purpose: "eligibility",
    },
  };
  assertActiveEligibilityDirectoryCheckpointV3(payload);
  return payload;
}

export function buildActiveEligibilityDirectoryBundleV3(input: {
  checkpoint: SignedPayload<ActiveEligibilityDirectoryCheckpointV3>;
  records: readonly ActiveEligibilityDirectoryRecordV3[];
}): ActiveEligibilityDirectoryBundleV3 {
  const bundle: ActiveEligibilityDirectoryBundleV3 = {
    schema: ACTIVE_ELIGIBILITY_DIRECTORY_BUNDLE_SCHEMA_V3,
    checkpoint: structuredClone(input.checkpoint),
    records: structuredClone([...input.records]),
  };
  assertActiveEligibilityDirectoryBundleV3(bundle);
  return bundle;
}

export async function buildActiveEligibilityDirectoryRecordProofV3(input: {
  checkpoint: SignedPayload<ActiveEligibilityDirectoryCheckpointV3>;
  records: readonly ActiveEligibilityDirectoryRecordV3[];
  publicVoterId: string;
}): Promise<ActiveEligibilityDirectoryRecordProofV3> {
  const leaves = await buildActiveEligibilityDirectoryLeavesV3(input.records);
  const leafIndex = leaves.findIndex(
    (leaf) => leaf.publicVoterId === input.publicVoterId,
  );
  const record = input.records.find(
    (candidate) => candidate.publicVoterId === input.publicVoterId,
  );
  if (leafIndex < 0 || !record) {
    throw new TypeError(
      "active eligibility directory record is absent from the current set",
    );
  }
  const proof = await createMerkleInclusionProof(
    leaves.map((leaf) => canonicalizeJson(leaf)),
    leafIndex,
  );
  if (
    proof.treeSize !== input.checkpoint.payload.treeSize ||
    proof.rootHash !== input.checkpoint.payload.rootHash
  ) {
    throw new TypeError(
      "active eligibility directory checkpoint does not match records",
    );
  }
  const result: ActiveEligibilityDirectoryRecordProofV3 = {
    schema: ACTIVE_ELIGIBILITY_DIRECTORY_RECORD_PROOF_SCHEMA_V3,
    checkpoint: structuredClone(input.checkpoint),
    record: structuredClone(record),
    recordSha256: leaves[leafIndex]?.recordSha256 ?? "",
    leafIndex,
    auditPath: proof.auditPath,
  };
  assertActiveEligibilityDirectoryRecordProofV3(result);
  return result;
}

export async function verifyActiveEligibilityDirectoryRecordIntegrityV3(
  record: ActiveEligibilityDirectoryRecordV3,
) {
  try {
    assertActiveEligibilityDirectoryRecordV3(record);
    return (
      record.registration.payloadSha256 ===
        (await canonicalJsonSha256(record.registration.payload)) &&
      (await verifySignedPayloadHash(record.eligibilityAssertion)) &&
      (await verifySignedPayloadHash(record.eligibilityDecision))
    );
  } catch {
    return false;
  }
}

/**
 * Proves exact full-list completeness relative to the signed checkpoint:
 * every committed leaf has one body and no extra body is admitted.
 */
export async function verifyActiveEligibilityDirectoryBundleIntegrityV3(
  bundle: ActiveEligibilityDirectoryBundleV3,
) {
  const errors: string[] = [];
  try {
    assertActiveEligibilityDirectoryBundleV3(bundle);
  } catch (error) {
    return {
      ok: false as const,
      errors: validationMessages(error),
    };
  }
  if (!(await verifySignedPayloadHash(bundle.checkpoint))) {
    errors.push("checkpoint_payload_hash_invalid");
  }
  const records = [...bundle.records].sort((left, right) =>
    left.publicVoterId.localeCompare(right.publicVoterId),
  );
  if (
    records.some(
      (record, index) =>
        index > 0 && record.publicVoterId === records[index - 1]?.publicVoterId,
    )
  ) {
    errors.push("directory_record_public_voter_duplicate");
  }
  for (const record of records) {
    if (!(await verifyActiveEligibilityDirectoryRecordIntegrityV3(record))) {
      errors.push(`directory_record_integrity_invalid:${record.publicVoterId}`);
    }
  }
  try {
    const leaves = await buildActiveEligibilityDirectoryLeavesV3(records);
    const rootHash = base64UrlEncode(
      await computeMerkleRoot(leaves.map((leaf) => canonicalizeJson(leaf))),
    );
    if (bundle.checkpoint.payload.treeSize !== leaves.length) {
      errors.push("directory_record_count_mismatch");
    }
    if (bundle.checkpoint.payload.rootHash !== rootHash) {
      errors.push("directory_record_root_mismatch");
    }
  } catch (error) {
    errors.push(...validationMessages(error));
  }
  return errors.length === 0
    ? { ok: true as const, value: bundle }
    : { ok: false as const, errors };
}

export async function verifyActiveEligibilityDirectoryRecordProofIntegrityV3(
  proof: ActiveEligibilityDirectoryRecordProofV3,
) {
  const errors: string[] = [];
  try {
    assertActiveEligibilityDirectoryRecordProofV3(proof);
  } catch (error) {
    return { ok: false as const, errors: validationMessages(error) };
  }
  if (!(await verifySignedPayloadHash(proof.checkpoint))) {
    errors.push("checkpoint_payload_hash_invalid");
  }
  if (!(await verifyActiveEligibilityDirectoryRecordIntegrityV3(proof.record))) {
    errors.push("directory_record_integrity_invalid");
  }
  const actualRecordSha256 = await activeEligibilityDirectoryRecordSha256V3(
    proof.record,
  );
  if (actualRecordSha256 !== proof.recordSha256) {
    errors.push("directory_record_hash_mismatch");
  }
  const leaf: ActiveEligibilityDirectoryLeafV3 = {
    schema: ACTIVE_ELIGIBILITY_DIRECTORY_LEAF_SCHEMA_V3,
    publicVoterId: proof.record.publicVoterId,
    recordSha256: proof.recordSha256,
  };
  if (
    !(await verifyMerkleInclusionProof({
      leaf: canonicalizeJson(leaf),
      leafIndex: proof.leafIndex,
      treeSize: proof.checkpoint.payload.treeSize,
      auditPath: proof.auditPath,
      expectedRootHash: proof.checkpoint.payload.rootHash,
    }))
  ) {
    errors.push("directory_record_inclusion_invalid");
  }
  return errors.length === 0
    ? { ok: true as const, value: proof }
    : { ok: false as const, errors };
}

export function assertActiveEligibilityDirectoryRecordV3(
  value: unknown,
): asserts value is ActiveEligibilityDirectoryRecordV3 {
  const object = exactObject(value, "$", [
    "schema",
    "publicVoterId",
    "registration",
    "eligibilityAssertion",
    "eligibilityDecision",
  ]);
  literal(object.schema, ACTIVE_ELIGIBILITY_DIRECTORY_RECORD_SCHEMA_V3, "$.schema");
  stableId(object.publicVoterId, "$.publicVoterId");
  const registration = exactObject(object.registration, "$.registration", [
    "proofId",
    "payload",
    "payloadSha256",
    "attestationToken",
  ]);
  stableId(registration.proofId, "$.registration.proofId");
  jsonValue(registration.payload, "$.registration.payload");
  digest(registration.payloadSha256, "$.registration.payloadSha256");
  compactJwt(registration.attestationToken, "$.registration.attestationToken");
  const assertion = signedEnvelope(
    object.eligibilityAssertion,
    "$.eligibilityAssertion",
  );
  assertEligibilityAssertionV3(assertion.payload);
  const decision = signedEnvelope(object.eligibilityDecision, "$.eligibilityDecision");
  assertEligibilityDecisionV3(decision.payload);
}

export function assertActiveEligibilityDirectoryLeafV3(
  value: unknown,
): asserts value is ActiveEligibilityDirectoryLeafV3 {
  const object = exactObject(value, "$", ["schema", "publicVoterId", "recordSha256"]);
  literal(object.schema, ACTIVE_ELIGIBILITY_DIRECTORY_LEAF_SCHEMA_V3, "$.schema");
  stableId(object.publicVoterId, "$.publicVoterId");
  digest(object.recordSha256, "$.recordSha256");
}

export function assertActiveEligibilityDirectoryCheckpointV3(
  value: unknown,
): asserts value is ActiveEligibilityDirectoryCheckpointV3 {
  const object = exactObject(value, "$", [
    "schema",
    "directoryId",
    "instanceId",
    "protocolBindingSha256",
    "sequence",
    "treeSize",
    "rootHash",
    "previousCheckpointSha256",
    "issuedAt",
    "issuer",
  ]);
  literal(object.schema, ACTIVE_ELIGIBILITY_DIRECTORY_CHECKPOINT_SCHEMA_V3, "$.schema");
  stableId(object.directoryId, "$.directoryId");
  stableId(object.instanceId, "$.instanceId");
  digest(object.protocolBindingSha256, "$.protocolBindingSha256");
  positiveInteger(object.sequence, "$.sequence");
  nonNegativeInteger(object.treeSize, "$.treeSize");
  digest(object.rootHash, "$.rootHash");
  nullableDigest(object.previousCheckpointSha256, "$.previousCheckpointSha256");
  if (object.sequence === 1 && object.previousCheckpointSha256 !== null) {
    fail("$.previousCheckpointSha256 must be null at sequence 1");
  }
  if (
    typeof object.sequence === "number" &&
    object.sequence > 1 &&
    object.previousCheckpointSha256 === null
  ) {
    fail("$.previousCheckpointSha256 is required after sequence 1");
  }
  timestamp(object.issuedAt, "$.issuedAt");
  const issuer = exactObject(object.issuer, "$.issuer", [
    "algorithm",
    "keyId",
    "purpose",
  ]);
  literal(issuer.algorithm, "Ed25519", "$.issuer.algorithm");
  stableId(issuer.keyId, "$.issuer.keyId");
  literal(issuer.purpose, "eligibility", "$.issuer.purpose");
}

export function assertActiveEligibilityDirectoryBundleV3(
  value: unknown,
): asserts value is ActiveEligibilityDirectoryBundleV3 {
  const object = exactObject(value, "$", ["schema", "checkpoint", "records"]);
  literal(object.schema, ACTIVE_ELIGIBILITY_DIRECTORY_BUNDLE_SCHEMA_V3, "$.schema");
  const checkpoint = signedEnvelope(object.checkpoint, "$.checkpoint");
  assertActiveEligibilityDirectoryCheckpointV3(checkpoint.payload);
  if (!Array.isArray(object.records)) fail("$.records must be an array");
  for (const [index, record] of object.records.entries()) {
    try {
      assertActiveEligibilityDirectoryRecordV3(record);
    } catch (error) {
      fail(`$.records[${index}] is invalid: ${validationMessages(error).join("; ")}`);
    }
  }
}

export function assertActiveEligibilityDirectoryRecordProofV3(
  value: unknown,
): asserts value is ActiveEligibilityDirectoryRecordProofV3 {
  const object = exactObject(value, "$", [
    "schema",
    "checkpoint",
    "record",
    "recordSha256",
    "leafIndex",
    "auditPath",
  ]);
  literal(
    object.schema,
    ACTIVE_ELIGIBILITY_DIRECTORY_RECORD_PROOF_SCHEMA_V3,
    "$.schema",
  );
  const checkpoint = signedEnvelope(object.checkpoint, "$.checkpoint");
  assertActiveEligibilityDirectoryCheckpointV3(checkpoint.payload);
  assertActiveEligibilityDirectoryRecordV3(object.record);
  digest(object.recordSha256, "$.recordSha256");
  nonNegativeInteger(object.leafIndex, "$.leafIndex");
  if (!Array.isArray(object.auditPath)) fail("$.auditPath must be an array");
  for (const [index, item] of object.auditPath.entries()) {
    digest(item, `$.auditPath[${index}]`);
  }
}

function signedEnvelope(value: unknown, path: string) {
  const object = exactObject(value, path, ["payload", "payloadSha256", "signature"]);
  digest(object.payloadSha256, `${path}.payloadSha256`);
  const signature = exactObject(object.signature, `${path}.signature`, [
    "algorithm",
    "keyId",
    "value",
  ]);
  literal(signature.algorithm, "Ed25519", `${path}.signature.algorithm`);
  stableId(signature.keyId, `${path}.signature.keyId`);
  base64Url(signature.value, `${path}.signature.value`);
  return object as unknown as SignedPayload<unknown>;
}

function assertSortedUniqueLeaves(leaves: readonly ActiveEligibilityDirectoryLeafV3[]) {
  for (let index = 0; index < leaves.length; index += 1) {
    const previous = leaves[index - 1];
    const current = leaves[index];
    if (
      !current ||
      (previous && previous.publicVoterId.localeCompare(current.publicVoterId) >= 0)
    ) {
      throw new TypeError(
        "active eligibility directory leaves must be uniquely sorted by publicVoterId",
      );
    }
  }
}

function exactObject(value: unknown, path: string, expectedKeys: readonly string[]) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${path} must be an object`);
  }
  const object = value as Record<string, unknown>;
  const expected = [...expectedKeys].sort();
  const actual = Object.keys(object).sort();
  if (
    expected.length !== actual.length ||
    expected.some((key, index) => key !== actual[index])
  ) {
    fail(`${path} must contain exactly ${expected.join(", ")}`);
  }
  return object;
}

function jsonValue(value: unknown, path: string): asserts value is JsonValue {
  try {
    canonicalizeJson(value as JsonValue);
  } catch {
    fail(`${path} must be canonical JSON data`);
  }
}

function stableId(value: unknown, path: string) {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$/.test(value)
  ) {
    fail(`${path} must be a stable, portable identifier`);
  }
}

function literal(value: unknown, expected: unknown, path: string) {
  if (value !== expected) fail(`${path} must equal ${JSON.stringify(expected)}`);
}

function digest(value: unknown, path: string) {
  if (typeof value !== "string" || !isSha256Base64Url(value)) {
    fail(`${path} must be an unpadded base64url SHA-256 digest`);
  }
}

function nullableDigest(value: unknown, path: string) {
  if (value !== null) digest(value, path);
}

function base64Url(value: unknown, path: string) {
  if (typeof value !== "string" || !isBase64Url(value)) {
    fail(`${path} must be non-empty unpadded base64url`);
  }
}

function compactJwt(value: unknown, path: string) {
  if (
    typeof value !== "string" ||
    value.split(".").length !== 3 ||
    value.split(".").some((part) => !isBase64Url(part))
  ) {
    fail(`${path} must be a three-part compact JWT`);
  }
}

function positiveInteger(value: unknown, path: string) {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    fail(`${path} must be a positive safe integer`);
  }
}

function nonNegativeInteger(value: unknown, path: string) {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    fail(`${path} must be a non-negative safe integer`);
  }
}

function timestamp(value: unknown, path: string) {
  if (
    typeof value !== "string" ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  ) {
    fail(`${path} must be a canonical ISO-8601 timestamp`);
  }
}

function isoTimestamp(value: Date | string) {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) {
    throw new TypeError("issuedAt must be a valid timestamp");
  }
  return date.toISOString();
}

function fail(message: string): never {
  throw new TypeError(message);
}

function validationMessages(error: unknown) {
  return error instanceof Error ? [error.message] : [String(error)];
}
