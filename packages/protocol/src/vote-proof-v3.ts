import { canonicalizeJson } from "./canonical";
import {
  base64UrlEncode,
  canonicalJsonSha256,
  isBase64Url,
  isSha256Base64Url,
} from "./encoding";
import { merkleLeafHash, verifyMerkleInclusionProof } from "./merkle";
import { questionVoteLogIdV3 } from "./question-vote-log-v3";
import type { SignedPayload, TransparencyInclusionV3, VoteAcceptanceV3 } from "./types";
import type {
  BallotManifestV3,
  QuestionVotingAuthorizationV3,
  VoteEventV3,
} from "./v3-types";
import {
  assertBallotManifestV3,
  assertQuestionVotingAuthorizationV3,
  assertVoteEventV3,
  verifyQuestionVotingAuthorizationV3Integrity,
  verifyVoteEventV3AuthorizationBinding,
} from "./v3-validate";
import {
  type ValidationResult,
  assertMerkleTreeHeadV3,
  assertVoteAcceptanceV3,
} from "./validate";

export const PUBLIC_VOTE_PROOF_BUNDLE_SCHEMA_V3 =
  "qualified-opinion.public-vote-proof-bundle.v3" as const;

/**
 * Immutable, question-only proof material for a V3 vote event.
 *
 * Deliberately absent: public/global voter identifiers, identity proof,
 * eligibility assertion, root credential/delegation, name, and email. Optional
 * attribution is mutable and therefore must be fetched separately.
 */
export type PublicVoteProofBundleV3 = {
  schema: typeof PUBLIC_VOTE_PROOF_BUNDLE_SCHEMA_V3;
  bundleId: string;
  questionAuthorization: QuestionVotingAuthorizationV3;
  questionManifest: SignedPayload<BallotManifestV3>;
  voteEvent: SignedPayload<VoteEventV3>;
  acceptance: SignedPayload<VoteAcceptanceV3>;
  voteEventTransparency: TransparencyInclusionV3;
  acceptanceTransparency: TransparencyInclusionV3;
};

export function buildPublicVoteProofBundleV3(input: {
  bundleId: string;
  questionAuthorization: QuestionVotingAuthorizationV3;
  questionManifest: SignedPayload<BallotManifestV3>;
  voteEvent: SignedPayload<VoteEventV3>;
  acceptance: SignedPayload<VoteAcceptanceV3>;
  voteEventTransparency: TransparencyInclusionV3;
  acceptanceTransparency: TransparencyInclusionV3;
}): PublicVoteProofBundleV3 {
  const bundle: PublicVoteProofBundleV3 = {
    schema: PUBLIC_VOTE_PROOF_BUNDLE_SCHEMA_V3,
    bundleId: input.bundleId,
    questionAuthorization: structuredClone(input.questionAuthorization),
    questionManifest: structuredClone(input.questionManifest),
    voteEvent: structuredClone(input.voteEvent),
    acceptance: structuredClone(input.acceptance),
    voteEventTransparency: structuredClone(input.voteEventTransparency),
    acceptanceTransparency: structuredClone(input.acceptanceTransparency),
  };
  assertPublicVoteProofBundleV3(bundle);
  return bundle;
}

export function validatePublicVoteProofBundleV3(
  value: unknown,
): ValidationResult<PublicVoteProofBundleV3> {
  try {
    assertPublicVoteProofBundleV3(value);
    return { ok: true, value };
  } catch (error) {
    return {
      ok: false,
      errors: [error instanceof Error ? error.message : String(error)],
    };
  }
}

export function assertPublicVoteProofBundleV3(
  value: unknown,
): asserts value is PublicVoteProofBundleV3 {
  const bundle = exactObject(value, "$", [
    "schema",
    "bundleId",
    "questionAuthorization",
    "questionManifest",
    "voteEvent",
    "acceptance",
    "voteEventTransparency",
    "acceptanceTransparency",
  ]);
  if (bundle.schema !== PUBLIC_VOTE_PROOF_BUNDLE_SCHEMA_V3) {
    throw new TypeError(
      `$.schema must equal ${JSON.stringify(PUBLIC_VOTE_PROOF_BUNDLE_SCHEMA_V3)}`,
    );
  }
  nonEmptyString(bundle.bundleId, "$.bundleId");
  assertQuestionVotingAuthorizationV3(bundle.questionAuthorization);
  assertSignedEnvelope(
    bundle.questionManifest,
    "$.questionManifest",
    "Ed25519",
    assertBallotManifestV3,
  );
  assertSignedEnvelope(bundle.voteEvent, "$.voteEvent", "ES256", assertVoteEventV3);
  assertSignedEnvelope(
    bundle.acceptance,
    "$.acceptance",
    "Ed25519",
    assertVoteAcceptanceV3,
  );
  assertTransparencyInclusion(bundle.voteEventTransparency, "$.voteEventTransparency");
  assertTransparencyInclusion(
    bundle.acceptanceTransparency,
    "$.acceptanceTransparency",
  );
}

/**
 * Verifies all locally checkable hashes, links, timestamps, and RFC 6962
 * inclusion proofs. Signature trust and Confidential Space token verification
 * require the deployment's independently anchored public policy.
 */
export async function verifyPublicVoteProofBundleV3Integrity(
  value: unknown,
): Promise<ValidationResult<PublicVoteProofBundleV3>> {
  const structural = validatePublicVoteProofBundleV3(value);
  if (!structural.ok) return structural;
  const bundle = structural.value;
  const errors: string[] = [];
  const authorizationIntegrity = await verifyQuestionVotingAuthorizationV3Integrity(
    bundle.questionAuthorization,
  );
  if (!authorizationIntegrity.ok) {
    errors.push(
      ...authorizationIntegrity.errors.map(
        (error) => `questionAuthorization: ${error}`,
      ),
    );
  }
  const eventBinding = await verifyVoteEventV3AuthorizationBinding({
    event: bundle.voteEvent.payload,
    authorization: bundle.questionAuthorization,
  });
  if (!eventBinding.ok) {
    errors.push(
      ...eventBinding.errors.map(
        (error) => `voteEvent authorization binding: ${error}`,
      ),
    );
  }

  const manifestHash = await canonicalJsonSha256(bundle.questionManifest.payload);
  const eventHash = await canonicalJsonSha256(bundle.voteEvent.payload);
  const acceptanceHash = await canonicalJsonSha256(bundle.acceptance.payload);
  equal(
    bundle.bundleId,
    bundle.voteEvent.payload.eventId,
    "bundleId must equal voteEvent.payload.eventId",
    errors,
  );
  equal(
    manifestHash,
    bundle.questionManifest.payloadSha256,
    "questionManifest.payloadSha256 must match its canonical payload",
    errors,
  );
  equal(
    eventHash,
    bundle.voteEvent.payloadSha256,
    "voteEvent.payloadSha256 must match its canonical payload",
    errors,
  );
  equal(
    acceptanceHash,
    bundle.acceptance.payloadSha256,
    "acceptance.payloadSha256 must match its canonical payload",
    errors,
  );
  equal(
    bundle.voteEvent.payload.ballotManifestSha256,
    bundle.questionManifest.payloadSha256,
    "voteEvent ballotManifestSha256 must match questionManifest",
    errors,
  );
  equal(
    bundle.voteEvent.payload.ballotId,
    bundle.questionManifest.payload.ballotId,
    "voteEvent ballotId must match questionManifest",
    errors,
  );
  equal(
    bundle.voteEvent.payload.questionId,
    bundle.questionManifest.payload.questionId,
    "voteEvent questionId must match questionManifest",
    errors,
  );
  if (
    bundle.questionAuthorization.payload.nullifierKeyEpoch !==
    bundle.questionManifest.payload.nullifierKeyEpoch
  ) {
    errors.push("questionAuthorization nullifierKeyEpoch must match questionManifest");
  }
  equal(
    canonicalizeJson(bundle.voteEvent.payload.binding),
    canonicalizeJson(bundle.questionManifest.payload.binding),
    "voteEvent binding must match questionManifest",
    errors,
  );
  equal(
    bundle.questionManifest.payload.issuer.keyId,
    bundle.questionManifest.signature.keyId,
    "questionManifest issuer key must match its signature key",
    errors,
  );
  equal(
    bundle.voteEvent.payload.questionKeyId,
    bundle.voteEvent.signature.keyId,
    "voteEvent question key must match its signature key",
    errors,
  );
  equal(
    bundle.acceptance.payload.issuerKeyId,
    bundle.acceptance.signature.keyId,
    "acceptance issuer key must match its signature key",
    errors,
  );
  equal(
    bundle.acceptance.payload.voteEventSha256,
    bundle.voteEvent.payloadSha256,
    "acceptance must refer to the vote event",
    errors,
  );
  if (bundle.acceptance.payload.status !== "counted") {
    errors.push("V3 acceptance status must be counted");
  }
  const expectedQuestionLogId = await questionVoteLogIdV3({
    instanceId: bundle.questionManifest.payload.binding.instance.id,
    questionId: bundle.questionManifest.payload.questionId,
  });
  equal(
    bundle.acceptance.payload.logId,
    expectedQuestionLogId,
    "acceptance must bind the deterministic question log",
    errors,
  );
  if (
    bundle.voteEvent.payload.choiceId !== null &&
    !bundle.questionManifest.payload.meaning.choices.some(
      (choice) => choice.id === bundle.voteEvent.payload.choiceId && choice.isCounted,
    )
  ) {
    errors.push("voteEvent choiceId must identify a counted manifest choice");
  }
  timestampNotBefore(
    bundle.voteEvent.payload.issuedAt,
    bundle.questionManifest.payload.publishedAt,
    "voteEvent must not predate the question manifest",
    errors,
  );
  timestampNotBefore(
    bundle.acceptance.payload.receivedAt,
    bundle.voteEvent.payload.issuedAt,
    "acceptance must not predate the vote event",
    errors,
  );

  await verifyTransparencyLink(
    {
      artifactTime: bundle.voteEvent.payload.issuedAt,
      entryId: bundle.voteEvent.payload.eventId,
      entryPayloadHash: bundle.voteEvent.payloadSha256,
      entryType: "vote_event",
      inclusion: bundle.voteEventTransparency,
      logId: bundle.acceptance.payload.logId,
      path: "voteEventTransparency",
    },
    errors,
  );
  await verifyTransparencyLink(
    {
      artifactTime: bundle.acceptance.payload.receivedAt,
      entryId: bundle.acceptance.payload.receiptId,
      entryPayloadHash: bundle.acceptance.payloadSha256,
      entryType: "vote_adjudication",
      inclusion: bundle.acceptanceTransparency,
      logId: bundle.acceptance.payload.logId,
      path: "acceptanceTransparency",
    },
    errors,
  );

  return errors.length === 0 ? { ok: true, value: bundle } : { ok: false, errors };
}

async function verifyTransparencyLink(
  input: {
    artifactTime: string;
    entryId: string;
    entryPayloadHash: string;
    entryType: "vote_event" | "vote_adjudication";
    inclusion: TransparencyInclusionV3;
    logId: string;
    path: string;
  },
  errors: string[],
) {
  const headHash = await canonicalJsonSha256(input.inclusion.treeHead.payload);
  equal(
    headHash,
    input.inclusion.treeHead.payloadSha256,
    `${input.path} tree-head payload hash must match`,
    errors,
  );
  equal(
    input.inclusion.treeHead.payload.issuerKeyId,
    input.inclusion.treeHead.signature.keyId,
    `${input.path} tree-head issuer key must match its signature key`,
    errors,
  );
  equal(
    input.logId,
    input.inclusion.treeHead.payload.logId,
    `${input.path} logId must match the acceptance log`,
    errors,
  );
  timestampNotBefore(
    input.inclusion.treeHead.payload.issuedAt,
    input.artifactTime,
    `${input.path} tree head must not predate its artifact`,
    errors,
  );
  const leaf = canonicalizeJson({
    entryId: input.entryId,
    entryPayloadHash: input.entryPayloadHash,
    entryType: input.entryType,
  });
  const leafHash = base64UrlEncode(await merkleLeafHash(leaf));
  equal(
    leafHash,
    input.inclusion.leafHash,
    `${input.path} leafHash must match its entry`,
    errors,
  );
  if (
    !(await verifyMerkleInclusionProof({
      leaf,
      leafIndex: input.inclusion.leafIndex,
      treeSize: input.inclusion.treeHead.payload.treeSize,
      auditPath: input.inclusion.auditPath,
      expectedRootHash: input.inclusion.treeHead.payload.rootHash,
    }))
  ) {
    errors.push(`${input.path} RFC 6962 inclusion proof is invalid`);
  }
}

function assertSignedEnvelope(
  value: unknown,
  path: string,
  algorithm: "Ed25519" | "ES256",
  assertPayload: (payload: unknown) => void,
) {
  const envelope = exactObject(value, path, ["payload", "payloadSha256", "signature"]);
  assertPayload(envelope.payload);
  digest(envelope.payloadSha256, `${path}.payloadSha256`);
  const signature = exactObject(envelope.signature, `${path}.signature`, [
    "algorithm",
    "keyId",
    "value",
  ]);
  if (signature.algorithm !== algorithm) {
    throw new TypeError(
      `${path}.signature.algorithm must equal ${JSON.stringify(algorithm)}`,
    );
  }
  nonEmptyString(signature.keyId, `${path}.signature.keyId`);
  nonEmptyString(signature.value, `${path}.signature.value`);
  if (!isBase64Url(signature.value)) {
    throw new TypeError(`${path}.signature.value must be unpadded base64url`);
  }
}

function assertTransparencyInclusion(value: unknown, path: string) {
  const inclusion = exactObject(value, path, [
    "leafIndex",
    "leafHash",
    "auditPath",
    "treeHead",
  ]);
  if (
    !Number.isSafeInteger(inclusion.leafIndex) ||
    (inclusion.leafIndex as number) < 0
  ) {
    throw new TypeError(`${path}.leafIndex must be a nonnegative safe integer`);
  }
  digest(inclusion.leafHash, `${path}.leafHash`);
  if (!Array.isArray(inclusion.auditPath)) {
    throw new TypeError(`${path}.auditPath must be an array`);
  }
  for (const [index, hash] of inclusion.auditPath.entries()) {
    digest(hash, `${path}.auditPath[${index}]`);
  }
  assertSignedEnvelope(
    inclusion.treeHead,
    `${path}.treeHead`,
    "Ed25519",
    assertMerkleTreeHeadV3,
  );
}

function exactObject(
  value: unknown,
  path: string,
  keys: readonly string[],
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${path} must be an object`);
  }
  const object = value as Record<string, unknown>;
  const expected = new Set(keys);
  const extras = Object.keys(object).filter((key) => !expected.has(key));
  const missing = keys.filter((key) => !(key in object));
  if (extras.length > 0) {
    throw new TypeError(`${path}.${extras[0]} is not allowed`);
  }
  if (missing.length > 0) {
    throw new TypeError(`${path}.${missing[0]} is required`);
  }
  return object;
}

function nonEmptyString(value: unknown, path: string): asserts value is string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError(`${path} must be a non-empty string`);
  }
}

function digest(value: unknown, path: string): asserts value is string {
  if (!isSha256Base64Url(value)) {
    throw new TypeError(`${path} must be a SHA-256 base64url digest`);
  }
}

function equal(actual: string, expected: string, message: string, errors: string[]) {
  if (actual !== expected) errors.push(message);
}

function timestampNotBefore(
  value: string,
  lowerBound: string,
  message: string,
  errors: string[],
) {
  const timestamp = Date.parse(value);
  const lower = Date.parse(lowerBound);
  if (!Number.isFinite(timestamp) || !Number.isFinite(lower) || timestamp < lower) {
    errors.push(message);
  }
}
