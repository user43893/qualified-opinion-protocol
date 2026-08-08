import { canonicalJsonSha256, isBase64Url } from "./encoding";
import {
  type DetachedSignature,
  ELIGIBILITY_DECISION_SCHEMA_V3,
  type EligibilityDecisionV3,
  MERKLE_TREE_HEAD_SCHEMA_V3,
  type MerkleTreeHeadV3,
  ROOT_KEY_DELEGATION_SCHEMA_V3,
  type RootKeyDelegationV3,
  type SignedPayload,
  VOTE_ACCEPTANCE_SCHEMA_V3,
  VOTE_ADJUDICATION_SCHEMA_V3,
  type VoteAcceptanceStatusV3,
  type VoteAcceptanceV3,
  type VoteAdjudicationV3,
  type WebAuthnAssertionProof,
  type WebAuthnSignedPayload,
} from "./types";
import {
  assertEligibilityDecisionV3,
  assertMerkleTreeHeadV3,
  assertRootKeyDelegationV3,
  assertVoteAcceptanceV3,
  assertVoteAdjudicationV3,
} from "./validate";

type TimestampInput = Date | string;

export function buildEligibilityDecisionV3(input: {
  decisionId: string;
  assertionSha256: string;
  publicVoterId: string;
  sequence: number;
  status: EligibilityDecisionV3["status"];
  reason?: string | null;
  previousDecisionSha256?: string | null;
  effectiveAt: TimestampInput;
  issuerKeyId: string;
}): EligibilityDecisionV3 {
  const payload: EligibilityDecisionV3 = {
    schema: ELIGIBILITY_DECISION_SCHEMA_V3,
    decisionId: requiredString(input.decisionId, "decisionId"),
    assertionSha256: input.assertionSha256,
    publicVoterId: requiredString(input.publicVoterId, "publicVoterId"),
    sequence: input.sequence,
    status: input.status,
    reason: input.reason?.trim() || null,
    previousDecisionSha256: input.previousDecisionSha256 ?? null,
    effectiveAt: isoTimestamp(input.effectiveAt, "effectiveAt"),
    issuerKeyId: requiredString(input.issuerKeyId, "issuerKeyId"),
  };
  assertEligibilityDecisionV3(payload);
  return payload;
}

const delegationActionOrder = ["vote:cast", "vote:replace", "vote:withdraw"] as const;

export function buildRootKeyDelegationV3(input: {
  delegationId: string;
  publicVoterId: string;
  rootCredentialId: string;
  delegatedPublicKeySpki: string;
  audience: string;
  actions?: RootKeyDelegationV3["scope"]["actions"];
  questionIds?: string[] | null;
  nonce: string;
  issuedAt: TimestampInput;
  expiresAt: TimestampInput;
}): RootKeyDelegationV3 {
  const requestedActions = input.actions ?? [...delegationActionOrder];
  const actions = delegationActionOrder.filter((action) =>
    requestedActions.includes(action),
  );
  const questionIds = input.questionIds
    ? [
        ...new Set(input.questionIds.map((id) => requiredString(id, "questionId"))),
      ].sort()
    : null;
  const payload: RootKeyDelegationV3 = {
    schema: ROOT_KEY_DELEGATION_SCHEMA_V3,
    delegationId: requiredString(input.delegationId, "delegationId"),
    publicVoterId: requiredString(input.publicVoterId, "publicVoterId"),
    rootCredentialId: requiredString(input.rootCredentialId, "rootCredentialId"),
    delegatedKey: {
      algorithm: "ES256",
      publicKeySpki: input.delegatedPublicKeySpki,
    },
    scope: {
      audience: requiredString(input.audience, "scope.audience"),
      actions,
      questionIds,
    },
    nonce: input.nonce,
    issuedAt: isoTimestamp(input.issuedAt, "issuedAt"),
    expiresAt: isoTimestamp(input.expiresAt, "expiresAt"),
  };
  assertRootKeyDelegationV3(payload);
  return payload;
}

export function buildVoteAcceptanceV3(input: {
  receiptId: string;
  voteEventSha256: string;
  status: VoteAcceptanceStatusV3;
  logId: string;
  receivedAt: TimestampInput;
  issuerKeyId: string;
}): VoteAcceptanceV3 {
  const payload: VoteAcceptanceV3 = {
    schema: VOTE_ACCEPTANCE_SCHEMA_V3,
    receiptId: requiredString(input.receiptId, "receiptId"),
    voteEventSha256: input.voteEventSha256,
    status: input.status,
    logId: requiredString(input.logId, "logId"),
    receivedAt: isoTimestamp(input.receivedAt, "receivedAt"),
    issuerKeyId: requiredString(input.issuerKeyId, "issuerKeyId"),
  };
  assertVoteAcceptanceV3(payload);
  return payload;
}

export function buildVoteAdjudicationV3(input: {
  receiptId: string;
  voteEventSha256: string;
  sequence: number;
  status: VoteAdjudicationV3["status"];
  reasonCode: VoteAdjudicationV3["reasonCode"];
  previousReceiptSha256: string;
  logId: string;
  receivedAt: TimestampInput;
  issuerKeyId: string;
}): VoteAdjudicationV3 {
  const payload: VoteAdjudicationV3 = {
    schema: VOTE_ADJUDICATION_SCHEMA_V3,
    receiptId: requiredString(input.receiptId, "receiptId"),
    voteEventSha256: input.voteEventSha256,
    sequence: input.sequence,
    status: input.status,
    reasonCode: input.reasonCode,
    eligibilityAssertionSha256: null,
    eligibilityDecisionSha256: null,
    previousReceiptSha256: input.previousReceiptSha256,
    logId: requiredString(input.logId, "logId"),
    receivedAt: isoTimestamp(input.receivedAt, "receivedAt"),
    issuerKeyId: requiredString(input.issuerKeyId, "issuerKeyId"),
  };
  assertVoteAdjudicationV3(payload);
  return payload;
}

export function buildMerkleTreeHeadV3(input: {
  logId: string;
  treeSize: number;
  rootHash: string;
  previousTreeHeadSha256?: string | null;
  issuedAt: TimestampInput;
  issuerKeyId: string;
}): MerkleTreeHeadV3 {
  const payload: MerkleTreeHeadV3 = {
    schema: MERKLE_TREE_HEAD_SCHEMA_V3,
    logId: requiredString(input.logId, "logId"),
    treeSize: input.treeSize,
    rootHash: input.rootHash,
    previousTreeHeadSha256: input.previousTreeHeadSha256 ?? null,
    issuedAt: isoTimestamp(input.issuedAt, "issuedAt"),
    issuerKeyId: requiredString(input.issuerKeyId, "issuerKeyId"),
  };
  assertMerkleTreeHeadV3(payload);
  return payload;
}

export async function attachDetachedSignature<T>(
  payload: T,
  signature: DetachedSignature,
): Promise<SignedPayload<T>> {
  if (!isBase64Url(signature.value) || signature.value.length === 0) {
    throw new TypeError("signature.value must be unpadded base64url");
  }
  return {
    payload,
    payloadSha256: await canonicalJsonSha256(payload),
    signature: {
      algorithm: signature.algorithm,
      keyId: requiredString(signature.keyId, "signature.keyId"),
      value: signature.value,
    },
  };
}

export async function attachWebAuthnSignature<T>(
  payload: T,
  webauthn: WebAuthnAssertionProof,
): Promise<WebAuthnSignedPayload<T>> {
  return {
    payload,
    payloadSha256: await canonicalJsonSha256(payload),
    webauthn: { ...webauthn },
  };
}

export function isoTimestamp(value: TimestampInput, field = "timestamp"): string {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) {
    throw new TypeError(`${field} must be a valid timestamp`);
  }
  return date.toISOString();
}

function requiredString(value: string, field: string): string {
  const normalized = value.trim();
  if (!normalized) {
    throw new TypeError(`${field} must not be empty`);
  }
  return normalized;
}
