import type { JsonValue } from "./canonical";

export const ELIGIBILITY_DECISION_SCHEMA_V3 =
  "qualified-opinion.eligibility-decision.v3" as const;
export const ROOT_KEY_DELEGATION_SCHEMA_V3 =
  "qualified-opinion.root-key-delegation.v3" as const;
export const VOTE_ACCEPTANCE_SCHEMA_V3 =
  "qualified-opinion.vote-acceptance.v3" as const;
export const VOTE_ADJUDICATION_SCHEMA_V3 =
  "qualified-opinion.vote-adjudication.v3" as const;
export const MERKLE_TREE_HEAD_SCHEMA_V3 =
  "qualified-opinion.transparency-tree-head.v3" as const;

export type ProofSignatureAlgorithm = "Ed25519" | "ES256";

export type DetachedSignature = {
  algorithm: ProofSignatureAlgorithm;
  keyId: string;
  value: string;
};

export type SignedPayload<T> = {
  payload: T;
  payloadSha256: string;
  signature: DetachedSignature;
};

export type WebAuthnAssertionProof = {
  algorithm: "ES256";
  credentialId: string;
  clientDataJson: string;
  authenticatorData: string;
  signature: string;
};

export type WebAuthnSignedPayload<T> = {
  payload: T;
  payloadSha256: string;
  webauthn: WebAuthnAssertionProof;
};

export type PublicIdentityProofV3 = {
  proofId: string;
  payload: JsonValue;
  payloadSha256: string;
  attestationToken: string;
};

/**
 * Append-only lifecycle decision for a current eligibility assertion.
 * Revocation prevents future authorization without rewriting accepted votes.
 */
export type EligibilityDecisionV3 = {
  schema: typeof ELIGIBILITY_DECISION_SCHEMA_V3;
  decisionId: string;
  assertionSha256: string;
  publicVoterId: string;
  sequence: number;
  status: "active" | "revoked";
  reason: string | null;
  previousDecisionSha256: string | null;
  effectiveAt: string;
  issuerKeyId: string;
};

/**
 * Private reusable-key authorization used only to request question-scoped
 * authorizations. It is never included in a public vote proof or tally.
 */
export type RootKeyDelegationV3 = {
  schema: typeof ROOT_KEY_DELEGATION_SCHEMA_V3;
  delegationId: string;
  publicVoterId: string;
  rootCredentialId: string;
  delegatedKey: {
    algorithm: "ES256";
    publicKeySpki: string;
  };
  scope: {
    audience: string;
    actions: Array<"vote:cast" | "vote:replace" | "vote:withdraw">;
    questionIds: string[] | null;
  };
  nonce: string;
  issuedAt: string;
  expiresAt: string;
};

export type VoteAcceptanceStatusV3 = "counted";

export type VoteAcceptanceV3 = {
  schema: typeof VOTE_ACCEPTANCE_SCHEMA_V3;
  receiptId: string;
  voteEventSha256: string;
  status: VoteAcceptanceStatusV3;
  logId: string;
  receivedAt: string;
  issuerKeyId: string;
};

/** A later, append-only decision about an immutable V3 vote event. */
export type VoteAdjudicationV3 = {
  schema: typeof VOTE_ADJUDICATION_SCHEMA_V3;
  receiptId: string;
  voteEventSha256: string;
  sequence: number;
  status: "counted" | "excluded" | "rejected";
  reasonCode:
    | "authorization_revoked"
    | "authorization_superseded"
    | "administrative_rejection";
  /**
   * Always null in V3. Keeping explicit nulls makes accidental publication of
   * identity-linked eligibility material fail structural validation.
   */
  eligibilityAssertionSha256: null;
  eligibilityDecisionSha256: null;
  previousReceiptSha256: string;
  logId: string;
  receivedAt: string;
  issuerKeyId: string;
};

export type VoteReceiptV3 = VoteAcceptanceV3 | VoteAdjudicationV3;

export type MerkleTreeHeadV3 = {
  schema: typeof MERKLE_TREE_HEAD_SCHEMA_V3;
  logId: string;
  treeSize: number;
  rootHash: string;
  previousTreeHeadSha256: string | null;
  issuedAt: string;
  issuerKeyId: string;
};

export type TransparencyInclusionV3 = {
  leafIndex: number;
  leafHash: string;
  auditPath: string[];
  treeHead: SignedPayload<MerkleTreeHeadV3>;
};
