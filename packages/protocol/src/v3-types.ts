export const BALLOT_MANIFEST_SCHEMA_V3 =
  "qualified-opinion.ballot-manifest.v3" as const;
export const REGISTRY_EVIDENCE_SCHEMA_V3 =
  "qualified-opinion.registry-evidence.v3" as const;
export const ACTIVE_ELIGIBILITY_DIRECTORY_SCHEMA_V3 =
  "qualified-opinion.active-eligibility-directory.v3" as const;
export const QUESTION_VOTING_AUTHORIZATION_SCHEMA_V3 =
  "qualified-opinion.question-voting-authorization.v3" as const;
export const VOTE_EVENT_SCHEMA_V3 = "qualified-opinion.vote-event.v3" as const;

export const QUESTION_VOTING_KEY_PURPOSE_V3 = "question-vote" as const;
export const QUESTION_VOTING_ATTESTATION_PURPOSE_V3 =
  "question-voting-authorization" as const;

export type PolicyReferenceV3 = {
  id: string;
  sha256: string;
};

/**
 * Everything that can change the meaning or trust boundary of a vote. This is
 * embedded in both the issuer-signed ballot and voter-signed event so an
 * artifact cannot be replayed under another deployment, origin, or policy.
 */
export type ProtocolBindingV3 = {
  instance: {
    id: string;
    profileSha256: string;
  };
  eligibilityPolicy: PolicyReferenceV3;
  tallyPolicy: PolicyReferenceV3;
  trustPolicy: PolicyReferenceV3;
  audience: string;
  origin: string;
};

export type QualificationSubjectV3 = {
  scheme: string;
  issuer: string;
  key: string;
};

export type RegistryEvidenceV3 = {
  schema: typeof REGISTRY_EVIDENCE_SCHEMA_V3;
  reviewId: string;
  reviewerAuthority: string;
  subject: QualificationSubjectV3;
  recordUrl: string;
  checkedFullName: string;
  checkedEmail: string;
  checkedAt: string;
};

export type ActiveEligibilityDirectoryEntryV3 = {
  publicVoterId: string;
  identityProofSha256: string;
  eligibilityAssertionSha256: string;
  eligibilityDecisionSha256: string;
};

export type ActiveEligibilityDirectoryV3 = {
  schema: typeof ACTIVE_ELIGIBILITY_DIRECTORY_SCHEMA_V3;
  entries: ActiveEligibilityDirectoryEntryV3[];
};

export type BallotChoiceMeaningV3 = {
  id: string;
  slug: string;
  semanticCode: string | null;
  displayOrder: number;
  isCounted: boolean;
};

export type BallotChoicePresentationV3 = {
  id: string;
  label: string;
  description: string;
};

/**
 * The stable ballot meaning is deliberately separated from localized display
 * text. Both are covered by the issuer signature and by the event's digest
 * link to this complete artifact.
 */
export type BallotManifestV3 = {
  schema: typeof BALLOT_MANIFEST_SCHEMA_V3;
  manifestId: string;
  ballotId: string;
  questionId: string;
  /**
   * Immutable for the lifetime of a question. Rotating the deployment's
   * current nullifier key only affects questions first published afterwards,
   * so replacement and withdrawal keep the same question-scoped nullifier.
   */
  nullifierKeyEpoch: number;
  revision: number;
  binding: ProtocolBindingV3;
  meaning: {
    choices: BallotChoiceMeaningV3[];
  };
  presentation: {
    locale: string;
    questionText: string;
    plainLanguageText: string | null;
    choices: BallotChoicePresentationV3[];
  };
  publishedAt: string;
  issuer: {
    algorithm: "Ed25519";
    keyId: string;
    purpose: "receipt";
  };
};

/**
 * Public, question-scoped authorization emitted by the attested issuer.
 *
 * This payload intentionally contains no member-specific registry identifier,
 * identity or eligibility proof hash, root credential, qualification subject,
 * name, email address, or reusable delegation.
 */
export type QuestionVotingAuthorizationPayloadV3 = {
  schema: typeof QUESTION_VOTING_AUTHORIZATION_SCHEMA_V3;
  binding: ProtocolBindingV3;
  questionId: string;
  questionNullifier: string;
  nullifierKeyEpoch: number;
  questionKey: {
    algorithm: "ES256";
    keyId: string;
    publicKeySpki: string;
    publicKeySpkiSha256: string;
    purpose: typeof QUESTION_VOTING_KEY_PURPOSE_V3;
  };
  eligibility: {
    claim: string;
    policy: PolicyReferenceV3;
  };
  registryCheckpoint: {
    id: string;
    sha256: string;
    witness: {
      canonicalEnvelope: string;
      envelopeSha256: string;
    };
  };
  issuedAt: string;
  expiresAt: string;
  issuerAttestation: {
    audience: string;
    purpose: typeof QUESTION_VOTING_ATTESTATION_PURPOSE_V3;
  };
};

/**
 * Google Confidential Space returns the attestation token after receiving the
 * canonical payload hash as its nonce. Token signature and claims are verified
 * by the consuming verifier; this envelope binds the raw token to that payload.
 */
export type QuestionVotingAuthorizationV3 = {
  payload: QuestionVotingAuthorizationPayloadV3;
  payloadSha256: string;
  attestationToken: string;
};

export type VoteEventTypeV3 = "cast" | "replace" | "withdraw";
export type VotePublicationModeV3 = "private" | "attributed";

/**
 * A voter-signed question event. Identity and reusable credential material are
 * absent by construction; authorizationSha256 refers to the authorization
 * envelope's payloadSha256.
 */
export type VoteEventV3 = {
  schema: typeof VOTE_EVENT_SCHEMA_V3;
  eventId: string;
  eventType: VoteEventTypeV3;
  binding: ProtocolBindingV3;
  questionNullifier: string;
  authorizationSha256: string;
  publicationMode: VotePublicationModeV3;
  ballotManifestSha256: string;
  ballotId: string;
  questionId: string;
  choiceId: string | null;
  sequence: number;
  previousEventSha256: string | null;
  challenge: string;
  issuedAt: string;
  questionKeyId: string;
};
