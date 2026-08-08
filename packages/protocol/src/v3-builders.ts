import { isoTimestamp } from "./builders";
import { canonicalizeJson } from "./canonical";
import {
  base64UrlDecode,
  base64UrlEncode,
  canonicalJsonSha256,
  sha256Base64Url,
} from "./encoding";
import {
  ACTIVE_ELIGIBILITY_DIRECTORY_SCHEMA_V3,
  type ActiveEligibilityDirectoryEntryV3,
  type ActiveEligibilityDirectoryV3,
  BALLOT_MANIFEST_SCHEMA_V3,
  type BallotChoiceMeaningV3,
  type BallotChoicePresentationV3,
  type BallotManifestV3,
  type PolicyReferenceV3,
  type ProtocolBindingV3,
  QUESTION_VOTING_ATTESTATION_PURPOSE_V3,
  QUESTION_VOTING_AUTHORIZATION_SCHEMA_V3,
  QUESTION_VOTING_KEY_PURPOSE_V3,
  type QualificationSubjectV3,
  type QuestionVotingAuthorizationPayloadV3,
  type QuestionVotingAuthorizationV3,
  REGISTRY_EVIDENCE_SCHEMA_V3,
  type RegistryEvidenceV3,
  VOTE_EVENT_SCHEMA_V3,
  type VoteEventTypeV3,
  type VoteEventV3,
  type VotePublicationModeV3,
} from "./v3-types";
import {
  assertBallotManifestV3,
  assertProtocolBindingV3,
  assertQuestionVotingAuthorizationPayloadV3,
  assertVoteEventV3,
  verifyQuestionVotingAuthorizationPayloadV3Integrity,
  verifyQuestionVotingAuthorizationV3Integrity,
} from "./v3-validate";

type TimestampInput = Date | string;

export function buildProtocolBindingV3(input: {
  instanceId: string;
  instanceProfileSha256: string;
  eligibilityPolicy: PolicyReferenceV3;
  tallyPolicy: PolicyReferenceV3;
  trustPolicy: PolicyReferenceV3;
  audience: string;
  origin: string;
}): ProtocolBindingV3 {
  const binding: ProtocolBindingV3 = {
    instance: {
      id: requiredString(input.instanceId, "instanceId"),
      profileSha256: input.instanceProfileSha256,
    },
    eligibilityPolicy: policyReference(input.eligibilityPolicy, "eligibilityPolicy"),
    tallyPolicy: policyReference(input.tallyPolicy, "tallyPolicy"),
    trustPolicy: policyReference(input.trustPolicy, "trustPolicy"),
    audience: requiredString(input.audience, "audience"),
    origin: normalizeOrigin(input.origin),
  };
  assertProtocolBindingV3(binding);
  return binding;
}

export function buildRegistryEvidenceV3(input: {
  reviewId: string;
  reviewerAuthority: string;
  subject: QualificationSubjectV3;
  recordUrl: string;
  checkedFullName: string;
  checkedEmail: string;
  checkedAt: TimestampInput;
}): RegistryEvidenceV3 {
  return {
    schema: REGISTRY_EVIDENCE_SCHEMA_V3,
    reviewId: requiredString(input.reviewId, "reviewId"),
    reviewerAuthority: requiredString(input.reviewerAuthority, "reviewerAuthority"),
    subject: qualificationSubject(input.subject),
    recordUrl: requiredString(input.recordUrl, "recordUrl"),
    checkedFullName: requiredString(input.checkedFullName, "checkedFullName"),
    checkedEmail: requiredString(input.checkedEmail, "checkedEmail"),
    checkedAt: isoTimestamp(input.checkedAt, "checkedAt"),
  };
}

export function buildActiveEligibilityDirectoryV3(input: {
  entries: ActiveEligibilityDirectoryEntryV3[];
}): ActiveEligibilityDirectoryV3 {
  const entries = input.entries
    .map((entry) => ({
      publicVoterId: requiredString(entry.publicVoterId, "entries.publicVoterId"),
      identityProofSha256: sha256Digest(
        entry.identityProofSha256,
        "entries.identityProofSha256",
      ),
      eligibilityAssertionSha256: sha256Digest(
        entry.eligibilityAssertionSha256,
        "entries.eligibilityAssertionSha256",
      ),
      eligibilityDecisionSha256: sha256Digest(
        entry.eligibilityDecisionSha256,
        "entries.eligibilityDecisionSha256",
      ),
    }))
    .sort((left, right) => left.publicVoterId.localeCompare(right.publicVoterId));
  if (
    entries.some(
      (entry, index) =>
        index > 0 && entry.publicVoterId === entries[index - 1]?.publicVoterId,
    )
  ) {
    throw new TypeError("entries must contain unique publicVoterId values");
  }
  return {
    schema: ACTIVE_ELIGIBILITY_DIRECTORY_SCHEMA_V3,
    entries,
  };
}

export function buildBallotManifestV3(input: {
  manifestId: string;
  ballotId: string;
  questionId: string;
  nullifierKeyEpoch: number;
  revision: number;
  binding: ProtocolBindingV3;
  meaningChoices: BallotChoiceMeaningV3[];
  locale: string;
  questionText: string;
  plainLanguageText?: string | null;
  presentationChoices: BallotChoicePresentationV3[];
  publishedAt: TimestampInput;
  issuerKeyId: string;
}): BallotManifestV3 {
  const meaningChoices = input.meaningChoices
    .map((choice) => ({
      id: requiredString(choice.id, "meaningChoices.id"),
      slug: requiredString(choice.slug, "meaningChoices.slug"),
      semanticCode: choice.semanticCode?.trim() || null,
      displayOrder: choice.displayOrder,
      isCounted: choice.isCounted,
    }))
    .sort(
      (left, right) =>
        left.displayOrder - right.displayOrder || left.id.localeCompare(right.id),
    );
  const presentationById = new Map(
    input.presentationChoices.map((choice) => [choice.id, choice]),
  );
  const presentationChoices = meaningChoices.map((meaning) => {
    const presentation = presentationById.get(meaning.id);
    if (!presentation) {
      throw new TypeError(
        `presentationChoices is missing choice ${JSON.stringify(meaning.id)}`,
      );
    }
    return {
      id: meaning.id,
      label: requiredString(presentation.label, "presentationChoices.label"),
      description: presentation.description.trim(),
    };
  });
  if (presentationById.size !== meaningChoices.length) {
    throw new TypeError(
      "presentationChoices must contain exactly the meaning choice IDs",
    );
  }
  const payload: BallotManifestV3 = {
    schema: BALLOT_MANIFEST_SCHEMA_V3,
    manifestId: requiredString(input.manifestId, "manifestId"),
    ballotId: requiredString(input.ballotId, "ballotId"),
    questionId: requiredString(input.questionId, "questionId"),
    nullifierKeyEpoch: input.nullifierKeyEpoch,
    revision: input.revision,
    binding: cloneBinding(input.binding),
    meaning: { choices: meaningChoices },
    presentation: {
      locale: requiredString(input.locale, "locale"),
      questionText: requiredString(input.questionText, "questionText"),
      plainLanguageText: input.plainLanguageText?.trim() || null,
      choices: presentationChoices,
    },
    publishedAt: isoTimestamp(input.publishedAt, "publishedAt"),
    issuer: {
      algorithm: "Ed25519",
      keyId: requiredString(input.issuerKeyId, "issuerKeyId"),
      purpose: "receipt",
    },
  };
  assertBallotManifestV3(payload);
  return payload;
}

export async function buildQuestionVotingAuthorizationPayloadV3(input: {
  binding: ProtocolBindingV3;
  questionId: string;
  questionNullifier: string;
  nullifierKeyEpoch: number;
  questionKeyPublicKeySpki: string;
  eligibilityClaim: string;
  registryCheckpointId: string;
  registryCheckpointSha256: string;
  registryCheckpointWitnessCanonicalEnvelope: string;
  registryCheckpointWitnessEnvelopeSha256: string;
  issuedAt: TimestampInput;
  expiresAt: TimestampInput;
  issuerAttestationAudience: string;
}): Promise<QuestionVotingAuthorizationPayloadV3> {
  const publicKeySpki = requiredString(
    input.questionKeyPublicKeySpki,
    "questionKeyPublicKeySpki",
  );
  const publicKeySpkiSha256 = await sha256Base64Url(base64UrlDecode(publicKeySpki));
  const payload: QuestionVotingAuthorizationPayloadV3 = {
    schema: QUESTION_VOTING_AUTHORIZATION_SCHEMA_V3,
    binding: cloneBinding(input.binding),
    questionId: requiredString(input.questionId, "questionId"),
    questionNullifier: input.questionNullifier,
    nullifierKeyEpoch: input.nullifierKeyEpoch,
    questionKey: {
      algorithm: "ES256",
      keyId: publicKeySpkiSha256,
      publicKeySpki,
      publicKeySpkiSha256,
      purpose: QUESTION_VOTING_KEY_PURPOSE_V3,
    },
    eligibility: {
      claim: requiredString(input.eligibilityClaim, "eligibilityClaim"),
      policy: structuredClone(input.binding.eligibilityPolicy),
    },
    registryCheckpoint: {
      id: requiredString(input.registryCheckpointId, "registryCheckpointId"),
      sha256: input.registryCheckpointSha256,
      witness: {
        canonicalEnvelope: requiredString(
          input.registryCheckpointWitnessCanonicalEnvelope,
          "registryCheckpointWitnessCanonicalEnvelope",
        ),
        envelopeSha256: input.registryCheckpointWitnessEnvelopeSha256,
      },
    },
    issuedAt: isoTimestamp(input.issuedAt, "issuedAt"),
    expiresAt: isoTimestamp(input.expiresAt, "expiresAt"),
    issuerAttestation: {
      audience: requiredString(
        input.issuerAttestationAudience,
        "issuerAttestationAudience",
      ),
      purpose: QUESTION_VOTING_ATTESTATION_PURPOSE_V3,
    },
  };
  assertQuestionVotingAuthorizationPayloadV3(payload);
  const integrity = await verifyQuestionVotingAuthorizationPayloadV3Integrity(payload);
  if (!integrity.ok) {
    throw new TypeError(
      `Invalid qualified-opinion V3 authorization payload:\n${integrity.errors
        .map((error) => `- ${error}`)
        .join("\n")}`,
    );
  }
  return payload;
}

/**
 * Attaches the raw attestation token after the issuer requested it with
 * canonicalJsonSha256(payload) as the Confidential Space nonce.
 */
export async function buildQuestionVotingAuthorizationV3(input: {
  payload: QuestionVotingAuthorizationPayloadV3;
  attestationToken: string;
}): Promise<QuestionVotingAuthorizationV3> {
  const payload = structuredClone(input.payload);
  assertQuestionVotingAuthorizationPayloadV3(payload);
  const authorization: QuestionVotingAuthorizationV3 = {
    payload,
    payloadSha256: await canonicalJsonSha256(payload),
    attestationToken: requiredString(input.attestationToken, "attestationToken"),
  };
  const integrity = await verifyQuestionVotingAuthorizationV3Integrity(authorization);
  if (!integrity.ok) {
    throw new TypeError(
      `Invalid qualified-opinion V3 authorization:\n${integrity.errors
        .map((error) => `- ${error}`)
        .join("\n")}`,
    );
  }
  return authorization;
}

export function buildVoteEventV3(input: {
  eventId: string;
  eventType: VoteEventTypeV3;
  binding: ProtocolBindingV3;
  questionNullifier: string;
  authorizationSha256: string;
  publicationMode: VotePublicationModeV3;
  ballotManifestSha256: string;
  ballotId: string;
  questionId: string;
  choiceId?: string | null;
  sequence: number;
  previousEventSha256?: string | null;
  challenge: string;
  issuedAt: TimestampInput;
  questionKeyId: string;
}): VoteEventV3 {
  const event: VoteEventV3 = {
    schema: VOTE_EVENT_SCHEMA_V3,
    eventId: requiredString(input.eventId, "eventId"),
    eventType: input.eventType,
    binding: cloneBinding(input.binding),
    questionNullifier: input.questionNullifier,
    authorizationSha256: input.authorizationSha256,
    publicationMode: input.publicationMode,
    ballotManifestSha256: input.ballotManifestSha256,
    ballotId: requiredString(input.ballotId, "ballotId"),
    questionId: requiredString(input.questionId, "questionId"),
    choiceId:
      input.eventType === "withdraw"
        ? null
        : requiredString(input.choiceId ?? "", "choiceId"),
    sequence: input.sequence,
    previousEventSha256: input.previousEventSha256 ?? null,
    challenge: input.challenge,
    issuedAt: isoTimestamp(input.issuedAt, "issuedAt"),
    questionKeyId: input.questionKeyId,
  };
  assertVoteEventV3(event);
  return event;
}

function cloneBinding(binding: ProtocolBindingV3): ProtocolBindingV3 {
  assertProtocolBindingV3(binding);
  return structuredClone(binding);
}

/** Byte-for-byte comparison for trust-critical contexts. */
export function protocolBindingsEqualV3(
  left: ProtocolBindingV3,
  right: ProtocolBindingV3,
) {
  return canonicalizeJson(left) === canonicalizeJson(right);
}

function policyReference(value: PolicyReferenceV3, field: string) {
  return {
    id: requiredString(value.id, `${field}.id`),
    sha256: value.sha256,
  };
}

function qualificationSubject(value: QualificationSubjectV3): QualificationSubjectV3 {
  return {
    scheme: requiredString(value.scheme, "subject.scheme"),
    issuer: requiredString(value.issuer, "subject.issuer"),
    key: requiredString(value.key, "subject.key"),
  };
}

function normalizeOrigin(value: string) {
  const normalized = requiredString(value, "origin");
  const url = new URL(normalized);
  if (
    (url.protocol !== "https:" && url.protocol !== "http:") ||
    url.origin !== normalized
  ) {
    throw new TypeError("origin must be an exact HTTP(S) origin");
  }
  return normalized;
}

function requiredString(value: string, field: string) {
  const normalized = value.trim();
  if (!normalized) throw new TypeError(`${field} must not be empty`);
  return normalized;
}

function sha256Digest(value: string, field: string) {
  const normalized = requiredString(value, field);
  if (!/^[A-Za-z0-9_-]{43}$/.test(normalized)) {
    throw new TypeError(`${field} must be a base64url SHA-256 digest`);
  }
  const bytes = base64UrlDecode(normalized);
  if (bytes.byteLength !== 32 || base64UrlEncode(bytes) !== normalized) {
    throw new TypeError(`${field} must be a base64url SHA-256 digest`);
  }
  return normalized;
}
