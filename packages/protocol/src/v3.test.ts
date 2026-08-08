import { describe, expect, test } from "bun:test";
import { base64UrlEncode, canonicalJsonSha256, sha256Base64Url } from "./encoding";
import {
  buildActiveEligibilityDirectoryV3,
  buildProtocolBindingV3,
  buildQuestionVotingAuthorizationPayloadV3,
  buildQuestionVotingAuthorizationV3,
  buildVoteEventV3,
} from "./v3-builders";
import type {
  ProtocolBindingV3,
  QuestionVotingAuthorizationPayloadV3,
  QuestionVotingAuthorizationV3,
  VoteEventV3,
} from "./v3-types";
import { ACTIVE_ELIGIBILITY_DIRECTORY_SCHEMA_V3 } from "./v3-types";
import {
  expectedQuestionVotingAuthorizationAttestationNonceV3,
  validateQuestionVotingAuthorizationPayloadV3,
  validateQuestionVotingAuthorizationV3,
  validateVoteEventV3,
  verifyQuestionVotingAuthorizationV3Integrity,
  verifyVoteEventV3AuthorizationBinding,
} from "./v3-validate";

const questionId = "question-2026-07-24";
const ballotId = "ballot-2026-07-24";
const issuedAt = "2026-07-24T12:00:00.000Z";
const expiresAt = "2026-07-24T12:15:00.000Z";

function digest(byte: number) {
  return base64UrlEncode(new Uint8Array(32).fill(byte));
}

function binding(): ProtocolBindingV3 {
  return buildProtocolBindingV3({
    instanceId: "org.example.qualified-opinion",
    instanceProfileSha256: digest(1),
    eligibilityPolicy: {
      id: "law-graduate-active.v3",
      sha256: digest(2),
    },
    tallyPolicy: { id: "direct-vote.v3", sha256: digest(3) },
    trustPolicy: { id: "confidential-space.v3", sha256: digest(4) },
    audience: "https://vote.example.test",
    origin: "https://app.example.test",
  });
}

async function questionKeySpki() {
  const keyPair = (await globalThis.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  return base64UrlEncode(
    new Uint8Array(await globalThis.crypto.subtle.exportKey("spki", keyPair.publicKey)),
  );
}

async function authorizationFixture(): Promise<QuestionVotingAuthorizationV3> {
  const payload = await buildQuestionVotingAuthorizationPayloadV3({
    binding: binding(),
    questionId,
    questionNullifier: digest(5),
    nullifierKeyEpoch: 1,
    questionKeyPublicKeySpki: await questionKeySpki(),
    eligibilityClaim: "active-law-graduate",
    registryCheckpointId: "registry-checkpoint-42",
    registryCheckpointSha256: digest(6),
    registryCheckpointWitnessCanonicalEnvelope: "{}",
    registryCheckpointWitnessEnvelopeSha256: await sha256Base64Url("{}"),
    issuedAt,
    expiresAt,
    issuerAttestationAudience: "https://verifier.example.test/question-authorization",
  });
  return buildQuestionVotingAuthorizationV3({
    payload,
    attestationToken: "header.payload.signature",
  });
}

async function voteFixture(
  overrides: Partial<Parameters<typeof buildVoteEventV3>[0]> = {},
) {
  const authorization = await authorizationFixture();
  const event = buildVoteEventV3({
    eventId: "vote-event-1",
    eventType: "cast",
    binding: authorization.payload.binding,
    questionNullifier: authorization.payload.questionNullifier,
    authorizationSha256: authorization.payloadSha256,
    publicationMode: "private",
    ballotManifestSha256: digest(7),
    ballotId,
    questionId,
    choiceId: "agree",
    sequence: 1,
    previousEventSha256: null,
    challenge: base64UrlEncode(new Uint8Array(24).fill(8)),
    issuedAt: "2026-07-24T12:05:00.000Z",
    questionKeyId: authorization.payload.questionKey.keyId,
    ...overrides,
  });
  return { authorization, event };
}

function objectKeys(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap(objectKeys);
  if (!value || typeof value !== "object") return [];
  return Object.entries(value).flatMap(([key, child]) => [key, ...objectKeys(child)]);
}

describe("question voting authorization V3", () => {
  test("builds one canonical current eligibility directory across request order", async () => {
    const entries = [
      {
        publicVoterId: "voter-b",
        identityProofSha256: digest(11),
        eligibilityAssertionSha256: digest(12),
        eligibilityDecisionSha256: digest(13),
      },
      {
        publicVoterId: "voter-a",
        identityProofSha256: digest(21),
        eligibilityAssertionSha256: digest(22),
        eligibilityDecisionSha256: digest(23),
      },
    ];
    const directory = buildActiveEligibilityDirectoryV3({ entries });
    expect(directory.schema).toBe(ACTIVE_ELIGIBILITY_DIRECTORY_SCHEMA_V3);
    expect(directory.entries.map(({ publicVoterId }) => publicVoterId)).toEqual([
      "voter-a",
      "voter-b",
    ]);
    expect(await canonicalJsonSha256(directory)).toBe(
      await canonicalJsonSha256(
        buildActiveEligibilityDirectoryV3({
          entries: [...entries].reverse(),
        }),
      ),
    );
    const first = entries[0];
    if (!first) throw new Error("test requires one directory entry");
    expect(() =>
      buildActiveEligibilityDirectoryV3({
        entries: [first, first],
      }),
    ).toThrow("unique publicVoterId");
    expect(() =>
      buildActiveEligibilityDirectoryV3({
        entries: [{ ...first, identityProofSha256: "not-a-digest" }],
      }),
    ).toThrow("base64url SHA-256");
  });

  test("builds the minimal public payload and attestation envelope", async () => {
    const authorization = await authorizationFixture();

    expect(Object.keys(authorization).sort()).toEqual([
      "attestationToken",
      "payload",
      "payloadSha256",
    ]);
    expect(Object.keys(authorization.payload).sort()).toEqual([
      "binding",
      "eligibility",
      "expiresAt",
      "issuedAt",
      "issuerAttestation",
      "nullifierKeyEpoch",
      "questionId",
      "questionKey",
      "questionNullifier",
      "registryCheckpoint",
      "schema",
    ]);
    const authorizationKeys = objectKeys(authorization.payload);
    for (const forbidden of [
      "publicVoterId",
      "identityProof",
      "identityProofSha256",
      "eligibilityAssertionSha256",
      "rootCredentialId",
      "qualificationSubject",
      "checkedFullName",
      "checkedEmail",
      "delegationSha256",
    ]) {
      expect(authorizationKeys).not.toContain(forbidden);
    }
    expect(
      await expectedQuestionVotingAuthorizationAttestationNonceV3(
        authorization.payload,
      ),
    ).toBe(authorization.payloadSha256);
    expect(await verifyQuestionVotingAuthorizationV3Integrity(authorization)).toEqual({
      ok: true,
      value: authorization,
    });
  });

  test("derives a fresh question key ID from the decoded SPKI", async () => {
    const first = await authorizationFixture();
    const second = await authorizationFixture();

    expect(first.payload.questionKey.keyId).toBe(
      first.payload.questionKey.publicKeySpkiSha256,
    );
    expect(second.payload.questionKey.keyId).toBe(
      second.payload.questionKey.publicKeySpkiSha256,
    );
    expect(first.payload.questionKey.keyId).not.toBe(second.payload.questionKey.keyId);
  });

  test("rejects unknown member-linking fields at every exact boundary", async () => {
    const authorization = await authorizationFixture();
    const topLevel = structuredClone(authorization) as QuestionVotingAuthorizationV3 & {
      publicVoterId?: string;
    };
    topLevel.publicVoterId = "member-1";
    const topResult = validateQuestionVotingAuthorizationV3(topLevel);
    expect(topResult.ok).toBe(false);
    if (!topResult.ok) {
      expect(topResult.errors.join("\n")).toContain("$.publicVoterId is not allowed");
    }

    const payload = structuredClone(
      authorization.payload,
    ) as QuestionVotingAuthorizationPayloadV3 & {
      eligibilityAssertionSha256?: string;
    };
    payload.eligibilityAssertionSha256 = digest(10);
    const payloadResult = validateQuestionVotingAuthorizationPayloadV3(payload);
    expect(payloadResult.ok).toBe(false);
    if (!payloadResult.ok) {
      expect(payloadResult.errors.join("\n")).toContain(
        "$.eligibilityAssertionSha256 is not allowed",
      );
    }

    const nested = structuredClone(authorization);
    (
      nested.payload.questionKey as typeof nested.payload.questionKey & {
        rootCredentialId?: string;
      }
    ).rootCredentialId = "credential-1";
    const nestedResult = validateQuestionVotingAuthorizationV3(nested);
    expect(nestedResult.ok).toBe(false);
    if (!nestedResult.ok) {
      expect(nestedResult.errors.join("\n")).toContain(
        "$.payload.questionKey.rootCredentialId is not allowed",
      );
    }
  });

  test("rejects a policy detached from the protocol binding", async () => {
    const authorization = await authorizationFixture();
    const payload = structuredClone(authorization.payload);
    payload.eligibility.policy.sha256 = digest(11);
    const result = validateQuestionVotingAuthorizationPayloadV3(payload);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors.join("\n")).toContain(
        "$.eligibility.policy must equal binding.eligibilityPolicy",
      );
    }
  });

  test("detects payload tampering and a falsely labelled ES256 key", async () => {
    const authorization = await authorizationFixture();
    const tampered = structuredClone(authorization);
    tampered.payload.questionId = "question-other";
    const tamperedResult = await verifyQuestionVotingAuthorizationV3Integrity(tampered);
    expect(tamperedResult.ok).toBe(false);
    if (!tamperedResult.ok) {
      expect(tamperedResult.errors.join("\n")).toContain("$.payloadSha256 must equal");
    }

    const falseKey = structuredClone(authorization);
    const falseSpkiBytes = new Uint8Array(65).fill(12);
    const falseSpkiSha256 = await sha256Base64Url(falseSpkiBytes);
    falseKey.payload.questionKey.publicKeySpki = base64UrlEncode(falseSpkiBytes);
    falseKey.payload.questionKey.publicKeySpkiSha256 = falseSpkiSha256;
    falseKey.payload.questionKey.keyId = falseSpkiSha256;
    falseKey.payloadSha256 = await canonicalJsonSha256(falseKey.payload);
    const falseKeyResult = await verifyQuestionVotingAuthorizationV3Integrity(falseKey);
    expect(falseKeyResult.ok).toBe(false);
    if (!falseKeyResult.ok) {
      expect(falseKeyResult.errors.join("\n")).toContain(
        "must encode a P-256 public key",
      );
    }
  });

  test("does not build an authorization payload around a non-P-256 key", async () => {
    await expect(
      buildQuestionVotingAuthorizationPayloadV3({
        binding: binding(),
        questionId,
        questionNullifier: digest(5),
        nullifierKeyEpoch: 1,
        questionKeyPublicKeySpki: base64UrlEncode(new Uint8Array(65).fill(12)),
        eligibilityClaim: "active-law-graduate",
        registryCheckpointId: "registry-checkpoint-42",
        registryCheckpointSha256: digest(6),
        registryCheckpointWitnessCanonicalEnvelope: "{}",
        registryCheckpointWitnessEnvelopeSha256: await sha256Base64Url("{}"),
        issuedAt,
        expiresAt,
        issuerAttestationAudience:
          "https://verifier.example.test/question-authorization",
      }),
    ).rejects.toThrow("must encode a P-256 public key");
  });

  test("requires a normalized, non-empty validity window", async () => {
    const authorization = await authorizationFixture();
    const payload = structuredClone(authorization.payload);
    payload.expiresAt = payload.issuedAt;
    const result = validateQuestionVotingAuthorizationPayloadV3(payload);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors.join("\n")).toContain(
        "$.expiresAt must be later than issuedAt",
      );
    }
  });
});

describe("vote event V3", () => {
  test("builds a private event and validates all authorization links", async () => {
    const { authorization, event } = await voteFixture();

    expect(event.publicationMode).toBe("private");
    const eventKeys = objectKeys(event);
    for (const forbidden of [
      "publicVoterId",
      "identityProofSha256",
      "eligibilityAssertionSha256",
      "rootCredentialId",
      "qualificationSubject",
      "delegationSha256",
    ]) {
      expect(eventKeys).not.toContain(forbidden);
    }
    expect(validateVoteEventV3(event)).toEqual({ ok: true, value: event });
    expect(
      await verifyVoteEventV3AuthorizationBinding({
        event,
        authorization,
      }),
    ).toEqual({ ok: true, value: event });
  });

  test("accepts explicit attribution and chained replacement/withdrawal", async () => {
    const attributed = await voteFixture({ publicationMode: "attributed" });
    expect(validateVoteEventV3(attributed.event).ok).toBe(true);

    const replacement = await voteFixture({
      eventId: "vote-event-2",
      eventType: "replace",
      sequence: 2,
      previousEventSha256: digest(13),
      choiceId: "disagree",
    });
    expect(validateVoteEventV3(replacement.event).ok).toBe(true);

    const withdrawal = await voteFixture({
      eventId: "vote-event-3",
      eventType: "withdraw",
      sequence: 3,
      previousEventSha256: digest(14),
      choiceId: "ignored-by-builder",
    });
    expect(withdrawal.event.choiceId).toBeNull();
    expect(validateVoteEventV3(withdrawal.event).ok).toBe(true);
  });

  test("rejects identity fields, public-by-omission, and invalid chain state", async () => {
    const { event } = await voteFixture();
    const linked = structuredClone(event) as VoteEventV3 & {
      publicVoterId?: string;
    };
    linked.publicVoterId = "member-1";
    const linkedResult = validateVoteEventV3(linked);
    expect(linkedResult.ok).toBe(false);
    if (!linkedResult.ok) {
      expect(linkedResult.errors.join("\n")).toContain(
        "$.publicVoterId is not allowed",
      );
    }

    const missingMode = structuredClone(event) as Partial<VoteEventV3>;
    Reflect.deleteProperty(missingMode, "publicationMode");
    const missingModeResult = validateVoteEventV3(missingMode);
    expect(missingModeResult.ok).toBe(false);
    if (!missingModeResult.ok) {
      expect(missingModeResult.errors.join("\n")).toContain(
        "$.publicationMode is required",
      );
    }

    const invalidFirst = structuredClone(event);
    invalidFirst.eventType = "replace";
    invalidFirst.previousEventSha256 = digest(15);
    const invalidFirstResult = validateVoteEventV3(invalidFirst);
    expect(invalidFirstResult.ok).toBe(false);
    if (!invalidFirstResult.ok) {
      expect(invalidFirstResult.errors.join("\n")).toContain(
        "$.eventType must be cast at sequence 1",
      );
      expect(invalidFirstResult.errors.join("\n")).toContain(
        "$.previousEventSha256 must be null at sequence 1",
      );
    }
  });

  test.each([
    [
      "question",
      (event: VoteEventV3) => {
        event.questionId = "question-other";
      },
      "questionId",
    ],
    [
      "nullifier",
      (event: VoteEventV3) => {
        event.questionNullifier = digest(20);
      },
      "questionNullifier",
    ],
    [
      "authorization hash",
      (event: VoteEventV3) => {
        event.authorizationSha256 = digest(21);
      },
      "authorizationSha256",
    ],
    [
      "question key",
      (event: VoteEventV3) => {
        event.questionKeyId = digest(22);
      },
      "questionKeyId",
    ],
    [
      "binding",
      (event: VoteEventV3) => {
        event.binding.instance.id = "org.other";
      },
      "binding",
    ],
    [
      "validity window",
      (event: VoteEventV3) => {
        event.issuedAt = expiresAt;
      },
      "validity window",
    ],
  ])("rejects a mismatched %s link", async (_name, mutate, expected) => {
    const { authorization, event } = await voteFixture();
    mutate(event);
    const result = await verifyVoteEventV3AuthorizationBinding({
      event,
      authorization,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors.join("\n")).toContain(expected);
    }
  });
});
