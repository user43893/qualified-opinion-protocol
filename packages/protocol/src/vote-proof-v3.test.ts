import { describe, expect, test } from "bun:test";
import {
  attachDetachedSignature,
  buildMerkleTreeHeadV3,
  buildVoteAcceptanceV3,
} from "./builders";
import { canonicalizeJson } from "./canonical";
import { base64UrlEncode, canonicalJsonSha256, sha256Base64Url } from "./encoding";
import { createMerkleInclusionProof } from "./merkle";
import { questionVoteLogIdV3 } from "./question-vote-log-v3";
import {
  buildBallotManifestV3,
  buildProtocolBindingV3,
  buildQuestionVotingAuthorizationPayloadV3,
  buildQuestionVotingAuthorizationV3,
  buildVoteEventV3,
} from "./v3-builders";
import {
  buildPublicVoteProofBundleV3,
  validatePublicVoteProofBundleV3,
  verifyPublicVoteProofBundleV3Integrity,
} from "./vote-proof-v3";

function digest(byte: number) {
  return base64UrlEncode(new Uint8Array(32).fill(byte));
}

function signature(byte: number) {
  return base64UrlEncode(new Uint8Array(64).fill(byte));
}

async function buildFixture() {
  const binding = buildProtocolBindingV3({
    instanceId: "org.example.qualified-opinion",
    instanceProfileSha256: digest(1),
    eligibilityPolicy: { id: "active-law-graduate.v3", sha256: digest(2) },
    tallyPolicy: { id: "direct-vote.v3", sha256: digest(3) },
    trustPolicy: { id: "confidential-space.v3", sha256: digest(4) },
    audience: "https://vote.example.test",
    origin: "https://app.example.test",
  });
  const questionKey = (await globalThis.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const questionKeySpki = base64UrlEncode(
    new Uint8Array(
      await globalThis.crypto.subtle.exportKey("spki", questionKey.publicKey),
    ),
  );
  const questionAuthorization = await buildQuestionVotingAuthorizationV3({
    payload: await buildQuestionVotingAuthorizationPayloadV3({
      binding,
      questionId: "question-1",
      questionNullifier: digest(5),
      nullifierKeyEpoch: 1,
      questionKeyPublicKeySpki: questionKeySpki,
      eligibilityClaim: "active-law-graduate",
      registryCheckpointId: "registry-checkpoint-1",
      registryCheckpointSha256: digest(6),
      registryCheckpointWitnessCanonicalEnvelope: "{}",
      registryCheckpointWitnessEnvelopeSha256: await sha256Base64Url("{}"),
      issuedAt: "2026-07-24T12:00:00.000Z",
      expiresAt: "2026-07-24T12:15:00.000Z",
      issuerAttestationAudience: "https://verifier.example.test/question-authorization",
    }),
    attestationToken: "header.payload.signature",
  });
  const manifest = buildBallotManifestV3({
    manifestId: "manifest-1",
    ballotId: "ballot-1",
    questionId: "question-1",
    nullifierKeyEpoch: 1,
    revision: 1,
    binding,
    meaningChoices: [
      {
        id: "agree",
        slug: "agree",
        semanticCode: null,
        displayOrder: 1,
        isCounted: true,
      },
      {
        id: "disagree",
        slug: "disagree",
        semanticCode: null,
        displayOrder: 2,
        isCounted: true,
      },
    ],
    locale: "tr",
    questionText: "Katılıyor musunuz?",
    presentationChoices: [
      { id: "agree", label: "Katılıyorum", description: "" },
      { id: "disagree", label: "Katılmıyorum", description: "" },
    ],
    publishedAt: "2026-07-24T11:00:00.000Z",
    issuerKeyId: "receipt-key-1",
  });
  const questionManifest = await attachDetachedSignature(manifest, {
    algorithm: "Ed25519",
    keyId: "receipt-key-1",
    value: signature(7),
  });
  const event = buildVoteEventV3({
    eventId: "vote-event-1",
    eventType: "cast",
    binding,
    questionNullifier: questionAuthorization.payload.questionNullifier,
    authorizationSha256: questionAuthorization.payloadSha256,
    publicationMode: "private",
    ballotManifestSha256: questionManifest.payloadSha256,
    ballotId: manifest.ballotId,
    questionId: manifest.questionId,
    choiceId: "agree",
    sequence: 1,
    challenge: base64UrlEncode(new Uint8Array(24).fill(8)),
    issuedAt: "2026-07-24T12:05:00.000Z",
    questionKeyId: questionAuthorization.payload.questionKey.keyId,
  });
  const voteEvent = await attachDetachedSignature(event, {
    algorithm: "ES256",
    keyId: event.questionKeyId,
    value: signature(9),
  });
  const receipt = buildVoteAcceptanceV3({
    receiptId: "receipt-1",
    voteEventSha256: voteEvent.payloadSha256,
    status: "counted",
    logId: await questionVoteLogIdV3({
      instanceId: binding.instance.id,
      questionId: manifest.questionId,
    }),
    receivedAt: "2026-07-24T12:05:01.000Z",
    issuerKeyId: "receipt-key-1",
  });
  const acceptance = await attachDetachedSignature(receipt, {
    algorithm: "Ed25519",
    keyId: "receipt-key-1",
    value: signature(10),
  });
  const leaves = [
    canonicalizeJson({
      entryId: event.eventId,
      entryPayloadHash: voteEvent.payloadSha256,
      entryType: "vote_event",
    }),
    canonicalizeJson({
      entryId: receipt.receiptId,
      entryPayloadHash: acceptance.payloadSha256,
      entryType: "vote_adjudication",
    }),
  ];
  const [eventProof, acceptanceProof] = await Promise.all([
    createMerkleInclusionProof(leaves, 0),
    createMerkleInclusionProof(leaves, 1),
  ]);
  const treeHead = await attachDetachedSignature(
    buildMerkleTreeHeadV3({
      logId: receipt.logId,
      treeSize: 2,
      rootHash: eventProof.rootHash,
      issuedAt: "2026-07-24T12:05:02.000Z",
      issuerKeyId: "receipt-key-1",
    }),
    {
      algorithm: "Ed25519",
      keyId: "receipt-key-1",
      value: signature(11),
    },
  );
  return buildPublicVoteProofBundleV3({
    bundleId: event.eventId,
    questionAuthorization,
    questionManifest,
    voteEvent,
    acceptance,
    voteEventTransparency: {
      leafIndex: eventProof.leafIndex,
      leafHash: eventProof.leafHash,
      auditPath: eventProof.auditPath,
      treeHead,
    },
    acceptanceTransparency: {
      leafIndex: acceptanceProof.leafIndex,
      leafHash: acceptanceProof.leafHash,
      auditPath: acceptanceProof.auditPath,
      treeHead,
    },
  });
}

const fixturePromise = buildFixture();

async function fixture() {
  return structuredClone(await fixturePromise);
}

function objectKeys(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap(objectKeys);
  if (!value || typeof value !== "object") return [];
  return Object.entries(value).flatMap(([key, child]) => [key, ...objectKeys(child)]);
}

describe("public V3 vote proof bundle", () => {
  test("verifies a complete question-only bundle", async () => {
    const bundle = await fixture();
    expect(await verifyPublicVoteProofBundleV3Integrity(bundle)).toEqual({
      ok: true,
      value: bundle,
    });
  });

  test("contains no global identity or reusable authorization material", async () => {
    const bundle = await fixture();
    const keys = objectKeys(bundle);
    for (const forbidden of [
      "publicVoterId",
      "identityProof",
      "eligibilityAssertion",
      "rootKeyDelegation",
      "delegationId",
      "userId",
      "displayName",
      "normalizedEmail",
      "qualificationSubject",
    ]) {
      expect(keys).not.toContain(forbidden);
    }
  });

  test("rejects extra identity-bearing fields at exact boundaries", async () => {
    const bundle = (await fixture()) as Awaited<ReturnType<typeof fixture>> & {
      publicVoterId?: string;
    };
    bundle.publicVoterId = "member-1";
    const result = validatePublicVoteProofBundleV3(bundle);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors.join("\n")).toContain("$.publicVoterId is not allowed");
    }

    const nested = (await fixture()) as Awaited<ReturnType<typeof fixture>> & {
      questionAuthorization: {
        payload: { accountId?: string };
      };
    };
    nested.questionAuthorization.payload.accountId = "private-account-id";
    const nestedResult = validatePublicVoteProofBundleV3(nested);
    expect(nestedResult.ok).toBe(false);
    if (!nestedResult.ok) {
      expect(nestedResult.errors.join("\n")).toContain(
        "$.payload.accountId is not allowed",
      );
    }
  });

  test("rejects an authorization from a different question epoch", async () => {
    const bundle = await fixture();
    bundle.questionManifest.payload.nullifierKeyEpoch = 2;
    bundle.questionManifest.payloadSha256 = await canonicalJsonSha256(
      bundle.questionManifest.payload,
    );
    const result = await verifyPublicVoteProofBundleV3Integrity(bundle);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors.join("\n")).toContain(
        "questionAuthorization nullifierKeyEpoch must match questionManifest",
      );
    }
  });

  test("rejects an acceptance bound to any non-deterministic log", async () => {
    const bundle = await fixture();
    bundle.acceptance.payload.logId = "attacker-selected-log";
    bundle.acceptance.payloadSha256 = await canonicalJsonSha256(
      bundle.acceptance.payload,
    );
    const result = await verifyPublicVoteProofBundleV3Integrity(bundle);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors.join("\n")).toContain(
        "acceptance must bind the deterministic question log",
      );
    }
  });

  test("rejects a manifest substitution", async () => {
    const bundle = await fixture();
    bundle.voteEvent.payload.ballotManifestSha256 = digest(12);
    const result = await verifyPublicVoteProofBundleV3Integrity(bundle);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors.join("\n")).toContain(
        "voteEvent ballotManifestSha256 must match questionManifest",
      );
    }
  });
});
