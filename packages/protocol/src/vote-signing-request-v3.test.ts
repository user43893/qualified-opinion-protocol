import { describe, expect, test } from "bun:test";
import {
  VOTE_SIGNING_REQUEST_BATCH_SCHEMA_V3,
  assertVoteSigningRequestBatchV3,
  attachDetachedSignature,
  buildBallotManifestV3,
  buildProtocolBindingV3,
  buildVoteSigningIntentV3,
  canonicalJsonSha256,
  canonicalizeJson,
  verifyVoteSigningRequestBatchV3,
  voteSigningRequestBatchSha256V3,
} from ".";

const digest = (byte: number) => Buffer.alloc(32, byte).toString("base64url");

async function fixture() {
  const binding = buildProtocolBindingV3({
    instanceId: "example",
    instanceProfileSha256: digest(1),
    eligibilityPolicy: { id: "eligibility", sha256: digest(2) },
    tallyPolicy: { id: "tally", sha256: digest(3) },
    trustPolicy: { id: "trust", sha256: digest(4) },
    audience: "https://api.example.test",
    origin: "https://app.example.test",
  });
  const manifest = buildBallotManifestV3({
    manifestId: "manifest",
    ballotId: "ballot",
    questionId: "question",
    nullifierKeyEpoch: 1,
    revision: 1,
    binding,
    meaningChoices: [
      {
        id: "yes",
        slug: "yes",
        semanticCode: "yes",
        displayOrder: 1,
        isCounted: true,
      },
      {
        id: "no",
        slug: "no",
        semanticCode: "no",
        displayOrder: 2,
        isCounted: true,
      },
    ],
    locale: "en",
    questionText: "Question?",
    presentationChoices: [
      { id: "yes", label: "Yes", description: "Yes." },
      { id: "no", label: "No", description: "No." },
    ],
    publishedAt: "2026-07-28T00:00:00.000Z",
    issuerKeyId: "receipt-key",
  });
  const questionManifest = await attachDetachedSignature(manifest, {
    algorithm: "Ed25519",
    keyId: "receipt-key",
    value: Buffer.alloc(64, 9).toString("base64url"),
  });
  const intent = buildVoteSigningIntentV3({
    eventId: "11111111-1111-4111-8111-111111111111",
    eventType: "cast",
    binding,
    ballotManifestSha256: questionManifest.payloadSha256,
    ballotId: "ballot",
    questionId: "question",
    choiceId: "yes",
    sequence: 1,
    challenge: Buffer.alloc(32, 8).toString("base64url"),
    preparedAt: "2026-07-28T00:01:00.000Z",
  });
  const batch = {
    schema: VOTE_SIGNING_REQUEST_BATCH_SCHEMA_V3,
    sessionId: "22222222-2222-4222-8222-222222222222",
    publicVoterId: "33333333-3333-4333-8333-333333333333",
    delegationId: "44444444-4444-4444-8444-444444444444",
    delegationSha256: digest(5),
    delegatedKeyId: digest(6),
    locale: "en" as const,
    expiresAt: "2026-07-28T00:05:00.000Z",
    items: [
      {
        challengeId: "55555555-5555-4555-8555-555555555555",
        canonicalIntent: canonicalizeJson(intent),
        intentSha256: await canonicalJsonSha256(intent),
        ordinal: 0,
        questionManifest,
      },
    ],
  };
  return { batch, intent };
}

describe("V3 vote signing request", () => {
  test("verifies the exact one-question request graph", async () => {
    const { batch, intent } = await fixture();
    const batchSha256 = await voteSigningRequestBatchSha256V3(batch);
    const verified = await verifyVoteSigningRequestBatchV3({
      batch,
      batchSha256,
    });
    expect(verified.items[0]?.intent).toEqual(intent);
  });

  test("rejects obsolete schemas and link tampering", async () => {
    const { batch } = await fixture();
    expect(() =>
      assertVoteSigningRequestBatchV3({ ...batch, schema: "old.v1" }),
    ).toThrow("invalid_vote_signing_request_batch");
    expect(() =>
      assertVoteSigningRequestBatchV3({
        ...batch,
        items: [
          {
            ...batch.items[0],
            intentSha256: digest(7),
          },
        ],
      }),
    ).not.toThrow();
    await expect(
      verifyVoteSigningRequestBatchV3({
        batch: {
          ...batch,
          items: [{ ...batch.items[0], intentSha256: digest(7) }],
        },
        batchSha256: await canonicalJsonSha256({
          ...batch,
          items: [{ ...batch.items[0], intentSha256: digest(7) }],
        }),
      }),
    ).rejects.toThrow("vote_signing_request_item_hash_mismatch");
  });
});
