import { describe, expect, test } from "bun:test";
import {
  attachPublicVoteAttributionSignatureV3,
  buildPublicVoteAttributionPayloadV3,
  verifyPublicVoteAttributionV3Integrity,
} from "./vote-attribution-v3";

const digest = "A".repeat(43);
const signature = "A".repeat(86);

describe("removable public V3 vote attribution", () => {
  test("binds one identity delegation to one exact vote event", async () => {
    const payload = buildPublicVoteAttributionPayloadV3({
      publicVoterId: "550e8400-e29b-41d4-a716-446655440000",
      delegationSha256: digest,
      voteEventId: "550e8400-e29b-41d4-a716-446655440001",
      voteEventSha256: digest,
      questionId: "550e8400-e29b-41d4-a716-446655440002",
      attributedAt: "2026-07-24T10:00:00.000Z",
    });
    const envelope = await attachPublicVoteAttributionSignatureV3({
      payload,
      delegatedKeyId: digest,
      signature,
    });

    expect(await verifyPublicVoteAttributionV3Integrity(envelope)).toEqual({
      ok: true,
      value: envelope,
    });
  });

  test("rejects an altered event binding and extra identity data", async () => {
    const payload = buildPublicVoteAttributionPayloadV3({
      publicVoterId: "550e8400-e29b-41d4-a716-446655440000",
      delegationSha256: digest,
      voteEventId: "550e8400-e29b-41d4-a716-446655440001",
      voteEventSha256: digest,
      questionId: "550e8400-e29b-41d4-a716-446655440002",
      attributedAt: "2026-07-24T10:00:00.000Z",
    });
    const envelope = await attachPublicVoteAttributionSignatureV3({
      payload,
      delegatedKeyId: digest,
      signature,
    });
    const altered = structuredClone(envelope) as typeof envelope & {
      email?: string;
    };
    altered.email = "lawyer@example.test";

    expect((await verifyPublicVoteAttributionV3Integrity(altered)).ok).toBe(false);
    envelope.payload.voteEventSha256 = "B".repeat(43);
    expect((await verifyPublicVoteAttributionV3Integrity(envelope)).ok).toBe(false);
  });
});
