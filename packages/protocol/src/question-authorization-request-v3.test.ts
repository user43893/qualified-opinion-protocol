import { describe, expect, test } from "bun:test";
import {
  QUESTION_SCOPED_VOTE_SESSION_MAX_ITEMS,
  buildQuestionVotingAuthorizationRequestV3,
} from "./index";

const sessionId = "00000000-0000-4000-8000-000000000001";
const requestBatchSha256 = "A".repeat(43);

describe("question authorization privacy boundary", () => {
  test("permits exactly one question per authorization request", async () => {
    expect(QUESTION_SCOPED_VOTE_SESSION_MAX_ITEMS).toBe(1);

    await expect(
      buildQuestionVotingAuthorizationRequestV3({
        sessionId,
        requestBatchSha256,
        publicationMode: "private",
        issuedAt: "2026-07-24T12:00:00.000Z",
        expiresAt: "2026-07-24T12:10:00.000Z",
        items: [
          {
            questionId: "question-1",
            ballotManifestSha256: "A".repeat(43),
            questionPublicKeySpki: "AQ",
          },
        ],
      }),
    ).resolves.toMatchObject({
      items: [{ ordinal: 0, questionId: "question-1" }],
    });
  });

  test("rejects two fresh question keys that could be linked by one public-log append", async () => {
    await expect(
      buildQuestionVotingAuthorizationRequestV3({
        sessionId,
        requestBatchSha256,
        publicationMode: "private",
        issuedAt: "2026-07-24T12:00:00.000Z",
        expiresAt: "2026-07-24T12:10:00.000Z",
        items: [
          {
            questionId: "question-1",
            ballotManifestSha256: "A".repeat(43),
            questionPublicKeySpki: "AQ",
          },
          {
            questionId: "question-2",
            ballotManifestSha256: "A".repeat(43),
            questionPublicKeySpki: "Ag",
          },
        ],
      }),
    ).rejects.toThrow("invalid_question_voting_authorization_request_v3");
  });
});
