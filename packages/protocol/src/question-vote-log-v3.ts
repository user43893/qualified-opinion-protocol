import { canonicalJsonSha256 } from "./encoding";

export const QUESTION_VOTE_LOG_DOMAIN_V3 =
  "qualified-opinion.question-votes.v3" as const;

/**
 * Derives the one authoritative accepted-vote log identifier for a question.
 *
 * Hashing the canonical instance/question tuple keeps the storage key short
 * and unambiguous while the domain prefix makes accidental reuse by another
 * log protocol impossible.
 */
export async function questionVoteLogIdV3(input: {
  instanceId: string;
  questionId: string;
}): Promise<string> {
  const instanceId = requiredString(input.instanceId, "instanceId");
  const questionId = requiredString(input.questionId, "questionId");
  const scopeSha256 = await canonicalJsonSha256({
    domain: QUESTION_VOTE_LOG_DOMAIN_V3,
    instanceId,
    questionId,
  });
  return `${QUESTION_VOTE_LOG_DOMAIN_V3}:${scopeSha256}`;
}

function requiredString(value: string, field: string) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError(`${field} must be a non-empty string`);
  }
  return value.trim();
}
