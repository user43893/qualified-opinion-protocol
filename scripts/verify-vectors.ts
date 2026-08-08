import { readFile } from "node:fs/promises";
import { join } from "node:path";
import {
  QUESTION_VOTE_LOG_DOMAIN_V3,
  assertActiveEligibilityDirectoryCheckpointV3,
  assertVoteEventV3,
  canonicalizeJson,
  questionVoteLogIdV3,
  sha256Base64Url,
  sha256Hex,
} from "../packages/protocol/src/index";
import { ROOT } from "./shared";

type VectorCase = {
  canonical: string;
  expectedLogId?: string;
  id: string;
  kind:
    | "active-eligibility-directory-checkpoint-v3"
    | "canonical-json"
    | "question-vote-log-id-v3"
    | "vote-event-v3";
  sha256Base64Url: string;
  sha256Hex: string;
  value: unknown;
};

type VectorSet = {
  $schema: string;
  cases: VectorCase[];
  publicOnly: boolean;
};

const vectorPath = join(ROOT, "vectors/v3/canonicalization.json");
const vectorText = await readFile(vectorPath, "utf8");
const vectors = JSON.parse(vectorText) as VectorSet;

if (
  vectors.$schema !== "qualified-opinion.canonicalization-conformance-vectors.v3" ||
  vectors.publicOnly !== true ||
  !Array.isArray(vectors.cases) ||
  vectors.cases.length === 0
) {
  throw new Error("Invalid V3 conformance-vector set");
}

const ids = new Set<string>();
for (const vector of vectors.cases) {
  if (!vector.id || ids.has(vector.id)) {
    throw new Error(`Missing or duplicate vector id ${JSON.stringify(vector.id)}`);
  }
  ids.add(vector.id);
  assertPublicOnly(vector.value, `cases.${vector.id}.value`);

  if (vector.kind === "vote-event-v3") {
    assertVoteEventV3(vector.value);
  } else if (vector.kind === "active-eligibility-directory-checkpoint-v3") {
    assertActiveEligibilityDirectoryCheckpointV3(vector.value);
  } else if (vector.kind === "question-vote-log-id-v3") {
    const scope = vector.value as {
      domain?: unknown;
      instanceId?: unknown;
      questionId?: unknown;
    };
    if (
      scope.domain !== QUESTION_VOTE_LOG_DOMAIN_V3 ||
      typeof scope.instanceId !== "string" ||
      typeof scope.questionId !== "string" ||
      (await questionVoteLogIdV3({
        instanceId: scope.instanceId,
        questionId: scope.questionId,
      })) !== vector.expectedLogId
    ) {
      throw new Error(`${vector.id}: question vote log ID mismatch`);
    }
  } else if (vector.kind !== "canonical-json") {
    throw new Error(`Unknown vector kind for ${vector.id}`);
  }

  const canonical = canonicalizeJson(vector.value);
  if (canonical !== vector.canonical) {
    throw new Error(`${vector.id}: canonical JSON mismatch`);
  }
  if ((await sha256Base64Url(canonical)) !== vector.sha256Base64Url) {
    throw new Error(`${vector.id}: base64url SHA-256 mismatch`);
  }
  if ((await sha256Hex(canonical)) !== vector.sha256Hex) {
    throw new Error(`${vector.id}: hexadecimal SHA-256 mismatch`);
  }
}

console.log(`Verified ${vectors.cases.length} public V3 conformance vectors.`);

function assertPublicOnly(value: unknown, path: string): void {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertPublicOnly(entry, `${path}[${index}]`));
    return;
  }
  if (value === null || typeof value !== "object") return;

  for (const [key, entry] of Object.entries(value)) {
    if (
      /(?:privatekey|private_key|secret|password|credential|attestationtoken)/i.test(
        key,
      )
    ) {
      throw new Error(`${path}.${key}: private material is not allowed`);
    }
    assertPublicOnly(entry, `${path}.${key}`);
  }
}
