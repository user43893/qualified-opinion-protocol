import { isoTimestamp } from "./builders";
import { canonicalizeJson } from "./canonical";
import { canonicalJsonSha256, isSha256Base64Url } from "./encoding";
import {
  type ProtocolBindingV3,
  type QualificationSubjectV3,
  REGISTRY_EVIDENCE_SCHEMA_V3,
  type RegistryEvidenceV3,
} from "./v3-types";
import { assertProtocolBindingV3 } from "./v3-validate";
import type { ValidationResult } from "./validate";

export const IDENTITY_ATTESTATION_POLICY_SCHEMA_V3 =
  "qualified-opinion.identity-attestation-policy.v3" as const;
export const ELIGIBILITY_ASSERTION_SCHEMA_V3 =
  "qualified-opinion.eligibility-assertion.v3" as const;
export const GOOGLE_CONFIDENTIAL_SPACE_PROVIDER_V3 =
  "google-confidential-space" as const;
export const GOOGLE_CONFIDENTIAL_SPACE_ISSUER_V3 =
  "https://confidentialcomputing.googleapis.com" as const;

/**
 * Exact, non-secret policy material used to verify one registration receipt.
 *
 * This object is embedded by hash in the eligibility issuer's signature. A
 * later verifier image or environment change therefore cannot reinterpret an
 * older identity proof, and the voting service does not need to trust policy
 * material supplied by the application at authorization time.
 */
export type IdentityAttestationPolicyV3 = {
  schema: typeof IDENTITY_ATTESTATION_POLICY_SCHEMA_V3;
  policyId: string;
  provider: typeof GOOGLE_CONFIDENTIAL_SPACE_PROVIDER_V3;
  issuer: typeof GOOGLE_CONFIDENTIAL_SPACE_ISSUER_V3;
  audience: string;
  imageDigest: string;
  projectId: string;
  serviceAccount: string;
  expectedEnvironment: Record<string, string>;
  allowDebug: boolean;
  requirePki: true;
  pkiRootCertificateSha256: string;
  requireMemoryMonitoringDisabled: true;
  requireStable: true;
  identityOrigin: string;
  rpId: string;
};

export type EligibilityAssertionV3 = {
  schema: typeof ELIGIBILITY_ASSERTION_SCHEMA_V3;
  assertionId: string;
  publicVoterId: string;
  binding: ProtocolBindingV3;
  identityProof: {
    proofId: string;
    payloadSha256: string;
  };
  identityAttestation: {
    policy: IdentityAttestationPolicyV3;
    policySha256: string;
  };
  rootKey: {
    credentialId: string;
    publicKeySpkiSha256: string;
  };
  qualification: {
    claim: string;
    policy: ProtocolBindingV3["eligibilityPolicy"];
    subject: QualificationSubjectV3;
  };
  registryEvidence: {
    payload: RegistryEvidenceV3;
    payloadSha256: string;
  };
  issuedAt: string;
  notBefore: string;
  expiresAt: string | null;
  issuer: {
    algorithm: "Ed25519";
    keyId: string;
    purpose: "eligibility";
  };
};

type TimestampInput = Date | string;

export function buildIdentityAttestationPolicyV3(input: {
  policyId: string;
  audience: string;
  imageDigest: string;
  projectId: string;
  serviceAccount: string;
  expectedEnvironment: Record<string, string>;
  allowDebug: boolean;
  pkiRootCertificateSha256: string;
  identityOrigin: string;
  rpId: string;
}): IdentityAttestationPolicyV3 {
  const expectedEnvironment = Object.fromEntries(
    Object.entries(input.expectedEnvironment)
      .map(([name, value]) => [
        requiredString(name, "expectedEnvironment.name"),
        requiredString(value, `expectedEnvironment.${name}`),
      ])
      .sort(([left], [right]) => left.localeCompare(right)),
  );
  if (Object.keys(expectedEnvironment).length === 0) {
    throw new TypeError("expectedEnvironment must not be empty");
  }
  const policy: IdentityAttestationPolicyV3 = {
    schema: IDENTITY_ATTESTATION_POLICY_SCHEMA_V3,
    policyId: requiredString(input.policyId, "policyId"),
    provider: GOOGLE_CONFIDENTIAL_SPACE_PROVIDER_V3,
    issuer: GOOGLE_CONFIDENTIAL_SPACE_ISSUER_V3,
    audience: requiredString(input.audience, "audience"),
    imageDigest: requiredString(input.imageDigest, "imageDigest"),
    projectId: requiredString(input.projectId, "projectId"),
    serviceAccount: requiredString(input.serviceAccount, "serviceAccount"),
    expectedEnvironment,
    allowDebug: input.allowDebug,
    requirePki: true,
    pkiRootCertificateSha256: requiredString(
      input.pkiRootCertificateSha256,
      "pkiRootCertificateSha256",
    ),
    requireMemoryMonitoringDisabled: true,
    requireStable: true,
    identityOrigin: exactOrigin(input.identityOrigin, "identityOrigin"),
    rpId: requiredString(input.rpId, "rpId"),
  };
  assertIdentityAttestationPolicyV3(policy);
  return policy;
}

export async function buildEligibilityAssertionV3(input: {
  assertionId: string;
  publicVoterId: string;
  binding: ProtocolBindingV3;
  identityProof: EligibilityAssertionV3["identityProof"];
  identityAttestationPolicy: IdentityAttestationPolicyV3;
  rootKey: EligibilityAssertionV3["rootKey"];
  qualificationClaim: string;
  subject: QualificationSubjectV3;
  registryEvidence: RegistryEvidenceV3;
  issuedAt: TimestampInput;
  notBefore?: TimestampInput;
  expiresAt?: TimestampInput | null;
  issuerKeyId: string;
}): Promise<EligibilityAssertionV3> {
  const issuedAt = isoTimestamp(input.issuedAt, "issuedAt");
  const evidence = structuredClone(input.registryEvidence);
  const policy = structuredClone(input.identityAttestationPolicy);
  assertProtocolBindingV3(input.binding);
  const payload: EligibilityAssertionV3 = {
    schema: ELIGIBILITY_ASSERTION_SCHEMA_V3,
    assertionId: requiredString(input.assertionId, "assertionId"),
    publicVoterId: requiredString(input.publicVoterId, "publicVoterId"),
    binding: structuredClone(input.binding),
    identityProof: {
      proofId: requiredString(input.identityProof.proofId, "identityProof.proofId"),
      payloadSha256: input.identityProof.payloadSha256,
    },
    identityAttestation: {
      policy,
      policySha256: await canonicalJsonSha256(policy),
    },
    rootKey: {
      credentialId: requiredString(input.rootKey.credentialId, "rootKey.credentialId"),
      publicKeySpkiSha256: input.rootKey.publicKeySpkiSha256,
    },
    qualification: {
      claim: requiredString(input.qualificationClaim, "qualificationClaim"),
      policy: structuredClone(input.binding.eligibilityPolicy),
      subject: structuredClone(input.subject),
    },
    registryEvidence: {
      payload: evidence,
      payloadSha256: await canonicalJsonSha256(evidence),
    },
    issuedAt,
    notBefore: isoTimestamp(input.notBefore ?? issuedAt, "notBefore"),
    expiresAt:
      input.expiresAt === null || input.expiresAt === undefined
        ? null
        : isoTimestamp(input.expiresAt, "expiresAt"),
    issuer: {
      algorithm: "Ed25519",
      keyId: requiredString(input.issuerKeyId, "issuerKeyId"),
      purpose: "eligibility",
    },
  };
  assertEligibilityAssertionV3(payload);
  return payload;
}

export function isEligibilityAssertionV3(
  value: unknown,
): value is EligibilityAssertionV3 {
  return isRecord(value) && value.schema === ELIGIBILITY_ASSERTION_SCHEMA_V3;
}

export function validateIdentityAttestationPolicyV3(
  value: unknown,
): ValidationResult<IdentityAttestationPolicyV3> {
  const errors = collectIdentityAttestationPolicyErrors(value, "$");
  return errors.length === 0
    ? { ok: true, value: value as IdentityAttestationPolicyV3 }
    : { ok: false, errors };
}

export function assertIdentityAttestationPolicyV3(
  value: unknown,
): asserts value is IdentityAttestationPolicyV3 {
  const result = validateIdentityAttestationPolicyV3(value);
  if (!result.ok) {
    throw new TypeError(
      `Invalid qualified-opinion identity-attestation policy:\n${result.errors
        .map((error) => `- ${error}`)
        .join("\n")}`,
    );
  }
}

export function validateEligibilityAssertionV3(
  value: unknown,
): ValidationResult<EligibilityAssertionV3> {
  const errors: string[] = [];
  if (!isRecord(value)) {
    return { ok: false, errors: ["$ must be an object"] };
  }
  exactKeys(
    value,
    [
      "schema",
      "assertionId",
      "publicVoterId",
      "binding",
      "identityProof",
      "identityAttestation",
      "rootKey",
      "qualification",
      "registryEvidence",
      "issuedAt",
      "notBefore",
      "expiresAt",
      "issuer",
    ],
    "$",
    errors,
  );
  if (value.schema !== ELIGIBILITY_ASSERTION_SCHEMA_V3) {
    errors.push(`$.schema must equal "${ELIGIBILITY_ASSERTION_SCHEMA_V3}"`);
  }
  nonEmpty(value.assertionId, "$.assertionId", errors);
  nonEmpty(value.publicVoterId, "$.publicVoterId", errors);
  try {
    assertProtocolBindingV3(value.binding);
  } catch (error) {
    errors.push(...validationMessages(error, "$.binding"));
  }

  if (!isRecord(value.identityProof)) {
    errors.push("$.identityProof must be an object");
  } else {
    exactKeys(
      value.identityProof,
      ["proofId", "payloadSha256"],
      "$.identityProof",
      errors,
    );
    nonEmpty(value.identityProof.proofId, "$.identityProof.proofId", errors);
    digest(value.identityProof.payloadSha256, "$.identityProof.payloadSha256", errors);
  }
  if (!isRecord(value.rootKey)) {
    errors.push("$.rootKey must be an object");
  } else {
    exactKeys(
      value.rootKey,
      ["credentialId", "publicKeySpkiSha256"],
      "$.rootKey",
      errors,
    );
    nonEmpty(value.rootKey.credentialId, "$.rootKey.credentialId", errors);
    digest(value.rootKey.publicKeySpkiSha256, "$.rootKey.publicKeySpkiSha256", errors);
  }
  let qualificationSubject: Record<string, unknown> | null = null;
  if (!isRecord(value.qualification)) {
    errors.push("$.qualification must be an object");
  } else {
    exactKeys(
      value.qualification,
      ["claim", "policy", "subject"],
      "$.qualification",
      errors,
    );
    nonEmpty(value.qualification.claim, "$.qualification.claim", errors);
    policyReference(value.qualification.policy, "$.qualification.policy", errors);
    qualificationSubject = qualification(
      value.qualification.subject,
      "$.qualification.subject",
      errors,
    );
    if (
      isRecord(value.binding) &&
      canonicalizeJson(value.qualification.policy) !==
        canonicalizeJson(value.binding.eligibilityPolicy)
    ) {
      errors.push("$.qualification.policy must equal binding.eligibilityPolicy");
    }
  }
  if (!isRecord(value.registryEvidence)) {
    errors.push("$.registryEvidence must be an object");
  } else {
    exactKeys(
      value.registryEvidence,
      ["payload", "payloadSha256"],
      "$.registryEvidence",
      errors,
    );
    digest(
      value.registryEvidence.payloadSha256,
      "$.registryEvidence.payloadSha256",
      errors,
    );
    const evidence = value.registryEvidence.payload;
    if (!isRecord(evidence)) {
      errors.push("$.registryEvidence.payload must be an object");
    } else {
      exactKeys(
        evidence,
        [
          "schema",
          "reviewId",
          "reviewerAuthority",
          "subject",
          "recordUrl",
          "checkedFullName",
          "checkedEmail",
          "checkedAt",
        ],
        "$.registryEvidence.payload",
        errors,
      );
      literal(
        evidence.schema,
        REGISTRY_EVIDENCE_SCHEMA_V3,
        "$.registryEvidence.payload.schema",
        errors,
      );
      nonEmpty(evidence.reviewId, "$.registryEvidence.payload.reviewId", errors);
      nonEmpty(
        evidence.reviewerAuthority,
        "$.registryEvidence.payload.reviewerAuthority",
        errors,
      );
      const evidenceSubject = qualification(
        evidence.subject,
        "$.registryEvidence.payload.subject",
        errors,
      );
      if (
        qualificationSubject &&
        evidenceSubject &&
        canonicalizeJson(qualificationSubject) !== canonicalizeJson(evidenceSubject)
      ) {
        errors.push(
          "$.registryEvidence.payload.subject must equal qualification.subject",
        );
      }
      httpUrl(evidence.recordUrl, "$.registryEvidence.payload.recordUrl", errors);
      nonEmpty(
        evidence.checkedFullName,
        "$.registryEvidence.payload.checkedFullName",
        errors,
      );
      nonEmpty(
        evidence.checkedEmail,
        "$.registryEvidence.payload.checkedEmail",
        errors,
      );
      timestamp(evidence.checkedAt, "$.registryEvidence.payload.checkedAt", errors);
    }
  }
  timestamp(value.issuedAt, "$.issuedAt", errors);
  timestamp(value.notBefore, "$.notBefore", errors);
  nullableTimestamp(value.expiresAt, "$.expiresAt", errors);
  if (
    typeof value.notBefore === "string" &&
    typeof value.expiresAt === "string" &&
    Date.parse(value.expiresAt) <= Date.parse(value.notBefore)
  ) {
    errors.push("$.expiresAt must be later than notBefore");
  }
  if (!isRecord(value.issuer)) {
    errors.push("$.issuer must be an object");
  } else {
    exactKeys(value.issuer, ["algorithm", "keyId", "purpose"], "$.issuer", errors);
    literal(value.issuer.algorithm, "Ed25519", "$.issuer.algorithm", errors);
    nonEmpty(value.issuer.keyId, "$.issuer.keyId", errors);
    literal(value.issuer.purpose, "eligibility", "$.issuer.purpose", errors);
  }
  const identityAttestation = value.identityAttestation;
  if (!isRecord(identityAttestation)) {
    errors.push("$.identityAttestation must be an object");
  } else {
    exactKeys(
      identityAttestation,
      ["policy", "policySha256"],
      "$.identityAttestation",
      errors,
    );
    errors.push(
      ...collectIdentityAttestationPolicyErrors(
        identityAttestation.policy,
        "$.identityAttestation.policy",
      ),
    );
    if (!isSha256Base64Url(identityAttestation.policySha256)) {
      errors.push(
        "$.identityAttestation.policySha256 must be a SHA-256 base64url digest",
      );
    }
  }
  return errors.length === 0
    ? { ok: true, value: value as EligibilityAssertionV3 }
    : { ok: false, errors };
}

export function assertEligibilityAssertionV3(
  value: unknown,
): asserts value is EligibilityAssertionV3 {
  const result = validateEligibilityAssertionV3(value);
  if (!result.ok) {
    throw new TypeError(
      `Invalid qualified-opinion V3 eligibility payload:\n${result.errors
        .map((error) => `- ${error}`)
        .join("\n")}`,
    );
  }
}

export async function verifyEligibilityAssertionV3Integrity(
  value: EligibilityAssertionV3,
) {
  return (
    (await canonicalJsonSha256(value.registryEvidence.payload)) ===
      value.registryEvidence.payloadSha256 &&
    (await canonicalJsonSha256(value.identityAttestation.policy)) ===
      value.identityAttestation.policySha256
  );
}

function collectIdentityAttestationPolicyErrors(value: unknown, path: string) {
  const errors: string[] = [];
  if (!isRecord(value)) {
    return [`${path} must be an object`];
  }
  exactKeys(
    value,
    [
      "schema",
      "policyId",
      "provider",
      "issuer",
      "audience",
      "imageDigest",
      "projectId",
      "serviceAccount",
      "expectedEnvironment",
      "allowDebug",
      "requirePki",
      "pkiRootCertificateSha256",
      "requireMemoryMonitoringDisabled",
      "requireStable",
      "identityOrigin",
      "rpId",
    ],
    path,
    errors,
  );
  literal(
    value.schema,
    IDENTITY_ATTESTATION_POLICY_SCHEMA_V3,
    `${path}.schema`,
    errors,
  );
  nonEmpty(value.policyId, `${path}.policyId`, errors);
  literal(
    value.provider,
    GOOGLE_CONFIDENTIAL_SPACE_PROVIDER_V3,
    `${path}.provider`,
    errors,
  );
  literal(value.issuer, GOOGLE_CONFIDENTIAL_SPACE_ISSUER_V3, `${path}.issuer`, errors);
  for (const key of [
    "audience",
    "imageDigest",
    "projectId",
    "serviceAccount",
    "pkiRootCertificateSha256",
    "rpId",
  ] as const) {
    nonEmpty(value[key], `${path}.${key}`, errors);
  }
  if (typeof value.allowDebug !== "boolean") {
    errors.push(`${path}.allowDebug must be a boolean`);
  }
  literal(value.requirePki, true, `${path}.requirePki`, errors);
  literal(
    value.requireMemoryMonitoringDisabled,
    true,
    `${path}.requireMemoryMonitoringDisabled`,
    errors,
  );
  literal(value.requireStable, true, `${path}.requireStable`, errors);
  origin(value.identityOrigin, `${path}.identityOrigin`, errors);
  if (
    !isRecord(value.expectedEnvironment) ||
    Object.keys(value.expectedEnvironment).length === 0
  ) {
    errors.push(`${path}.expectedEnvironment must be a non-empty object`);
  } else {
    for (const [name, environmentValue] of Object.entries(value.expectedEnvironment)) {
      nonEmpty(name, `${path}.expectedEnvironment key`, errors);
      nonEmpty(environmentValue, `${path}.expectedEnvironment.${name}`, errors);
    }
  }
  return errors;
}

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  path: string,
  errors: string[],
) {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (
    actual.length !== sortedExpected.length ||
    actual.some((key, index) => key !== sortedExpected[index])
  ) {
    errors.push(`${path} must contain exactly: ${sortedExpected.join(", ")}`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function literal(value: unknown, expected: unknown, path: string, errors: string[]) {
  if (value !== expected) {
    errors.push(`${path} must equal ${JSON.stringify(expected)}`);
  }
}

function nonEmpty(value: unknown, path: string, errors: string[]) {
  if (typeof value !== "string" || value.trim().length === 0) {
    errors.push(`${path} must be a non-empty string`);
  }
}

function digest(value: unknown, path: string, errors: string[]) {
  if (!isSha256Base64Url(value)) {
    errors.push(`${path} must be a SHA-256 base64url digest`);
  }
}

function policyReference(value: unknown, path: string, errors: string[]) {
  if (!isRecord(value)) {
    errors.push(`${path} must be an object`);
    return;
  }
  exactKeys(value, ["id", "sha256"], path, errors);
  nonEmpty(value.id, `${path}.id`, errors);
  digest(value.sha256, `${path}.sha256`, errors);
}

function qualification(
  value: unknown,
  path: string,
  errors: string[],
): Record<string, unknown> | null {
  if (!isRecord(value)) {
    errors.push(`${path} must be an object`);
    return null;
  }
  exactKeys(value, ["scheme", "issuer", "key"], path, errors);
  nonEmpty(value.scheme, `${path}.scheme`, errors);
  nonEmpty(value.issuer, `${path}.issuer`, errors);
  nonEmpty(value.key, `${path}.key`, errors);
  return value;
}

function timestamp(value: unknown, path: string, errors: string[]) {
  if (typeof value !== "string") {
    errors.push(`${path} must be a normalized UTC timestamp`);
    return;
  }
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) {
    errors.push(`${path} must be a normalized UTC timestamp`);
  }
}

function nullableTimestamp(value: unknown, path: string, errors: string[]) {
  if (value !== null) timestamp(value, path, errors);
}

function httpUrl(value: unknown, path: string, errors: string[]) {
  if (typeof value !== "string") {
    errors.push(`${path} must be an HTTP(S) URL`);
    return;
  }
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      errors.push(`${path} must be an HTTP(S) URL`);
    }
  } catch {
    errors.push(`${path} must be an HTTP(S) URL`);
  }
}

function validationMessages(error: unknown, path: string) {
  if (!(error instanceof Error)) return [`${path}: invalid protocol binding`];
  return error.message
    .split("\n")
    .filter((line) => line.startsWith("- "))
    .map((line) => `${path}${line.slice(3)}`);
}

function requiredString(value: string, field: string) {
  const normalized = value.trim();
  if (!normalized) throw new TypeError(`${field} must not be empty`);
  return normalized;
}

function exactOrigin(value: string, field: string) {
  const normalized = requiredString(value, field);
  const parsed = new URL(normalized);
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    parsed.origin !== normalized
  ) {
    throw new TypeError(`${field} must be an exact HTTP(S) origin`);
  }
  return normalized;
}

function origin(value: unknown, path: string, errors: string[]) {
  if (typeof value !== "string") {
    errors.push(`${path} must be an exact HTTP(S) origin`);
    return;
  }
  try {
    const parsed = new URL(value);
    if (
      (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
      parsed.origin !== value
    ) {
      errors.push(`${path} must be an exact HTTP(S) origin`);
    }
  } catch {
    errors.push(`${path} must be an exact HTTP(S) origin`);
  }
}
