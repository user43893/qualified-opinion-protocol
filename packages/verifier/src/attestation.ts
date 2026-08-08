import { X509Certificate, createVerify, timingSafeEqual } from "node:crypto";
import {
  type QuestionVotingAuthorizationPayloadV3,
  base64UrlDecode,
  canonicalJsonSha256,
  utf8Decode,
} from "@qualified-opinion/protocol";
import { GOOGLE_CONFIDENTIAL_SPACE_ISSUER } from "./gcs";
import {
  type EmailVerificationReceiptPayload,
  emailVerificationPayloadHash,
} from "./identity-receipt";
import {
  type IdentityAttestationPolicyV3,
  normalizeCertificateFingerprint,
} from "./policy";

export type OfflineAttestationVerification = {
  audience: string;
  certificateRootSha256: string;
  debugStatus: string;
  imageDigest: string;
  issuedAt: string;
  projectId: string;
  serviceAccounts: string[];
  subject: string | null;
};

export type ParsedAttestationJwt = {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: Uint8Array;
  signingInput: string;
};

export function attestationIssuedAt(token: string) {
  const { payload } = parseAttestationJwt(token);
  const issuedAt = integerClaim(payload.iat, "iat");
  return new Date(issuedAt * 1000);
}

/**
 * Fully offline Google Confidential Space PKI verification. It never falls
 * back to Google's network JWKS endpoint: an x5c chain rooted in the static
 * independently obtained policy is mandatory.
 */
export async function verifyConfidentialSpacePkiAttestation(input: {
  token: string;
  identityPayload: EmailVerificationReceiptPayload;
  policy: IdentityAttestationPolicyV3;
}): Promise<OfflineAttestationVerification> {
  return verifyConfidentialSpacePkiAttestationClaims({
    token: input.token,
    expectedNonce: await emailVerificationPayloadHash(input.identityPayload),
    referenceTime: input.identityPayload.verifiedAt,
    policy: input.policy,
  });
}

/**
 * Verifies the question-scoped V3 authorization token against the same
 * independently pinned Confidential Space workload policy used for the
 * registration verifier. The authorization payload hash is the attestation
 * nonce, so the token binds the public question key, nullifier, eligibility
 * class, protocol policy, and validity window without publishing identity.
 */
export async function verifyQuestionVotingAuthorizationPkiAttestation(input: {
  token: string;
  payload: QuestionVotingAuthorizationPayloadV3;
  payloadSha256: string;
  policy: IdentityAttestationPolicyV3;
}): Promise<OfflineAttestationVerification> {
  if (input.payload.issuerAttestation.audience !== input.policy.audience) {
    throw new Error("unexpected_attestation_audience_policy");
  }
  if ((await canonicalJsonSha256(input.payload)) !== input.payloadSha256) {
    throw new Error("question_authorization_payload_hash_mismatch");
  }
  return verifyConfidentialSpacePkiAttestationClaims({
    token: input.token,
    expectedNonce: input.payloadSha256,
    referenceTime: input.payload.issuedAt,
    policy: input.policy,
  });
}

function verifyConfidentialSpacePkiAttestationClaims(input: {
  token: string;
  expectedNonce: string;
  referenceTime: string;
  policy: IdentityAttestationPolicyV3;
}): OfflineAttestationVerification {
  const { header, payload, signature, signingInput } = parseAttestationJwt(input.token);
  if (header.alg !== "RS256") throw new Error("unsupported_attestation_algorithm");
  if (payload.iss !== GOOGLE_CONFIDENTIAL_SPACE_ISSUER) {
    throw new Error("unexpected_attestation_issuer");
  }
  const audience = stringArrayClaim(payload.aud, "aud");
  if (!audience.includes(input.policy.audience)) {
    throw new Error("unexpected_attestation_audience");
  }

  const certificates = certificateChain(header.x5c);
  const [leaf, intermediate, root] = certificates;
  if (!leaf || !intermediate || !root) {
    throw new Error("invalid_attestation_certificate_chain");
  }
  const rootFingerprint = normalizeCertificateFingerprint(root.fingerprint256);
  if (!input.policy.trustedRootCertificateSha256.includes(rootFingerprint)) {
    throw new Error("unexpected_attestation_root_certificate");
  }
  if (
    !root.ca ||
    !intermediate.ca ||
    leaf.ca ||
    !root.verify(root.publicKey) ||
    !intermediate.checkIssued(root) ||
    !intermediate.verify(root.publicKey) ||
    !leaf.checkIssued(intermediate) ||
    !leaf.verify(intermediate.publicKey)
  ) {
    throw new Error("invalid_attestation_certificate_chain");
  }
  const verifier = createVerify("RSA-SHA256");
  verifier.update(signingInput);
  verifier.end();
  if (!verifier.verify(leaf.publicKey, signature)) {
    throw new Error("invalid_attestation_signature");
  }

  const issuedAtSeconds = integerClaim(payload.iat, "iat");
  const notBeforeSeconds = integerClaim(payload.nbf, "nbf");
  const expiresSeconds = integerClaim(payload.exp, "exp");
  if (
    expiresSeconds < issuedAtSeconds ||
    notBeforeSeconds > issuedAtSeconds + 60 ||
    issuedAtSeconds - notBeforeSeconds > 2 * 60 * 60 ||
    expiresSeconds - issuedAtSeconds > 2 * 60 * 60
  ) {
    throw new Error("invalid_attestation_time_claims");
  }
  const issuedAt = new Date(issuedAtSeconds * 1000);
  for (const certificate of certificates) {
    if (
      issuedAt < new Date(certificate.validFrom) ||
      issuedAt > new Date(certificate.validTo)
    ) {
      throw new Error("attestation_certificate_not_valid_at_issuance");
    }
  }
  const verifiedAt = Date.parse(input.referenceTime);
  if (
    !Number.isFinite(verifiedAt) ||
    issuedAt.getTime() < verifiedAt - 60_000 ||
    issuedAt.getTime() > verifiedAt + 20 * 60_000
  ) {
    throw new Error("identity_attestation_time_mismatch");
  }

  const nonces = stringArrayClaim(payload.eat_nonce, "eat_nonce");
  if (!nonces.some((nonce) => safeTextEqual(nonce, input.expectedNonce))) {
    throw new Error("attestation_nonce_mismatch");
  }
  if (payload.swname !== "CONFIDENTIAL_SPACE") {
    throw new Error("not_confidential_space");
  }
  const debugStatus = stringClaim(payload.dbgstat, "dbgstat");
  if (!input.policy.debugAllowed && debugStatus !== "disabled-since-boot") {
    throw new Error("attestation_debug_enabled");
  }

  const submods = objectClaim(payload.submods, "submods");
  const container = objectClaim(submods.container, "submods.container");
  const gce = objectClaim(submods.gce, "submods.gce");
  const confidentialSpace = objectClaim(
    submods.confidential_space,
    "submods.confidential_space",
  );
  const imageDigest = stringClaim(container.image_digest, "image_digest");
  const projectId = stringClaim(gce.project_id, "project_id");
  const serviceAccounts = stringArrayClaim(
    payload.google_service_accounts,
    "google_service_accounts",
  );
  if (imageDigest !== input.policy.imageDigest) {
    throw new Error("unexpected_attestation_image_digest");
  }
  if (projectId !== input.policy.projectId) {
    throw new Error("unexpected_attestation_project");
  }
  if (!serviceAccounts.includes(input.policy.serviceAccount)) {
    throw new Error("unexpected_attestation_service_account");
  }
  verifyExpectedEnvironment(
    container,
    input.policy.expectedEnvironment,
    input.policy.requireExactEnvironment,
  );
  if (
    input.policy.stable &&
    !stringArrayClaim(
      confidentialSpace.support_attributes,
      "support_attributes",
    ).includes("STABLE")
  ) {
    throw new Error("attestation_image_not_stable");
  }
  if (input.policy.memoryMonitoringDisabled) {
    const monitoring = objectClaim(
      confidentialSpace.monitoring_enabled,
      "monitoring_enabled",
    );
    if (monitoring.memory !== false) {
      throw new Error("attestation_memory_monitoring_enabled");
    }
  }

  return {
    audience: input.policy.audience,
    certificateRootSha256: rootFingerprint,
    debugStatus,
    imageDigest,
    issuedAt: issuedAt.toISOString(),
    projectId,
    serviceAccounts,
    subject: typeof payload.sub === "string" ? payload.sub : null,
  };
}

export function parseAttestationJwt(token: string): ParsedAttestationJwt {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("invalid_attestation_token");
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  if (!encodedHeader || !encodedPayload || !encodedSignature) {
    throw new Error("invalid_attestation_token");
  }
  try {
    const header = JSON.parse(utf8Decode(base64UrlDecode(encodedHeader))) as Record<
      string,
      unknown
    >;
    const payload = JSON.parse(utf8Decode(base64UrlDecode(encodedPayload))) as Record<
      string,
      unknown
    >;
    return {
      header,
      payload,
      signature: Buffer.from(base64UrlDecode(encodedSignature)),
      signingInput: `${encodedHeader}.${encodedPayload}`,
    };
  } catch (error) {
    if (error instanceof Error && error.message === "invalid_attestation_token") {
      throw error;
    }
    throw new Error("invalid_attestation_token");
  }
}

function certificateChain(value: unknown) {
  if (
    !Array.isArray(value) ||
    value.length !== 3 ||
    value.some((certificate) => typeof certificate !== "string")
  ) {
    throw new Error("pki_attestation_required");
  }
  try {
    return value.map(
      (certificate) =>
        new X509Certificate(Buffer.from(certificate as string, "base64")),
    );
  } catch {
    throw new Error("invalid_attestation_certificate_chain");
  }
}

function verifyExpectedEnvironment(
  container: Record<string, unknown>,
  expected: Record<string, string>,
  requireExact: boolean,
) {
  const imageEnvironment = environmentObjectClaim(container.env, "env");
  const environmentOverride = environmentObjectClaim(
    container.env_override,
    "env_override",
  );
  for (const [name, value] of Object.entries(expected)) {
    const effectiveValue = Object.hasOwn(environmentOverride, name)
      ? environmentOverride[name]
      : imageEnvironment[name];
    if (effectiveValue !== value) {
      throw new Error(`unexpected_attestation_environment:${name}`);
    }
  }
  if (requireExact) {
    // container.env also contains image/base-runtime values. The exact
    // digest-bound tee.launch_policy.allow_env_override label is verified by
    // the release boundary to equal the expected names, so only unexpected
    // operator overrides are rejected here.
    if (
      Object.keys(environmentOverride).some((name) => !Object.hasOwn(expected, name))
    ) {
      throw new Error("unexpected_attestation_environment_keys");
    }
  }
}

function environmentObjectClaim(value: unknown, name: string) {
  if (value === undefined) return {};
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`invalid_attestation_environment_claim:${name}`);
  }
  return value as Record<string, unknown>;
}

function integerClaim(value: unknown, name: string) {
  if (!Number.isSafeInteger(value)) {
    throw new Error(`invalid_attestation_claim:${name}`);
  }
  return value as number;
}

function stringClaim(value: unknown, name: string) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`invalid_attestation_claim:${name}`);
  }
  return value;
}

function stringArrayClaim(value: unknown, name: string) {
  const array = typeof value === "string" ? [value] : value;
  if (
    !Array.isArray(array) ||
    array.length < 1 ||
    array.some((item) => typeof item !== "string" || item.length === 0)
  ) {
    throw new Error(`invalid_attestation_claim:${name}`);
  }
  return array as string[];
}

function objectClaim(value: unknown, name: string) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`invalid_attestation_claim:${name}`);
  }
  return value as Record<string, unknown>;
}

function safeTextEqual(left: string, right: string) {
  const leftBytes = Buffer.from(left, "utf8");
  const rightBytes = Buffer.from(right, "utf8");
  return (
    leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes)
  );
}
