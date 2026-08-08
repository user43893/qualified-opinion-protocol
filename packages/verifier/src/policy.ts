import { createPublicKey } from "node:crypto";
import {
  VOTE_EVENT_SCHEMA_V3,
  base64UrlDecode,
  canonicalizeJson,
  sha256Hex,
} from "@qualified-opinion/protocol";
import {
  GOOGLE_CONFIDENTIAL_SPACE_ISSUER,
  GOOGLE_CONFIDENTIAL_SPACE_PKI_ROOT_SHA256,
} from "./gcs";

export const OFFLINE_VERIFICATION_POLICY_SCHEMA_V3 =
  "qualified-opinion.vote-proof-verification-policy.v3" as const;

export type PolicyWindow = {
  validFrom: string;
  validUntil: string | null;
};

export type IdentityAttestationPolicyV3 = PolicyWindow & {
  audience: string;
  debugAllowed: false;
  expectedEnvironment: Record<string, string>;
  imageDigest: string;
  issuer: typeof GOOGLE_CONFIDENTIAL_SPACE_ISSUER;
  memoryMonitoringDisabled: true;
  projectId: string;
  requireExactEnvironment: true;
  serviceAccount: string;
  stable: true;
  trustedRootCertificateSha256: [string];
  webauthnOrigin: string;
  webauthnRpId: string;
};

export type ServerVerificationKeyV3 = PolicyWindow & {
  algorithm: "Ed25519";
  keyId: string;
  publicKeySpki: string;
  purpose: "eligibility" | "receipt";
};

export type VotingPolicyV3 = PolicyWindow & {
  protocolBindingSha256: string;
  protocolVersion: typeof VOTE_EVENT_SCHEMA_V3;
  transparencyLogId: string;
  voteServiceAudience: string;
};

export type OfflineVerificationPolicyV3 = {
  schemaVersion: typeof OFFLINE_VERIFICATION_POLICY_SCHEMA_V3;
  policyId: string;
  identityAttestationPolicies: IdentityAttestationPolicyV3[];
  serverKeys: ServerVerificationKeyV3[];
  votingPolicies: VotingPolicyV3[];
};

export async function verificationPolicySha256(value: unknown) {
  return sha256Hex(canonicalizeJson(value));
}

export function parseVerificationPolicy(value: unknown): OfflineVerificationPolicyV3 {
  const object = record(value, "policy");
  exactKeys(
    object,
    [
      "schemaVersion",
      "policyId",
      "identityAttestationPolicies",
      "serverKeys",
      "votingPolicies",
    ],
    "policy",
  );
  if (object.schemaVersion !== OFFLINE_VERIFICATION_POLICY_SCHEMA_V3) {
    throw new Error("unsupported_verification_policy_schema");
  }
  const policy: OfflineVerificationPolicyV3 = {
    schemaVersion: OFFLINE_VERIFICATION_POLICY_SCHEMA_V3,
    policyId: nonEmptyString(object.policyId, "policy.policyId"),
    identityAttestationPolicies: nonEmptyArray(
      object.identityAttestationPolicies,
      "policy.identityAttestationPolicies",
    ).map((entry, index) =>
      parseIdentityPolicy(entry, `policy.identityAttestationPolicies[${index}]`),
    ),
    serverKeys: nonEmptyArray(object.serverKeys, "policy.serverKeys").map(
      (entry, index) => parseServerKey(entry, `policy.serverKeys[${index}]`),
    ),
    votingPolicies: nonEmptyArray(object.votingPolicies, "policy.votingPolicies").map(
      (entry, index) => parseVotingPolicy(entry, `policy.votingPolicies[${index}]`),
    ),
  };
  validatePolicySemantics(policy);
  return policy;
}

export function selectIdentityPolicy(
  policy: OfflineVerificationPolicyV3,
  time: Date | string,
) {
  return selectWindow(
    policy.identityAttestationPolicies,
    time,
    "identity_attestation_policy",
  );
}

/**
 * An image rotation may make several policies valid at the same instant.
 * Callers must verify the token against every candidate and require exactly
 * one match.
 */
export function selectIdentityPolicyCandidates(
  policy: OfflineVerificationPolicyV3,
  time: Date | string,
) {
  return policy.identityAttestationPolicies.filter((candidate) =>
    containsTime(candidate, time),
  );
}

export function selectVotingPolicy(
  policy: OfflineVerificationPolicyV3,
  time: Date | string,
) {
  return selectWindow(policy.votingPolicies, time, "voting_policy");
}

export function selectVotingPolicyCandidates(
  policy: OfflineVerificationPolicyV3,
  time: Date | string,
) {
  return policy.votingPolicies.filter((candidate) => containsTime(candidate, time));
}

export function selectVotingPolicyForBinding(
  policy: OfflineVerificationPolicyV3,
  input: {
    protocolBindingSha256: string | null;
    protocolVersion: string;
    time: Date | string;
  },
) {
  const matches = selectVotingPolicyCandidates(policy, input.time).filter(
    (candidate) =>
      candidate.protocolVersion === input.protocolVersion &&
      candidate.protocolBindingSha256 === input.protocolBindingSha256,
  );
  if (matches.length !== 1) {
    throw new Error(
      matches.length === 0 ? "voting_policy_not_found" : "voting_policy_ambiguous",
    );
  }
  return matches[0] as VotingPolicyV3;
}

export function selectServerKey(
  policy: OfflineVerificationPolicyV3,
  input: {
    keyId: string;
    purpose: ServerVerificationKeyV3["purpose"];
    time: Date | string;
  },
) {
  const matches = policy.serverKeys.filter(
    (key) =>
      key.keyId === input.keyId &&
      key.purpose === input.purpose &&
      containsTime(key, input.time),
  );
  if (matches.length !== 1) {
    throw new Error(
      matches.length === 0
        ? `untrusted_${input.purpose}_key:${input.keyId}`
        : `ambiguous_${input.purpose}_key:${input.keyId}`,
    );
  }
  return matches[0] as ServerVerificationKeyV3;
}

export function containsTime(window: PolicyWindow, time: Date | string) {
  const timestamp = toTime(time, "artifact_time");
  const from = toTime(window.validFrom, "validFrom");
  const until = window.validUntil
    ? toTime(window.validUntil, "validUntil")
    : Number.POSITIVE_INFINITY;
  return timestamp >= from && timestamp < until;
}

export function normalizeCertificateFingerprint(value: string) {
  const hex = value.replaceAll(":", "").toUpperCase();
  if (!/^[0-9A-F]{64}$/.test(hex)) {
    throw new Error("invalid_certificate_fingerprint");
  }
  return hex.match(/.{2}/g)?.join(":") ?? "";
}

function parseIdentityPolicy(
  value: unknown,
  path: string,
): IdentityAttestationPolicyV3 {
  const object = record(value, path);
  exactKeys(
    object,
    [
      "audience",
      "debugAllowed",
      "expectedEnvironment",
      "imageDigest",
      "issuer",
      "memoryMonitoringDisabled",
      "projectId",
      "requireExactEnvironment",
      "serviceAccount",
      "stable",
      "trustedRootCertificateSha256",
      "validFrom",
      "validUntil",
      "webauthnOrigin",
      "webauthnRpId",
    ],
    path,
  );
  if (object.issuer !== GOOGLE_CONFIDENTIAL_SPACE_ISSUER) {
    throw new Error(`${path}.issuer must be Google Confidential Space`);
  }
  if (object.debugAllowed !== false) {
    throw new Error(`${path}.debugAllowed must be false`);
  }
  if (object.memoryMonitoringDisabled !== true) {
    throw new Error(`${path}.memoryMonitoringDisabled must be true`);
  }
  if (object.requireExactEnvironment !== true) {
    throw new Error(`${path}.requireExactEnvironment must be true`);
  }
  if (object.stable !== true) {
    throw new Error(`${path}.stable must be true`);
  }
  const roots = nonEmptyArray(
    object.trustedRootCertificateSha256,
    `${path}.trustedRootCertificateSha256`,
  ).map((entry) =>
    normalizeCertificateFingerprint(
      nonEmptyString(entry, `${path}.trustedRootCertificateSha256[]`),
    ),
  );
  if (roots.length !== 1) {
    throw new Error(`${path} must pin exactly one PKI root`);
  }
  const expectedEnvironment = stringRecord(
    object.expectedEnvironment,
    `${path}.expectedEnvironment`,
  );
  if (Object.keys(expectedEnvironment).length === 0) {
    throw new Error(`${path}.expectedEnvironment must not be empty`);
  }
  const imageDigest = nonEmptyString(object.imageDigest, `${path}.imageDigest`);
  if (!/^sha256:[0-9a-f]{64}$/.test(imageDigest)) {
    throw new Error(`${path}.imageDigest must be an immutable SHA-256 digest`);
  }
  const webauthnOrigin = httpsOrigin(object.webauthnOrigin, `${path}.webauthnOrigin`);
  const webauthnRpId = hostname(object.webauthnRpId, `${path}.webauthnRpId`);
  if (new URL(webauthnOrigin).hostname !== webauthnRpId) {
    throw new Error(`${path} WebAuthn origin and RP ID do not match`);
  }
  return {
    ...parseWindow(object, path),
    audience: nonEmptyString(object.audience, `${path}.audience`),
    debugAllowed: false,
    expectedEnvironment,
    imageDigest,
    issuer: GOOGLE_CONFIDENTIAL_SPACE_ISSUER,
    memoryMonitoringDisabled: true,
    projectId: nonEmptyString(object.projectId, `${path}.projectId`),
    requireExactEnvironment: true,
    serviceAccount: serviceAccount(object.serviceAccount, `${path}.serviceAccount`),
    stable: true,
    trustedRootCertificateSha256: [roots[0] as string],
    webauthnOrigin,
    webauthnRpId,
  };
}

function parseServerKey(value: unknown, path: string): ServerVerificationKeyV3 {
  const object = record(value, path);
  exactKeys(
    object,
    ["algorithm", "keyId", "publicKeySpki", "purpose", "validFrom", "validUntil"],
    path,
  );
  if (object.algorithm !== "Ed25519") {
    throw new Error(`${path}.algorithm must be Ed25519`);
  }
  if (object.purpose !== "eligibility" && object.purpose !== "receipt") {
    throw new Error(`${path}.purpose is invalid`);
  }
  const publicKeySpki = nonEmptyString(object.publicKeySpki, `${path}.publicKeySpki`);
  try {
    const key = createPublicKey({
      key: Buffer.from(base64UrlDecode(publicKeySpki)),
      format: "der",
      type: "spki",
    });
    if (key.asymmetricKeyType !== "ed25519") throw new Error("wrong key type");
  } catch {
    throw new Error(`${path}.publicKeySpki is not an Ed25519 SPKI key`);
  }
  return {
    ...parseWindow(object, path),
    algorithm: "Ed25519",
    keyId: nonEmptyString(object.keyId, `${path}.keyId`),
    publicKeySpki,
    purpose: object.purpose,
  };
}

function parseVotingPolicy(value: unknown, path: string): VotingPolicyV3 {
  const object = record(value, path);
  exactKeys(
    object,
    [
      "protocolBindingSha256",
      "protocolVersion",
      "transparencyLogId",
      "validFrom",
      "validUntil",
      "voteServiceAudience",
    ],
    path,
  );
  if (object.protocolVersion !== VOTE_EVENT_SCHEMA_V3) {
    throw new Error(`${path}.protocolVersion must identify the current V3 protocol`);
  }
  return {
    ...parseWindow(object, path),
    protocolBindingSha256: sha256Base64UrlString(
      object.protocolBindingSha256,
      `${path}.protocolBindingSha256`,
    ),
    protocolVersion: VOTE_EVENT_SCHEMA_V3,
    transparencyLogId: nonEmptyString(
      object.transparencyLogId,
      `${path}.transparencyLogId`,
    ),
    voteServiceAudience: nonEmptyString(
      object.voteServiceAudience,
      `${path}.voteServiceAudience`,
    ),
  };
}

function validatePolicySemantics(policy: OfflineVerificationPolicyV3) {
  if (
    policy.identityAttestationPolicies.length < 1 ||
    policy.serverKeys.length < 2 ||
    policy.votingPolicies.length < 1
  ) {
    throw new Error("verification_policy_is_incomplete");
  }
  const identitiesByImage = new Map<string, IdentityAttestationPolicyV3[]>();
  for (const identity of policy.identityAttestationPolicies) {
    const existing = identitiesByImage.get(identity.imageDigest) ?? [];
    existing.push(identity);
    identitiesByImage.set(identity.imageDigest, existing);
  }
  for (const identities of identitiesByImage.values()) {
    ensureNoOverlappingWindows(identities, "identity_attestation_policy");
  }

  const votingByBinding = new Map<string, VotingPolicyV3[]>();
  for (const voting of policy.votingPolicies) {
    const identity = `${voting.protocolVersion}:${voting.protocolBindingSha256}`;
    const existing = votingByBinding.get(identity) ?? [];
    existing.push(voting);
    votingByBinding.set(identity, existing);
  }
  for (const policies of votingByBinding.values()) {
    ensureNoOverlappingWindows(policies, "voting_policy");
  }

  const keysById = new Map<string, ServerVerificationKeyV3[]>();
  for (const key of policy.serverKeys) {
    const identity = `${key.purpose}:${key.keyId}`;
    const existing = keysById.get(identity) ?? [];
    if (existing.some((candidate) => candidate.publicKeySpki !== key.publicKeySpki)) {
      throw new Error(`server_key_id_collision:${identity}`);
    }
    existing.push(key);
    keysById.set(identity, existing);
  }
  for (const [identity, keys] of keysById) {
    ensureNoOverlappingWindows(keys, `server_key:${identity}`);
  }
  for (const purpose of ["eligibility", "receipt"] as const) {
    if (!policy.serverKeys.some((key) => key.purpose === purpose)) {
      throw new Error(`missing_${purpose}_verification_key`);
    }
  }
}

function ensureNoOverlappingWindows(windows: PolicyWindow[], label: string) {
  const ordered = [...windows].sort(
    (left, right) =>
      toTime(left.validFrom, "validFrom") - toTime(right.validFrom, "validFrom"),
  );
  for (let index = 1; index < ordered.length; index += 1) {
    const previousWindow = ordered[index - 1];
    const currentWindow = ordered[index];
    if (
      previousWindow &&
      currentWindow &&
      (previousWindow.validUntil === null ||
        toTime(previousWindow.validUntil, "validUntil") >
          toTime(currentWindow.validFrom, "validFrom"))
    ) {
      throw new Error(`overlapping_${label}_windows`);
    }
  }
}

function selectWindow<T extends PolicyWindow>(
  windows: T[],
  time: Date | string,
  label: string,
) {
  const matches = windows.filter((window) => containsTime(window, time));
  if (matches.length !== 1) {
    throw new Error(matches.length === 0 ? `${label}_not_found` : `${label}_ambiguous`);
  }
  return matches[0] as T;
}

function parseWindow(object: Record<string, unknown>, path: string): PolicyWindow {
  const validFrom = timestamp(object.validFrom, `${path}.validFrom`);
  const validUntil =
    object.validUntil === null
      ? null
      : timestamp(object.validUntil, `${path}.validUntil`);
  if (
    validUntil &&
    toTime(validUntil, "validUntil") <= toTime(validFrom, "validFrom")
  ) {
    throw new Error(`${path} has an invalid validity window`);
  }
  return { validFrom, validUntil };
}

function record(value: unknown, path: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${path} must be an object`);
  }
  return value as Record<string, unknown>;
}

function nonEmptyArray(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${path} must be a non-empty array`);
  }
  return value;
}

function exactKeys(value: Record<string, unknown>, keys: string[], path: string) {
  const expected = new Set(keys);
  for (const key of Object.keys(value)) {
    if (!expected.has(key)) throw new Error(`${path}.${key} is not allowed`);
  }
  for (const key of expected) {
    if (!(key in value)) throw new Error(`${path}.${key} is required`);
  }
}

function nonEmptyString(value: unknown, path: string) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${path} must be a non-empty string`);
  }
  return value;
}

function sha256Base64UrlString(value: unknown, path: string) {
  const result = nonEmptyString(value, path);
  if (!/^[A-Za-z0-9_-]{43}$/.test(result)) {
    throw new Error(`${path} must be a base64url SHA-256 digest`);
  }
  return result;
}

function timestamp(value: unknown, path: string) {
  const text = nonEmptyString(value, path);
  const parsed = Date.parse(text);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== text) {
    throw new Error(`${path} must be a canonical ISO-8601 timestamp`);
  }
  return text;
}

function httpsOrigin(value: unknown, path: string) {
  const text = nonEmptyString(value, path);
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    throw new Error(`${path} must be an HTTPS origin`);
  }
  if (
    url.protocol !== "https:" ||
    url.origin !== text ||
    url.username ||
    url.password
  ) {
    throw new Error(`${path} must be an HTTPS origin`);
  }
  return text;
}

function hostname(value: unknown, path: string) {
  const text = nonEmptyString(value, path);
  if (
    text !== text.toLowerCase() ||
    text.includes("/") ||
    text.includes(":") ||
    text.includes(" ")
  ) {
    throw new Error(`${path} must be a hostname`);
  }
  return text;
}

function serviceAccount(value: unknown, path: string) {
  const text = nonEmptyString(value, path);
  if (!/^[^@\s]+@[^@\s]+\.iam\.gserviceaccount\.com$/.test(text)) {
    throw new Error(`${path} must be a Google service-account email`);
  }
  return text;
}

function stringRecord(value: unknown, path: string) {
  const object = record(value, path);
  const output: Record<string, string> = {};
  for (const [key, child] of Object.entries(object)) {
    if (!key || typeof child !== "string") {
      throw new Error(`${path} must contain only string values`);
    }
    output[key] = child;
  }
  return output;
}

function toTime(value: Date | string, path: string) {
  const time = value instanceof Date ? value.getTime() : Date.parse(value);
  if (!Number.isFinite(time)) throw new Error(`${path} is invalid`);
  return time;
}
