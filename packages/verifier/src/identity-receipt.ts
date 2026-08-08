import { createHash } from "node:crypto";

export const EMAIL_VERIFICATION_RECEIPT_SCHEMA_V3 =
  "qualified-opinion.email-control-passkey.v3";
export const EMAIL_VERIFICATION_RESULT = "email_control_verified";
export const EMAIL_VERIFICATION_METHOD = "one_time_email_code";
export const EMAIL_VERIFICATION_PASSKEY_ALGORITHM = "ES256";

export type EmailVerificationPasskeyProofOfPossessionV3 = {
  registration: {
    challenge: string;
    clientDataJson: string;
    attestationObject: string;
  };
  assertion: {
    challenge: string;
    clientDataJson: string;
    authenticatorData: string;
    signature: string;
    userHandle: string | null;
  };
};

export type EmailVerificationPasskeyBindingV3 = {
  credentialId: string;
  publicKeySpki: string;
  algorithm: typeof EMAIL_VERIFICATION_PASSKEY_ALGORITHM;
  rpId: string;
  origin: string;
  signCount: number;
  transports: string[];
  userHandle: string;
  proofOfPossession: EmailVerificationPasskeyProofOfPossessionV3;
};

export type EmailVerificationReceiptPayloadV3 = {
  schema: typeof EMAIL_VERIFICATION_RECEIPT_SCHEMA_V3;
  result: typeof EMAIL_VERIFICATION_RESULT;
  requestId: string;
  claimedFullName: string;
  claimedEmail: string;
  normalizedEmail: string;
  verificationMethod: typeof EMAIL_VERIFICATION_METHOD;
  verifiedAt: string;
  verifierVersion: string;
  passkey: EmailVerificationPasskeyBindingV3;
  limitations: string[];
};

export type EmailVerificationReceiptPayload = EmailVerificationReceiptPayloadV3;

export type EmailVerificationReceipt = {
  payload: EmailVerificationReceiptPayload;
  attestationToken: string;
};

const EMAIL_VERIFICATION_RECEIPT_KEYS = ["attestationToken", "payload"] as const;
const EMAIL_VERIFICATION_PAYLOAD_KEYS = [
  "claimedEmail",
  "claimedFullName",
  "limitations",
  "normalizedEmail",
  "passkey",
  "requestId",
  "result",
  "schema",
  "verificationMethod",
  "verifiedAt",
  "verifierVersion",
] as const;
const EMAIL_VERIFICATION_PASSKEY_KEYS = [
  "algorithm",
  "credentialId",
  "origin",
  "proofOfPossession",
  "publicKeySpki",
  "rpId",
  "signCount",
  "transports",
  "userHandle",
] as const;
const EMAIL_VERIFICATION_PROOF_OF_POSSESSION_KEYS = [
  "assertion",
  "registration",
] as const;
const EMAIL_VERIFICATION_REGISTRATION_KEYS = [
  "attestationObject",
  "challenge",
  "clientDataJson",
] as const;
const EMAIL_VERIFICATION_ASSERTION_KEYS = [
  "authenticatorData",
  "challenge",
  "clientDataJson",
  "signature",
  "userHandle",
] as const;

export function normalizeVerifiedEmail(value: string) {
  return value.trim().toLowerCase();
}

export function normalizeVerifiedFullName(value: string) {
  return value.trim().replace(/\s+/g, " ");
}

export function isValidVerifiedEmail(value: string) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizeVerifiedEmail(value));
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortJsonValue(value));
}

function sortJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortJsonValue);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, child]) => child !== undefined)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, child]) => [key, sortJsonValue(child)]),
    );
  }
  return value;
}

export function sha256Hex(value: string | Uint8Array) {
  return createHash("sha256").update(value).digest("hex");
}

export function emailVerificationPayloadHash(payload: EmailVerificationReceiptPayload) {
  return sha256Hex(canonicalJson(payload));
}

export function createEmailVerificationReceiptPayloadV3(input: {
  claimedEmail: string;
  claimedFullName: string;
  passkey: EmailVerificationPasskeyBindingV3;
  requestId: string;
  verifiedAt: Date | string;
  verifierVersion: string;
}): EmailVerificationReceiptPayloadV3 {
  const claimedFullName = normalizeVerifiedFullName(input.claimedFullName);
  const claimedEmail = input.claimedEmail.trim();
  const normalizedEmail = normalizeVerifiedEmail(claimedEmail);
  const verifiedAt =
    input.verifiedAt instanceof Date
      ? input.verifiedAt.toISOString()
      : input.verifiedAt;

  return {
    schema: EMAIL_VERIFICATION_RECEIPT_SCHEMA_V3,
    result: EMAIL_VERIFICATION_RESULT,
    requestId: input.requestId,
    claimedFullName,
    claimedEmail,
    normalizedEmail,
    verificationMethod: EMAIL_VERIFICATION_METHOD,
    verifiedAt,
    verifierVersion: input.verifierVersion,
    passkey: input.passkey,
    limitations: [
      "This receipt proves that the one-time code sent to the claimed email address was presented to the attested workload during this verification transaction.",
      "This receipt binds that code-verification result to the included passkey public key after a WebAuthn registration and proof-of-possession assertion.",
      "This receipt does not prove exclusive or continuing control of the mailbox; the email-delivery provider and mailbox security remain trust assumptions.",
      "This receipt does not prove that the email appears in an external qualification registry.",
      "This receipt does not prove that the claimant and the registry-record person are the same person.",
    ],
  };
}

export function isEmailVerificationReceiptPayload(
  value: unknown,
): value is EmailVerificationReceiptPayload {
  if (!hasExactKeys(value, EMAIL_VERIFICATION_PAYLOAD_KEYS)) {
    return false;
  }
  const payload = value as Partial<EmailVerificationReceiptPayload>;
  const commonFieldsAreValid =
    payload.result === EMAIL_VERIFICATION_RESULT &&
    payload.verificationMethod === EMAIL_VERIFICATION_METHOD &&
    typeof payload.requestId === "string" &&
    typeof payload.claimedFullName === "string" &&
    typeof payload.claimedEmail === "string" &&
    typeof payload.normalizedEmail === "string" &&
    typeof payload.verifiedAt === "string" &&
    typeof payload.verifierVersion === "string" &&
    Array.isArray(payload.limitations) &&
    payload.limitations.every((limitation) => typeof limitation === "string");
  if (!commonFieldsAreValid) {
    return false;
  }
  return (
    payload.schema === EMAIL_VERIFICATION_RECEIPT_SCHEMA_V3 &&
    isEmailVerificationPasskeyBinding(payload.passkey)
  );
}

function isEmailVerificationPasskeyBinding(
  value: unknown,
): value is EmailVerificationPasskeyBindingV3 {
  if (!hasExactKeys(value, EMAIL_VERIFICATION_PASSKEY_KEYS)) {
    return false;
  }
  const passkey = value as Partial<EmailVerificationPasskeyBindingV3>;
  const proof = passkey.proofOfPossession;
  if (!hasExactKeys(proof, EMAIL_VERIFICATION_PROOF_OF_POSSESSION_KEYS)) {
    return false;
  }
  const registration = proof.registration;
  const assertion = proof.assertion;
  return (
    isBase64Url(passkey.credentialId) &&
    isBase64Url(passkey.publicKeySpki) &&
    passkey.algorithm === EMAIL_VERIFICATION_PASSKEY_ALGORITHM &&
    typeof passkey.rpId === "string" &&
    passkey.rpId.length > 0 &&
    isPasskeyOriginForRpId(passkey.origin, passkey.rpId) &&
    Number.isSafeInteger(passkey.signCount) &&
    (passkey.signCount ?? -1) >= 0 &&
    Array.isArray(passkey.transports) &&
    passkey.transports.every((transport) => typeof transport === "string") &&
    isBase64Url(passkey.userHandle) &&
    hasExactKeys(registration, EMAIL_VERIFICATION_REGISTRATION_KEYS) &&
    isBase64Url(registration.challenge) &&
    isBase64Url(registration.clientDataJson) &&
    isBase64Url(registration.attestationObject) &&
    hasExactKeys(assertion, EMAIL_VERIFICATION_ASSERTION_KEYS) &&
    isBase64Url(assertion.challenge) &&
    isBase64Url(assertion.clientDataJson) &&
    isBase64Url(assertion.authenticatorData) &&
    isBase64Url(assertion.signature) &&
    (assertion.userHandle === null || isBase64Url(assertion.userHandle))
  );
}

export function isEmailVerificationReceipt(
  value: unknown,
): value is EmailVerificationReceipt {
  if (!hasExactKeys(value, EMAIL_VERIFICATION_RECEIPT_KEYS)) {
    return false;
  }
  return (
    typeof value.attestationToken === "string" &&
    value.attestationToken.length > 0 &&
    isEmailVerificationReceiptPayload(value.payload)
  );
}

function hasExactKeys<const TKeys extends readonly string[]>(
  value: unknown,
  expectedKeys: TKeys,
): value is Record<TKeys[number], unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const actualKeys = Object.keys(value).sort();
  return (
    actualKeys.length === expectedKeys.length &&
    expectedKeys.every((key, index) => actualKeys[index] === key)
  );
}

function isBase64Url(value: unknown): value is string {
  return (
    typeof value === "string" && value.length > 0 && /^[A-Za-z0-9_-]+$/.test(value)
  );
}

function isPasskeyOriginForRpId(value: unknown, rpId: string): value is string {
  if (typeof value !== "string") {
    return false;
  }
  try {
    const url = new URL(value);
    return (
      url.origin === value &&
      url.hostname === rpId &&
      (url.protocol === "https:" ||
        (url.protocol === "http:" &&
          (url.hostname === "localhost" || url.hostname === "127.0.0.1")))
    );
  } catch {
    return false;
  }
}
