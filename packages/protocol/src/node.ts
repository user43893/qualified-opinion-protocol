import {
  type KeyObject,
  createHash,
  createPublicKey,
  verify as cryptoVerify,
} from "node:crypto";
import { canonicalizeJson } from "./canonical";
import {
  type BinaryInput,
  base64UrlDecode,
  equalBytes,
  toBytes,
  utf8Decode,
  utf8Encode,
} from "./encoding";
import {
  type TallyInputSetV3,
  type TallyPolicyV3,
  type TallyResultV3,
  type TallySnapshotV3,
  replayTallyV3,
  verifyTallySnapshotStructureV3,
} from "./tally-v3";
import type { MerkleTreeHeadV3, SignedPayload, WebAuthnSignedPayload } from "./types";
import type { QuestionVotingAuthorizationV3, VoteEventV3 } from "./v3-types";
import { verifySignedPayloadHash } from "./validate";

export type P256SignatureEncoding = "der" | "ieee-p1363" | "auto";

export function verifyP256SpkiSignature(input: {
  publicKeySpki: string | Uint8Array;
  message: BinaryInput;
  signature: string | Uint8Array;
  signatureEncoding?: P256SignatureEncoding;
}): boolean {
  try {
    const publicKey = importSpki(input.publicKeySpki);
    assertP256Key(publicKey);
    const signature = binary(input.signature);
    const encoding =
      input.signatureEncoding === "auto" || !input.signatureEncoding
        ? signature.length === 64
          ? "ieee-p1363"
          : "der"
        : input.signatureEncoding;
    return cryptoVerify(
      "sha256",
      toBytes(input.message),
      { key: publicKey, dsaEncoding: encoding },
      signature,
    );
  } catch {
    return false;
  }
}

/** Verifies a raw P-256 signature emitted by Web Crypto subtle.sign(). */
export function verifyP256WebCryptoSpkiSignature(input: {
  publicKeySpki: string | Uint8Array;
  message: BinaryInput;
  signature: string | Uint8Array;
}): boolean {
  return verifyP256SpkiSignature({
    ...input,
    signatureEncoding: "ieee-p1363",
  });
}

/** Verifies an Ed25519 server/TEE signature over exact bytes. */
export function verifyEd25519SpkiSignature(input: {
  publicKeySpki: string | Uint8Array;
  message: BinaryInput;
  signature: string | Uint8Array;
}): boolean {
  try {
    const publicKey = importSpki(input.publicKeySpki);
    if (publicKey.asymmetricKeyType !== "ed25519") {
      return false;
    }
    return cryptoVerify(
      null,
      toBytes(input.message),
      publicKey,
      binary(input.signature),
    );
  } catch {
    return false;
  }
}

export async function verifyP256SignedPayload<T>(input: {
  envelope: SignedPayload<T>;
  publicKeySpki: string | Uint8Array;
  expectedKeyId?: string;
}): Promise<boolean> {
  if (
    input.envelope.signature.algorithm !== "ES256" ||
    (input.expectedKeyId && input.envelope.signature.keyId !== input.expectedKeyId) ||
    !(await verifySignedPayloadHash(input.envelope))
  ) {
    return false;
  }
  return verifyP256WebCryptoSpkiSignature({
    publicKeySpki: input.publicKeySpki,
    message: canonicalizeJson(input.envelope.payload),
    signature: input.envelope.signature.value,
  });
}

export async function verifyEd25519SignedPayload<T>(input: {
  envelope: SignedPayload<T>;
  publicKeySpki: string | Uint8Array;
  expectedKeyId?: string;
}): Promise<boolean> {
  if (
    input.envelope.signature.algorithm !== "Ed25519" ||
    (input.expectedKeyId && input.envelope.signature.keyId !== input.expectedKeyId) ||
    !(await verifySignedPayloadHash(input.envelope))
  ) {
    return false;
  }
  return verifyEd25519SpkiSignature({
    publicKeySpki: input.publicKeySpki,
    message: canonicalizeJson(input.envelope.payload),
    signature: input.envelope.signature.value,
  });
}

export type TallySignatureRoleV3 =
  | "snapshot"
  | "ballot_manifest"
  | "tree_head"
  | "vote_receipt";

export type TallyTrustedSigningKeyV3 = {
  algorithm: "Ed25519";
  keyId: string;
  publicKeySpki: string | Uint8Array;
  purpose: "receipt";
  validFrom: string;
  validUntil: string | null;
};

export type TallySignatureTrustRequestV3 = {
  role: TallySignatureRoleV3;
  keyId: string;
  algorithm: "Ed25519";
  signedAt: string;
  envelope: SignedPayload<unknown>;
};

export type ResolveTallyTrustedSigningKeyV3 = (
  request: TallySignatureTrustRequestV3,
) => Promise<TallyTrustedSigningKeyV3 | null> | TallyTrustedSigningKeyV3 | null;

export type TallyAuthorizationVerificationMaterialV3 = {
  authorization: QuestionVotingAuthorizationV3;
  /**
   * The verifier must validate the Google token signature, pinned workload
   * policy, audience and purpose, and require eat_nonce to equal this digest.
   */
  expectedAttestationNonce: string;
  firstPublishedAt: string;
};

export type VerifyTallyQuestionAuthorizationV3 = (
  material: TallyAuthorizationVerificationMaterialV3,
) =>
  | Promise<{ ok: true } | { ok: false; errors: string[] }>
  | { ok: true }
  | { ok: false; errors: string[] };

export type TallyCryptographicVerificationResultV3 =
  | { ok: true; result: TallyResultV3 }
  | { ok: false; errors: string[] };

/**
 * Verifies the public V3 replay boundary without resolving any member-level
 * key or identity material. Server artifacts use pinned Ed25519 history,
 * events use their attested question keys, and the required authorization
 * callback verifies the Confidential Space workload and payload-hash nonce.
 */
export async function verifyTallySnapshotCryptographicallyV3(input: {
  snapshot: SignedPayload<TallySnapshotV3>;
  policy?: TallyPolicyV3;
  inputSet: TallyInputSetV3;
  expectedLatestQuestionTreeHead?: SignedPayload<MerkleTreeHeadV3>;
  resolveTrustedKey: ResolveTallyTrustedSigningKeyV3;
  verifyQuestionAuthorization: VerifyTallyQuestionAuthorizationV3;
}): Promise<TallyCryptographicVerificationResultV3> {
  const structural = await verifyTallySnapshotStructureV3({
    snapshot: input.snapshot,
    policy: input.policy,
    inputSet: input.inputSet,
    expectedLatestQuestionTreeHead: input.expectedLatestQuestionTreeHead,
  });
  if (!structural.ok) return structural;

  const errors: string[] = [];
  const checkpointTime = input.inputSet.treeHead.payload.issuedAt;
  const trustedArtifacts: Array<{
    role: TallySignatureRoleV3;
    envelope: SignedPayload<unknown>;
    signedAt: string;
    expectedKeyId: string;
  }> = [
    {
      role: "snapshot",
      envelope: input.snapshot as SignedPayload<unknown>,
      signedAt: input.snapshot.payload.generatedAt,
      expectedKeyId: input.snapshot.payload.issuerKeyId,
    },
    ...input.inputSet.ballotManifests.map((manifest) => ({
      role: "ballot_manifest" as const,
      envelope: manifest as SignedPayload<unknown>,
      signedAt: manifest.payload.publishedAt,
      expectedKeyId: manifest.payload.issuer.keyId,
    })),
    {
      role: "tree_head",
      envelope: input.inputSet.treeHead as SignedPayload<unknown>,
      signedAt: checkpointTime,
      expectedKeyId: input.inputSet.treeHead.payload.issuerKeyId,
    },
    ...(input.expectedLatestQuestionTreeHead
      ? [
          {
            role: "tree_head" as const,
            envelope: input.expectedLatestQuestionTreeHead as SignedPayload<unknown>,
            signedAt: input.expectedLatestQuestionTreeHead.payload.issuedAt,
            expectedKeyId: input.expectedLatestQuestionTreeHead.payload.issuerKeyId,
          },
        ]
      : []),
    ...input.inputSet.voteReceipts.map((receipt) => ({
      role: "vote_receipt" as const,
      envelope: receipt.envelope as SignedPayload<unknown>,
      signedAt: receipt.envelope.payload.receivedAt,
      expectedKeyId: receipt.envelope.payload.issuerKeyId,
    })),
  ];
  for (const artifact of trustedArtifacts) {
    const label = `${artifact.role}:${artifact.envelope.payloadSha256}`;
    if (
      artifact.envelope.signature.algorithm !== "Ed25519" ||
      artifact.envelope.signature.keyId !== artifact.expectedKeyId
    ) {
      errors.push(`${label}:payload_signature_key_mismatch`);
      continue;
    }
    let trusted: TallyTrustedSigningKeyV3 | null = null;
    try {
      trusted = await input.resolveTrustedKey({
        role: artifact.role,
        keyId: artifact.envelope.signature.keyId,
        algorithm: "Ed25519",
        signedAt: artifact.signedAt,
        envelope: artifact.envelope,
      });
    } catch {
      errors.push(`${label}:trust_resolution_failed`);
      continue;
    }
    if (
      !trusted ||
      trusted.keyId !== artifact.envelope.signature.keyId ||
      trusted.algorithm !== "Ed25519" ||
      trusted.purpose !== "receipt"
    ) {
      errors.push(`${label}:untrusted_signing_key`);
      continue;
    }
    if (!trustWindowContainsTimestamp(trusted, artifact.signedAt)) {
      errors.push(`${label}:signing_key_outside_trust_window`);
      continue;
    }
    if (
      !(await verifyEd25519SignedPayload({
        envelope: artifact.envelope,
        publicKeySpki: trusted.publicKeySpki,
        expectedKeyId: trusted.keyId,
      }))
    ) {
      errors.push(`${label}:invalid_signature`);
    }
  }

  const firstPublishedByPayloadHash = new Map<string, string>();
  for (const logLeaf of input.inputSet.questionLogLeaves) {
    firstPublishedByPayloadHash.set(logLeaf.entryPayloadSha256, checkpointTime);
  }
  const authorizationsByHash = new Map(
    input.inputSet.questionVotingAuthorizations.map((authorization) => [
      authorization.payloadSha256,
      authorization,
    ]),
  );
  for (const authorization of input.inputSet.questionVotingAuthorizations) {
    const label = `question_authorization:${authorization.payloadSha256}`;
    try {
      const firstPublishedAt =
        input.inputSet.voteEvents
          .map((event) => event.envelope)
          .filter(
            (event) =>
              event.payload.authorizationSha256 === authorization.payloadSha256,
          )
          .map(
            (event) =>
              firstPublishedByPayloadHash.get(event.payloadSha256) ?? checkpointTime,
          )
          .sort()[0] ?? checkpointTime;
      const verified = await input.verifyQuestionAuthorization({
        authorization,
        expectedAttestationNonce: authorization.payloadSha256,
        firstPublishedAt,
      });
      if (!verified.ok) {
        errors.push(...verified.errors.map((error) => `${label}:${error}`));
      }
    } catch {
      errors.push(`${label}:attestation_verification_failed`);
    }
  }

  for (const entry of input.inputSet.voteEvents) {
    const event = entry.envelope.payload;
    const label = `vote_event:${event.eventId}`;
    const authorization = authorizationsByHash.get(event.authorizationSha256);
    if (!authorization) {
      errors.push(`${label}:question_authorization_missing`);
      continue;
    }
    if (
      entry.envelope.signature.algorithm !== "ES256" ||
      entry.envelope.signature.keyId !== authorization.payload.questionKey.keyId ||
      event.questionKeyId !== authorization.payload.questionKey.keyId
    ) {
      errors.push(`${label}:question_key_mismatch`);
      continue;
    }
    if (
      !(await verifyP256SignedPayload({
        envelope: entry.envelope,
        publicKeySpki: authorization.payload.questionKey.publicKeySpki,
        expectedKeyId: authorization.payload.questionKey.keyId,
      }))
    ) {
      errors.push(`${label}:invalid_question_key_signature`);
    }
  }

  const replay = await replayTallyV3(
    input.policy ?? input.snapshot.payload.policy.payload,
    input.inputSet,
  );
  return errors.length === 0
    ? { ok: true, result: replay.result }
    : { ok: false, errors };
}

function trustWindowContainsTimestamp(
  key: Pick<TallyTrustedSigningKeyV3, "validFrom" | "validUntil">,
  signedAt: string,
) {
  const timestamp = Date.parse(signedAt);
  const validFrom = Date.parse(key.validFrom);
  const validUntil = key.validUntil === null ? null : Date.parse(key.validUntil);
  return (
    Number.isFinite(timestamp) &&
    Number.isFinite(validFrom) &&
    (validUntil === null || Number.isFinite(validUntil)) &&
    timestamp >= validFrom &&
    (validUntil === null || timestamp < validUntil)
  );
}

export type WebAuthnP256VerificationResult =
  | {
      verified: true;
      clientData: Record<string, unknown>;
      flags: number;
      signCount: number;
      userPresent: true;
      userVerified: boolean;
    }
  | { verified: false; error: string };

/**
 * Verifies a WebAuthn ES256 assertion whose credential public key is SPKI.
 * WebAuthn authenticator signatures are ASN.1 DER encoded.
 */
export function verifyWebAuthnP256SpkiAssertion(input: {
  publicKeySpki: string | Uint8Array;
  credentialId?: string;
  expectedCredentialId?: string;
  clientDataJson: string | Uint8Array;
  authenticatorData: string | Uint8Array;
  signature: string | Uint8Array;
  expectedChallenge: string;
  expectedOrigins: string | string[];
  expectedRpId: string;
  requireUserVerification?: boolean;
}): WebAuthnP256VerificationResult {
  try {
    if (
      input.expectedCredentialId &&
      input.credentialId !== input.expectedCredentialId
    ) {
      return failed("credential_id_mismatch");
    }
    const clientDataBytes = binary(input.clientDataJson);
    const authenticatorData = binary(input.authenticatorData);
    const signature = binary(input.signature);
    if (authenticatorData.length < 37) {
      return failed("authenticator_data_too_short");
    }

    const clientData = JSON.parse(utf8Decode(clientDataBytes)) as Record<
      string,
      unknown
    >;
    if (clientData.type !== "webauthn.get") {
      return failed("unexpected_client_data_type");
    }
    if (!sameBase64Url(clientData.challenge, input.expectedChallenge)) {
      return failed("challenge_mismatch");
    }
    const expectedOrigins = Array.isArray(input.expectedOrigins)
      ? input.expectedOrigins
      : [input.expectedOrigins];
    if (
      typeof clientData.origin !== "string" ||
      !expectedOrigins.includes(clientData.origin)
    ) {
      return failed("origin_mismatch");
    }
    if (clientData.crossOrigin === true) {
      return failed("cross_origin_assertion_rejected");
    }

    const expectedRpIdHash = createHash("sha256")
      .update(input.expectedRpId, "utf8")
      .digest();
    if (!equalBytes(authenticatorData.subarray(0, 32), expectedRpIdHash)) {
      return failed("rp_id_hash_mismatch");
    }
    const flags = authenticatorData[32];
    const userPresent = (flags & 0x01) !== 0;
    const userVerified = (flags & 0x04) !== 0;
    if (!userPresent) {
      return failed("user_presence_required");
    }
    if (input.requireUserVerification && !userVerified) {
      return failed("user_verification_required");
    }

    const signedBytes = new Uint8Array(authenticatorData.length + 32);
    signedBytes.set(authenticatorData);
    signedBytes.set(
      createHash("sha256").update(clientDataBytes).digest(),
      authenticatorData.length,
    );
    const valid = verifyP256SpkiSignature({
      publicKeySpki: input.publicKeySpki,
      message: signedBytes,
      signature,
      signatureEncoding: "der",
    });
    if (!valid) {
      return failed("invalid_signature");
    }

    return {
      verified: true,
      clientData,
      flags,
      signCount:
        authenticatorData[33] * 0x1000000 +
        authenticatorData[34] * 0x10000 +
        authenticatorData[35] * 0x100 +
        authenticatorData[36],
      userPresent: true,
      userVerified,
    };
  } catch {
    return failed("malformed_assertion");
  }
}

/** Verifies that WebAuthn signed the envelope's canonical SHA-256 challenge. */
export async function verifyWebAuthnSignedPayload<T>(input: {
  envelope: WebAuthnSignedPayload<T>;
  publicKeySpki: string | Uint8Array;
  expectedOrigins: string | string[];
  expectedRpId: string;
  expectedCredentialId?: string;
  requireUserVerification?: boolean;
}): Promise<WebAuthnP256VerificationResult> {
  if (!(await verifySignedPayloadHash(input.envelope))) {
    return failed("payload_hash_mismatch");
  }
  if (input.envelope.webauthn.algorithm !== "ES256") {
    return failed("unsupported_algorithm");
  }
  return verifyWebAuthnP256SpkiAssertion({
    publicKeySpki: input.publicKeySpki,
    credentialId: input.envelope.webauthn.credentialId,
    expectedCredentialId: input.expectedCredentialId,
    clientDataJson: input.envelope.webauthn.clientDataJson,
    authenticatorData: input.envelope.webauthn.authenticatorData,
    signature: input.envelope.webauthn.signature,
    expectedChallenge: input.envelope.payloadSha256,
    expectedOrigins: input.expectedOrigins,
    expectedRpId: input.expectedRpId,
    requireUserVerification: input.requireUserVerification,
  });
}

function importSpki(value: string | Uint8Array): KeyObject {
  return createPublicKey({
    key: Buffer.from(binary(value)),
    format: "der",
    type: "spki",
  });
}

function assertP256Key(key: KeyObject) {
  if (
    key.asymmetricKeyType !== "ec" ||
    key.asymmetricKeyDetails?.namedCurve !== "prime256v1"
  ) {
    throw new TypeError("Expected a P-256 SPKI public key");
  }
}

function binary(value: string | Uint8Array): Uint8Array {
  return typeof value === "string" ? base64UrlDecode(value) : value;
}

function sameBase64Url(actual: unknown, expected: string) {
  if (typeof actual !== "string") {
    return false;
  }
  try {
    return equalBytes(base64UrlDecode(actual), base64UrlDecode(expected));
  } catch {
    return false;
  }
}

function failed(error: string): WebAuthnP256VerificationResult {
  return { verified: false, error };
}

/** Convenience helper for clients constructing WebAuthn clientDataJSON. */
export function webAuthnClientDataJsonBytes(input: {
  challenge: string;
  origin: string;
  crossOrigin?: boolean;
}): Uint8Array {
  return utf8Encode(
    JSON.stringify({
      type: "webauthn.get",
      challenge: input.challenge,
      origin: input.origin,
      crossOrigin: input.crossOrigin ?? false,
    }),
  );
}
