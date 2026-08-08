import { createHash, timingSafeEqual } from "node:crypto";
import { base64UrlDecode, equalBytes, utf8Decode } from "@qualified-opinion/protocol";
import { verifyWebAuthnP256SpkiAssertion } from "@qualified-opinion/protocol/node";
import type { EmailVerificationReceiptPayload } from "./identity-receipt";
import type { IdentityAttestationPolicyV3 } from "./policy";

const ES256_COSE_ALGORITHM = -7;
const EC2_COSE_KEY_TYPE = 2;
const P256_COSE_CURVE = 1;
const P256_SPKI_PREFIX = Buffer.from(
  "3059301306072a8648ce3d020106082a8648ce3d03010703420004",
  "hex",
);

export type IdentityPasskeyVerification = {
  credentialId: string;
  origin: string;
  proofOfPossessionSignCount: number;
  publicKeySpki: string;
  rpId: string;
};

export function verifyIdentityPasskeyBinding(input: {
  payload: EmailVerificationReceiptPayload;
  policy: IdentityAttestationPolicyV3;
}): IdentityPasskeyVerification {
  const passkey = input.payload.passkey;
  if (
    passkey.origin !== input.policy.webauthnOrigin ||
    passkey.rpId !== input.policy.webauthnRpId
  ) {
    throw new Error("identity_passkey_policy_mismatch");
  }
  const registration = verifyRegistration({
    attestationObject: passkey.proofOfPossession.registration.attestationObject,
    challenge: passkey.proofOfPossession.registration.challenge,
    clientDataJson: passkey.proofOfPossession.registration.clientDataJson,
    credentialId: passkey.credentialId,
    origin: passkey.origin,
    rpId: passkey.rpId,
  });
  if (
    registration.credentialId !== passkey.credentialId ||
    registration.publicKeySpki !== passkey.publicKeySpki
  ) {
    throw new Error("passkey_registration_binding_mismatch");
  }
  const proof = passkey.proofOfPossession.assertion;
  if (
    proof.userHandle !== null &&
    !safeBase64Equal(proof.userHandle, passkey.userHandle)
  ) {
    throw new Error("authentication_user_handle_mismatch");
  }
  const authentication = verifyWebAuthnP256SpkiAssertion({
    publicKeySpki: passkey.publicKeySpki,
    credentialId: passkey.credentialId,
    expectedCredentialId: passkey.credentialId,
    clientDataJson: proof.clientDataJson,
    authenticatorData: proof.authenticatorData,
    signature: proof.signature,
    expectedChallenge: proof.challenge,
    expectedOrigins: input.policy.webauthnOrigin,
    expectedRpId: input.policy.webauthnRpId,
    requireUserVerification: true,
  });
  if (!authentication.verified) {
    throw new Error(`identity_passkey_proof_${authentication.error}`);
  }
  if (authentication.signCount !== passkey.signCount) {
    throw new Error("passkey_assertion_counter_mismatch");
  }
  return {
    credentialId: passkey.credentialId,
    origin: passkey.origin,
    proofOfPossessionSignCount: authentication.signCount,
    publicKeySpki: passkey.publicKeySpki,
    rpId: passkey.rpId,
  };
}

function verifyRegistration(input: {
  attestationObject: string;
  challenge: string;
  clientDataJson: string;
  credentialId: string;
  origin: string;
  rpId: string;
}) {
  const clientData = JSON.parse(
    utf8Decode(base64UrlDecode(input.clientDataJson)),
  ) as Record<string, unknown>;
  if (
    clientData.type !== "webauthn.create" ||
    clientData.challenge !== input.challenge ||
    clientData.origin !== input.origin ||
    clientData.crossOrigin === true ||
    clientData.topOrigin !== undefined
  ) {
    throw new Error("unexpected_registration_client_data");
  }
  const attestation = decodeCbor(base64UrlDecode(input.attestationObject));
  if (!(attestation instanceof Map)) {
    throw new Error("invalid_attestation_object");
  }
  const statement = attestation.get("attStmt");
  if (
    attestation.get("fmt") !== "none" ||
    !(statement instanceof Map) ||
    statement.size !== 0
  ) {
    throw new Error("unexpected_attestation_format");
  }
  const authData = attestation.get("authData");
  if (!(authData instanceof Uint8Array)) {
    throw new Error("missing_registration_authenticator_data");
  }
  const parsed = registrationAuthenticatorData(Buffer.from(authData), input.rpId);
  if (!safeBase64Equal(input.credentialId, parsed.credentialId)) {
    throw new Error("registration_credential_id_mismatch");
  }
  return parsed;
}

function registrationAuthenticatorData(authData: Buffer, rpId: string) {
  const header = authenticatorHeader(authData, rpId);
  if ((header.flags & 0x40) === 0 || authData.length < 55) {
    throw new Error("missing_attested_credential_data");
  }
  const credentialLength = authData.readUInt16BE(53);
  const credentialStart = 55;
  const credentialEnd = credentialStart + credentialLength;
  if (
    credentialLength < 16 ||
    credentialLength > 1023 ||
    credentialEnd >= authData.length
  ) {
    throw new Error("invalid_attested_credential_id");
  }
  const credentialIdBytes = authData.subarray(credentialStart, credentialEnd);
  const coseKey = decodeCbor(authData.subarray(credentialEnd));
  if (!(coseKey instanceof Map)) {
    throw new Error("invalid_credential_public_key");
  }
  if (
    coseKey.get(1) !== EC2_COSE_KEY_TYPE ||
    coseKey.get(3) !== ES256_COSE_ALGORITHM ||
    coseKey.get(-1) !== P256_COSE_CURVE
  ) {
    throw new Error("unsupported_credential_public_key");
  }
  const x = coseKey.get(-2);
  const y = coseKey.get(-3);
  if (
    !(x instanceof Uint8Array) ||
    !(y instanceof Uint8Array) ||
    x.length !== 32 ||
    y.length !== 32
  ) {
    throw new Error("invalid_credential_public_key_coordinates");
  }
  return {
    credentialId: Buffer.from(credentialIdBytes).toString("base64url"),
    publicKeySpki: Buffer.concat([
      P256_SPKI_PREFIX,
      Buffer.from(x),
      Buffer.from(y),
    ]).toString("base64url"),
  };
}

function authenticatorHeader(authData: Buffer, rpId: string) {
  if (authData.length < 37) throw new Error("invalid_authenticator_data");
  const expectedRpIdHash = createHash("sha256").update(rpId).digest();
  if (!timingSafeEqual(authData.subarray(0, 32), expectedRpIdHash)) {
    throw new Error("unexpected_webauthn_rp_id");
  }
  const flags = authData[32] ?? 0;
  if ((flags & 0x01) === 0) throw new Error("webauthn_user_presence_required");
  if ((flags & 0x04) === 0) {
    throw new Error("webauthn_user_verification_required");
  }
  return { flags };
}

function safeBase64Equal(left: string, right: string) {
  try {
    return equalBytes(base64UrlDecode(left), base64UrlDecode(right));
  } catch {
    return false;
  }
}

function decodeCbor(value: Uint8Array): unknown {
  return new CborDecoder(value).read();
}

class CborDecoder {
  private offset = 0;

  constructor(private readonly bytes: Uint8Array) {}

  read(): unknown {
    const initial = this.readByte();
    const major = initial >> 5;
    const additional = initial & 0x1f;
    if (major === 0) return this.readLength(additional);
    if (major === 1) return -1 - this.readLength(additional);
    if (major === 2) return this.readBytes(this.readLength(additional));
    if (major === 3) {
      return new TextDecoder("utf-8", { fatal: true }).decode(
        this.readBytes(this.readLength(additional)),
      );
    }
    if (major === 4) {
      return Array.from({ length: this.readLength(additional) }, () => this.read());
    }
    if (major === 5) {
      const map = new Map<unknown, unknown>();
      const length = this.readLength(additional);
      for (let index = 0; index < length; index += 1) {
        map.set(this.read(), this.read());
      }
      return map;
    }
    if (major === 6) {
      this.readLength(additional);
      return this.read();
    }
    if (major === 7) {
      if (additional === 20) return false;
      if (additional === 21) return true;
      if (additional === 22 || additional === 23) return null;
    }
    throw new Error("unsupported_cbor_value");
  }

  private readLength(additional: number) {
    if (additional < 24) return additional;
    if (additional === 24) return this.readByte();
    if (additional === 25) {
      const bytes = this.readBytes(2);
      return (bytes[0] ?? 0) * 256 + (bytes[1] ?? 0);
    }
    if (additional === 26) {
      const bytes = this.readBytes(4);
      return new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0);
    }
    if (additional === 27) {
      const bytes = this.readBytes(8);
      const integer = new DataView(bytes.buffer, bytes.byteOffset, 8).getBigUint64(0);
      if (integer > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error("cbor_integer_too_large");
      }
      return Number(integer);
    }
    throw new Error("indefinite_cbor_not_supported");
  }

  private readByte() {
    const value = this.bytes[this.offset];
    if (value === undefined) throw new Error("truncated_cbor");
    this.offset += 1;
    return value;
  }

  private readBytes(length: number) {
    const end = this.offset + length;
    if (!Number.isSafeInteger(length) || length < 0 || end > this.bytes.length) {
      throw new Error("truncated_cbor");
    }
    const value = this.bytes.subarray(this.offset, end);
    this.offset = end;
    return value;
  }
}
