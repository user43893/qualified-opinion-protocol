import { describe, expect, test } from "bun:test";
import type { EmailVerificationReceiptPayload } from "./identity-receipt";
import type { IdentityAttestationPolicyV3 } from "./policy";
import { createIdentityPasskeyBindingFixture } from "./testing/fixture";
import { verifyIdentityPasskeyBinding } from "./webauthn-binding";

const origin = "https://passkey-proof.example.test";
const rpId = "passkey-proof.example.test";
const policy = {
  webauthnOrigin: origin,
  webauthnRpId: rpId,
} as IdentityAttestationPolicyV3;
type PasskeyBinding = ReturnType<typeof createIdentityPasskeyBindingFixture>;

function fixture(): PasskeyBinding {
  return structuredClone(createIdentityPasskeyBindingFixture({ origin, rpId }));
}

function verify(
  passkey: PasskeyBinding,
  identityPolicy: IdentityAttestationPolicyV3 = policy,
) {
  return verifyIdentityPasskeyBinding({
    payload: { passkey } as EmailVerificationReceiptPayload,
    policy: identityPolicy,
  });
}

function decodeClientData(value: string) {
  return JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as Record<
    string,
    unknown
  >;
}

function encodeClientData(value: Record<string, unknown>) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

describe("identity passkey proof binding", () => {
  test("verifies the registration key and proof-of-possession assertion", () => {
    const passkey = fixture();
    expect(verify(passkey)).toEqual({
      credentialId: passkey.credentialId,
      origin,
      proofOfPossessionSignCount: 1,
      publicKeySpki: passkey.publicKeySpki,
      rpId,
    });
  });

  test("rejects registration and assertion challenge substitution", () => {
    const registration = fixture();
    registration.proofOfPossession.registration.challenge = Buffer.alloc(
      32,
      1,
    ).toString("base64url");
    expect(() => verify(registration)).toThrow("unexpected_registration_client_data");

    const assertion = fixture();
    assertion.proofOfPossession.assertion.challenge = Buffer.alloc(32, 2).toString(
      "base64url",
    );
    expect(() => verify(assertion)).toThrow(
      "identity_passkey_proof_challenge_mismatch",
    );
  });

  test("rejects registration and assertion origin substitution", () => {
    const registration = fixture();
    const registrationClientData = decodeClientData(
      registration.proofOfPossession.registration.clientDataJson,
    );
    registrationClientData.origin = "https://attacker.example.test";
    registration.proofOfPossession.registration.clientDataJson =
      encodeClientData(registrationClientData);
    expect(() => verify(registration)).toThrow("unexpected_registration_client_data");

    const assertion = fixture();
    const assertionClientData = decodeClientData(
      assertion.proofOfPossession.assertion.clientDataJson,
    );
    assertionClientData.origin = "https://attacker.example.test";
    assertion.proofOfPossession.assertion.clientDataJson =
      encodeClientData(assertionClientData);
    expect(() => verify(assertion)).toThrow("identity_passkey_proof_origin_mismatch");
  });

  test("rejects a substituted RP ID even when the payload and policy agree", () => {
    const passkey = fixture();
    passkey.rpId = "attacker.example.test";
    expect(() =>
      verify(passkey, {
        ...policy,
        webauthnRpId: "attacker.example.test",
      }),
    ).toThrow("unexpected_webauthn_rp_id");
  });

  test("rejects a corrupted proof-of-possession signature", () => {
    const passkey = fixture();
    const signature = Buffer.from(
      passkey.proofOfPossession.assertion.signature,
      "base64url",
    );
    signature[signature.length - 1] ^= 1;
    passkey.proofOfPossession.assertion.signature = signature.toString("base64url");
    expect(() => verify(passkey)).toThrow("identity_passkey_proof_invalid_signature");
  });

  test("rejects a counter not signed by the authenticator", () => {
    const passkey = fixture();
    passkey.signCount += 1;
    expect(() => verify(passkey)).toThrow("passkey_assertion_counter_mismatch");
  });

  test("rejects a public key not bound by the registration", () => {
    const passkey = fixture();
    passkey.publicKeySpki = fixture().publicKeySpki;
    expect(() => verify(passkey)).toThrow("passkey_registration_binding_mismatch");
  });
});
