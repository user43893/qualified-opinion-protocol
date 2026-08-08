import { describe, expect, test } from "bun:test";
import { type KeyObject, createHash, generateKeyPairSync, sign } from "node:crypto";
import { attachDetachedSignature, attachWebAuthnSignature } from "./builders";
import { canonicalizeJson } from "./canonical";
import {
  base64UrlEncode,
  canonicalJsonSha256,
  concatBytes,
  utf8Encode,
} from "./encoding";
import {
  verifyEd25519SignedPayload,
  verifyP256SignedPayload,
  verifyP256WebCryptoSpkiSignature,
  verifyWebAuthnP256SpkiAssertion,
  verifyWebAuthnSignedPayload,
  webAuthnClientDataJsonBytes,
} from "./node";

const signedVotePayload = {
  schema: "qualified-opinion.test-vote.v3",
  eventId: "event-1",
  choiceId: "choice-valid",
};

const delegatedAuthorizationPayload = {
  schema: "qualified-opinion.test-delegation.v3",
  delegationId: "delegation-1",
};

function spki(key: KeyObject) {
  return base64UrlEncode(new Uint8Array(key.export({ type: "spki", format: "der" })));
}

describe("Node SPKI verification", () => {
  test("verifies P-256 Web Crypto/P1363 signatures and rejects tampering", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    });
    const message = utf8Encode("canonical vote bytes");
    const signature = sign("sha256", message, {
      key: privateKey,
      dsaEncoding: "ieee-p1363",
    });
    expect(
      verifyP256WebCryptoSpkiSignature({
        publicKeySpki: spki(publicKey),
        message,
        signature: base64UrlEncode(signature),
      }),
    ).toBe(true);
    expect(
      verifyP256WebCryptoSpkiSignature({
        publicKeySpki: spki(publicKey),
        message: "tampered",
        signature: base64UrlEncode(signature),
      }),
    ).toBe(false);
  });

  test("verifies complete P-256 and Ed25519 signed envelopes", async () => {
    const p256 = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const voteBytes = utf8Encode(canonicalizeJson(signedVotePayload));
    const voteSignature = sign("sha256", voteBytes, {
      key: p256.privateKey,
      dsaEncoding: "ieee-p1363",
    });
    const voteEnvelope = await attachDetachedSignature(signedVotePayload, {
      algorithm: "ES256",
      keyId: "p256-test-key",
      value: base64UrlEncode(voteSignature),
    });
    expect(
      await verifyP256SignedPayload({
        envelope: voteEnvelope,
        publicKeySpki: spki(p256.publicKey),
        expectedKeyId: "p256-test-key",
      }),
    ).toBe(true);

    const ed25519 = generateKeyPairSync("ed25519");
    const serverSignature = sign(null, voteBytes, ed25519.privateKey);
    const serverEnvelope = await attachDetachedSignature(
      structuredClone(signedVotePayload),
      {
        algorithm: "Ed25519",
        keyId: "server-test-key",
        value: base64UrlEncode(serverSignature),
      },
    );
    expect(
      await verifyEd25519SignedPayload({
        envelope: serverEnvelope,
        publicKeySpki: spki(ed25519.publicKey),
        expectedKeyId: "server-test-key",
      }),
    ).toBe(true);
    serverEnvelope.payload.choiceId = "choice-tampered";
    expect(
      await verifyEd25519SignedPayload({
        envelope: serverEnvelope,
        publicKeySpki: spki(ed25519.publicKey),
      }),
    ).toBe(false);
  });
});

describe("WebAuthn P-256 assertion verification", () => {
  test("checks challenge, origin, RP ID, flags, and DER signature", async () => {
    const keyPair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const challenge = await canonicalJsonSha256(delegatedAuthorizationPayload);
    const origin = "https://vote.example.test";
    const rpId = "example.test";
    const clientData = webAuthnClientDataJsonBytes({ challenge, origin });
    const authenticatorData = new Uint8Array(37);
    authenticatorData.set(createHash("sha256").update(rpId).digest(), 0);
    authenticatorData[32] = 0x05;
    authenticatorData[36] = 7;
    const signedBytes = concatBytes(
      authenticatorData,
      createHash("sha256").update(clientData).digest(),
    );
    const signature = sign("sha256", signedBytes, keyPair.privateKey);
    const credentialId = base64UrlEncode(utf8Encode("credential-vector-1"));

    const result = verifyWebAuthnP256SpkiAssertion({
      publicKeySpki: spki(keyPair.publicKey),
      credentialId,
      expectedCredentialId: credentialId,
      clientDataJson: base64UrlEncode(clientData),
      authenticatorData: base64UrlEncode(authenticatorData),
      signature: base64UrlEncode(signature),
      expectedChallenge: challenge,
      expectedOrigins: origin,
      expectedRpId: rpId,
      requireUserVerification: true,
    });
    expect(result.verified).toBe(true);
    if (result.verified) {
      expect(result.signCount).toBe(7);
      expect(result.userVerified).toBe(true);
    }

    expect(
      verifyWebAuthnP256SpkiAssertion({
        publicKeySpki: spki(keyPair.publicKey),
        clientDataJson: base64UrlEncode(clientData),
        authenticatorData: base64UrlEncode(authenticatorData),
        signature: base64UrlEncode(signature),
        expectedChallenge: challenge,
        expectedOrigins: "https://evil.example",
        expectedRpId: rpId,
      }),
    ).toEqual({ verified: false, error: "origin_mismatch" });

    const envelope = await attachWebAuthnSignature(delegatedAuthorizationPayload, {
      algorithm: "ES256",
      credentialId,
      clientDataJson: base64UrlEncode(clientData),
      authenticatorData: base64UrlEncode(authenticatorData),
      signature: base64UrlEncode(signature),
    });
    expect(
      (
        await verifyWebAuthnSignedPayload({
          envelope,
          publicKeySpki: spki(keyPair.publicKey),
          expectedCredentialId: credentialId,
          expectedOrigins: origin,
          expectedRpId: rpId,
          requireUserVerification: true,
        })
      ).verified,
    ).toBe(true);
  });
});
