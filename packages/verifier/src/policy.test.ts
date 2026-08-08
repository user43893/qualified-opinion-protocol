import { describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { GOOGLE_CONFIDENTIAL_SPACE_ISSUER } from "./gcs";
import { parseVerificationPolicy, selectServerKey } from "./policy";

function spki() {
  return generateKeyPairSync("ed25519")
    .publicKey.export({
      format: "der",
      type: "spki",
    })
    .toString("base64url");
}

function policy() {
  return {
    schemaVersion: "qualified-opinion.vote-proof-verification-policy.v3",
    policyId: "example-current-v3",
    identityAttestationPolicies: [
      {
        audience: "https://verifier.example.test",
        debugAllowed: false,
        expectedEnvironment: {
          QO_APP_URL: "https://app.example.test",
          QO_ELIGIBILITY_DIRECTORY_WITNESS_ID: "example-witness",
          QO_ELIGIBILITY_DIRECTORY_WITNESS_MAX_AGE_SECONDS: "300",
          QO_ELIGIBILITY_DIRECTORY_WITNESS_PUBLIC_KEY_SPKI_SHA256: "a".repeat(64),
          QO_ELIGIBILITY_DIRECTORY_WITNESS_SOURCE_REVISION: "b".repeat(40),
          QO_ELIGIBILITY_DIRECTORY_WITNESS_STATUS_URL:
            "https://witness.example.test/status",
          QO_ELIGIBILITY_DIRECTORY_WITNESS_TRUST_ROOT_SHA256: "c".repeat(64),
          QO_VOTE_LOG_ID: "example-log",
          QO_WEBAUTHN_ORIGIN: "https://app.example.test",
          QO_WEBAUTHN_RP_ID: "app.example.test",
        },
        imageDigest: `sha256:${"d".repeat(64)}`,
        issuer: GOOGLE_CONFIDENTIAL_SPACE_ISSUER,
        memoryMonitoringDisabled: true,
        projectId: "example-project",
        requireExactEnvironment: true,
        serviceAccount: "verifier@example-project.iam.gserviceaccount.com",
        stable: true,
        trustedRootCertificateSha256: [`${"AA:".repeat(31)}AA`],
        validFrom: "2026-01-01T00:00:00.000Z",
        validUntil: null,
        webauthnOrigin: "https://app.example.test",
        webauthnRpId: "app.example.test",
      },
    ],
    serverKeys: [
      {
        algorithm: "Ed25519",
        keyId: "eligibility-key",
        publicKeySpki: spki(),
        purpose: "eligibility",
        validFrom: "2026-01-01T00:00:00.000Z",
        validUntil: null,
      },
      {
        algorithm: "Ed25519",
        keyId: "receipt-key",
        publicKeySpki: spki(),
        purpose: "receipt",
        validFrom: "2026-01-01T00:00:00.000Z",
        validUntil: null,
      },
    ],
    votingPolicies: [
      {
        protocolBindingSha256: "A".repeat(43),
        protocolVersion: "qualified-opinion.vote-event.v3",
        transparencyLogId: "example-log",
        validFrom: "2026-01-01T00:00:00.000Z",
        validUntil: null,
        voteServiceAudience: "https://vote.example.test",
      },
    ],
  };
}

describe("current standalone verification policy", () => {
  test("requires and selects separate eligibility and receipt authorities", () => {
    const parsed = parseVerificationPolicy(policy());
    expect(
      selectServerKey(parsed, {
        keyId: "eligibility-key",
        purpose: "eligibility",
        time: "2026-02-01T00:00:00.000Z",
      }).purpose,
    ).toBe("eligibility");
    expect(
      selectServerKey(parsed, {
        keyId: "receipt-key",
        purpose: "receipt",
        time: "2026-02-01T00:00:00.000Z",
      }).purpose,
    ).toBe("receipt");
  });

  test("rejects a policy without either current signing purpose", () => {
    for (const missing of ["eligibility", "receipt"] as const) {
      const value = policy();
      value.serverKeys = value.serverKeys.filter((key) => key.purpose !== missing);
      expect(() => parseVerificationPolicy(value)).toThrow(
        "verification_policy_is_incomplete",
      );
    }
  });

  test("rejects overlapping authority windows for the same purpose and key", () => {
    const value = policy();
    const receipt = value.serverKeys[1];
    if (!receipt) throw new Error("receipt fixture missing");
    value.serverKeys.push({ ...receipt });
    expect(() => parseVerificationPolicy(value)).toThrow(
      "overlapping_server_key:receipt:receipt-key_windows",
    );
  });
});
