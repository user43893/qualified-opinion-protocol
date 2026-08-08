import { describe, expect, test } from "bun:test";
import {
  buildEligibilityAssertionV3,
  buildIdentityAttestationPolicyV3,
  buildProtocolBindingV3,
  buildRegistryEvidenceV3,
  isEligibilityAssertionV3,
  validateEligibilityAssertionV3,
  verifyEligibilityAssertionV3Integrity,
} from "./index";

function digest(byte: number) {
  return Buffer.alloc(32, byte).toString("base64url");
}

async function fixture() {
  const binding = buildProtocolBindingV3({
    instanceId: "org.example",
    instanceProfileSha256: digest(1),
    eligibilityPolicy: { id: "eligibility", sha256: digest(2) },
    tallyPolicy: { id: "tally", sha256: digest(3) },
    trustPolicy: { id: "trust", sha256: digest(4) },
    audience: "https://example.test/api/voting",
    origin: "https://example.test",
  });
  const subject = {
    scheme: "example.registry.v3",
    issuer: "example.registry",
    key: "12345",
  };
  const registryEvidence = buildRegistryEvidenceV3({
    reviewId: "review-1",
    reviewerAuthority: "org.example",
    subject,
    recordUrl: "https://registry.example/12345",
    checkedFullName: "Ada Example",
    checkedEmail: "ada@example.test",
    checkedAt: "2026-07-24T10:00:00.000Z",
  });
  const identityAttestationPolicy = buildIdentityAttestationPolicyV3({
    policyId: "policy-image-a",
    audience: "email-verification",
    imageDigest: "sha256:image-a",
    projectId: "project-a",
    serviceAccount: "verifier@example.test",
    expectedEnvironment: {
      QO_WEBAUTHN_ORIGIN: "https://verify.example.test",
      QO_WEBAUTHN_RP_ID: "verify.example.test",
    },
    allowDebug: false,
    pkiRootCertificateSha256: "AA:BB:CC",
    identityOrigin: "https://verify.example.test",
    rpId: "verify.example.test",
  });
  return buildEligibilityAssertionV3({
    assertionId: "assertion-1",
    publicVoterId: "voter-1",
    binding,
    identityProof: {
      proofId: "proof-1",
      payloadSha256: digest(5),
    },
    identityAttestationPolicy,
    rootKey: {
      credentialId: "credential-1",
      publicKeySpkiSha256: digest(6),
    },
    qualificationClaim: "active_attorney",
    subject,
    registryEvidence,
    issuedAt: "2026-07-24T11:00:00.000Z",
    issuerKeyId: "eligibility-key-1",
  });
}

describe("EligibilityAssertionV3", () => {
  test("binds exact identity-attestation policy material", async () => {
    const assertion = await fixture();

    expect(isEligibilityAssertionV3(assertion)).toBe(true);
    expect(validateEligibilityAssertionV3(assertion).ok).toBe(true);
    expect(await verifyEligibilityAssertionV3Integrity(assertion)).toBe(true);
    expect(assertion.identityAttestation.policy.imageDigest).toBe("sha256:image-a");
  });

  test("detects a policy payload changed without changing its signed hash", async () => {
    const assertion = await fixture();
    assertion.identityAttestation.policy.expectedEnvironment.QO_WEBAUTHN_RP_ID =
      "changed.example.test";

    expect(validateEligibilityAssertionV3(assertion).ok).toBe(true);
    expect(await verifyEligibilityAssertionV3Integrity(assertion)).toBe(false);
  });

  test("rejects policy extension fields", async () => {
    const assertion = await fixture();
    const value = structuredClone(assertion) as unknown as {
      identityAttestation: { policy: Record<string, unknown> };
    };
    value.identityAttestation.policy.untrustedOverride = true;

    expect(validateEligibilityAssertionV3(value).ok).toBe(false);
  });
});
