import { describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import {
  VOTE_EVENT_SCHEMA_V3,
  base64UrlDecode,
  buildActiveEligibilityDirectoryCheckpointV3,
  buildActiveEligibilityDirectoryLeavesV3,
  buildActiveEligibilityDirectoryRecordProofV3,
  buildActiveEligibilityDirectoryRecordV3,
  buildEligibilityAssertionV3,
  buildEligibilityDecisionV3,
  buildIdentityAttestationPolicyV3,
  buildProtocolBindingV3,
  buildRegistryEvidenceV3,
  canonicalJsonSha256,
  sha256Base64Url,
} from "@qualified-opinion/protocol";
import { verifyActiveEligibilityDirectoryRecordV3 } from "./eligibility-directory-v3";
import { GOOGLE_CONFIDENTIAL_SPACE_ISSUER } from "./gcs";
import {
  createEmailVerificationReceiptPayloadV3,
  emailVerificationPayloadHash,
} from "./identity-receipt";
import type { OfflineVerificationPolicyV3 } from "./policy";
import {
  createIdentityPasskeyBindingFixture,
  generateAttestationPki,
  signAttestationJwt,
  signEd25519,
} from "./testing/fixture";

function spki(key: ReturnType<typeof generateKeyPairSync>["publicKey"]) {
  return key.export({ format: "der", type: "spki" }).toString("base64url");
}

async function fixture(
  mutatePasskey?: (
    passkey: ReturnType<typeof createIdentityPasskeyBindingFixture>,
  ) => void,
) {
  const now = Math.ceil(Date.now() / 1_000) * 1_000 + 5_000;
  const at = (offset: number) => new Date(now + offset).toISOString();
  const instanceId = "org.example.directory-fixture";
  const directoryId = `${instanceId}:active-eligibility`;
  const origin = "https://directory-fixture.example.test";
  const rpId = "directory-fixture.example.test";
  const audience = "https://directory-verifier.example.test";
  const projectId = "directory-fixture";
  const serviceAccount = "directory-fixture@directory-fixture.iam.gserviceaccount.com";
  const imageDigest = `sha256:${"ab".repeat(32)}`;
  const expectedEnvironment = {
    QO_WEBAUTHN_ORIGIN: origin,
    QO_WEBAUTHN_RP_ID: rpId,
  };
  const passkey = createIdentityPasskeyBindingFixture({ origin, rpId });
  mutatePasskey?.(passkey);
  const eligibilityKey = generateKeyPairSync("ed25519");
  const eligibilityPublicKeySpki = spki(eligibilityKey.publicKey);
  const eligibilityKeyId = "directory-eligibility-key";
  const binding = buildProtocolBindingV3({
    instanceId,
    instanceProfileSha256: await sha256Base64Url("directory-instance"),
    eligibilityPolicy: {
      id: "directory-eligibility-policy",
      sha256: await sha256Base64Url("directory-eligibility-policy"),
    },
    tallyPolicy: {
      id: "directory-tally-policy",
      sha256: await sha256Base64Url("directory-tally-policy"),
    },
    trustPolicy: {
      id: "directory-trust-policy",
      sha256: await sha256Base64Url("directory-trust-policy"),
    },
    audience: "https://vote.example.test",
    origin,
  });
  const bindingSha256 = await canonicalJsonSha256(binding);
  const publicVoterId = "10000000-0000-4000-8000-000000000001";
  const proofId = "20000000-0000-4000-8000-000000000002";
  const receipt = createEmailVerificationReceiptPayloadV3({
    claimedEmail: "ada@example.test",
    claimedFullName: "Ada Example",
    passkey,
    requestId: "30000000-0000-4000-8000-000000000003",
    verifiedAt: at(0),
    verifierVersion: "directory-fixture",
  });
  const pki = await generateAttestationPki();
  let token: string;
  try {
    token = signAttestationJwt({
      audience,
      certificates: pki.certificates,
      environment: expectedEnvironment,
      environmentOverride: {},
      imageDigest,
      issuedAtSeconds: Math.floor(Date.parse(at(1_000)) / 1_000),
      leafPrivateKeyPem: pki.leafPrivateKeyPem,
      nonce: emailVerificationPayloadHash(receipt),
      projectId,
      serviceAccount,
    });
  } finally {
    await pki.cleanup();
  }
  const identityPolicy = buildIdentityAttestationPolicyV3({
    policyId: "directory-identity-policy",
    audience,
    imageDigest,
    projectId,
    serviceAccount,
    expectedEnvironment,
    allowDebug: false,
    pkiRootCertificateSha256: pki.rootFingerprint,
    identityOrigin: origin,
    rpId,
  });
  const subject = {
    scheme: "example.registry.subject.v3",
    issuer: "example.registry",
    key: "registry-subject-1",
  };
  const registryEvidence = buildRegistryEvidenceV3({
    reviewId: "40000000-0000-4000-8000-000000000004",
    reviewerAuthority: instanceId,
    subject,
    recordUrl: "https://registry.example.test/record/1",
    checkedFullName: receipt.claimedFullName,
    checkedEmail: receipt.normalizedEmail,
    checkedAt: at(2_000),
  });
  const assertionPayload = await buildEligibilityAssertionV3({
    assertionId: "50000000-0000-4000-8000-000000000005",
    publicVoterId,
    binding,
    identityProof: {
      proofId,
      payloadSha256: await canonicalJsonSha256(receipt),
    },
    identityAttestationPolicy: identityPolicy,
    rootKey: {
      credentialId: receipt.passkey.credentialId,
      publicKeySpkiSha256: await sha256Base64Url(
        base64UrlDecode(receipt.passkey.publicKeySpki),
      ),
    },
    qualificationClaim: "active-law-graduate",
    subject,
    registryEvidence,
    issuedAt: at(3_000),
    issuerKeyId: eligibilityKeyId,
  });
  const assertion = await signEd25519(
    assertionPayload,
    eligibilityKey.privateKey,
    eligibilityKeyId,
  );
  const decisionPayload = buildEligibilityDecisionV3({
    decisionId: "60000000-0000-4000-8000-000000000006",
    assertionSha256: assertion.payloadSha256,
    publicVoterId,
    sequence: 1,
    status: "active",
    reason: "initial_approval",
    effectiveAt: at(3_000),
    issuerKeyId: eligibilityKeyId,
  });
  const decision = await signEd25519(
    decisionPayload,
    eligibilityKey.privateKey,
    eligibilityKeyId,
  );
  const record = await buildActiveEligibilityDirectoryRecordV3({
    publicVoterId,
    registration: {
      proofId,
      payload: receipt,
      payloadSha256: await canonicalJsonSha256(receipt),
      attestationToken: token,
    },
    eligibilityAssertion: assertion,
    eligibilityDecision: decision,
  });
  const leaves = await buildActiveEligibilityDirectoryLeavesV3([record]);
  const checkpointPayload = await buildActiveEligibilityDirectoryCheckpointV3({
    directoryId,
    instanceId,
    protocolBindingSha256: bindingSha256,
    sequence: 1,
    previousCheckpointSha256: null,
    issuedAt: at(4_000),
    issuerKeyId: eligibilityKeyId,
    leaves,
  });
  const checkpoint = await signEd25519(
    checkpointPayload,
    eligibilityKey.privateKey,
    eligibilityKeyId,
  );
  const proof = await buildActiveEligibilityDirectoryRecordProofV3({
    checkpoint,
    records: [record],
    publicVoterId,
  });
  const policy: OfflineVerificationPolicyV3 = {
    schemaVersion: "qualified-opinion.vote-proof-verification-policy.v3",
    policyId: "directory-fixture-policy",
    identityAttestationPolicies: [
      {
        audience,
        debugAllowed: false,
        expectedEnvironment,
        imageDigest,
        issuer: GOOGLE_CONFIDENTIAL_SPACE_ISSUER,
        memoryMonitoringDisabled: true,
        projectId,
        requireExactEnvironment: true,
        serviceAccount,
        stable: true,
        trustedRootCertificateSha256: [pki.rootFingerprint],
        validFrom: new Date(now - 60_000).toISOString(),
        validUntil: null,
        webauthnOrigin: origin,
        webauthnRpId: rpId,
      },
    ],
    serverKeys: [
      {
        algorithm: "Ed25519",
        keyId: eligibilityKeyId,
        publicKeySpki: eligibilityPublicKeySpki,
        purpose: "eligibility",
        validFrom: new Date(now - 60_000).toISOString(),
        validUntil: null,
      },
    ],
    votingPolicies: [
      {
        protocolBindingSha256: bindingSha256,
        protocolVersion: VOTE_EVENT_SCHEMA_V3,
        transparencyLogId: "directory-fixture-log",
        validFrom: new Date(now - 60_000).toISOString(),
        validUntil: null,
        voteServiceAudience: binding.audience,
      },
    ],
  };
  const expected = {
    directoryId,
    instanceId,
    protocolBindingSha256: bindingSha256,
    qualificationClaim: "active-law-graduate",
    reviewerAuthority: instanceId,
    subjectIssuer: subject.issuer,
    subjectKeyScheme: subject.scheme,
  };
  return { expected, policy, proof };
}

describe("offline active eligibility directory verifier", () => {
  test("verifies the exact receipt, attestation, eligibility, decision and membership chain", async () => {
    const input = await fixture();
    const asOf = await verifyActiveEligibilityDirectoryRecordV3(input);
    if (!asOf.ok) throw new Error(asOf.errors.join("; "));
    expect(asOf.ok).toBe(true);
    expect(asOf.current).toBe(false);

    expect(
      await verifyActiveEligibilityDirectoryRecordV3({
        ...input,
        witnessedCurrentHead: {
          checkpointSha256: input.proof.checkpoint.payloadSha256,
          directoryId: input.proof.checkpoint.payload.directoryId,
          sequence: input.proof.checkpoint.payload.sequence,
        },
      }),
    ).toMatchObject({ ok: true, current: true });
  });

  test("rejects a stale or equivocal checkpoint against the witnessed head", async () => {
    const input = await fixture();
    const result = await verifyActiveEligibilityDirectoryRecordV3({
      ...input,
      witnessedCurrentHead: {
        checkpointSha256: Buffer.alloc(32, 9).toString("base64url"),
        directoryId: input.proof.checkpoint.payload.directoryId,
        sequence: input.proof.checkpoint.payload.sequence + 1,
      },
    });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected stale checkpoint rejection");
    expect(result.errors.join(";")).toContain(
      "directory_checkpoint_stale_or_equivocal",
    );
  });

  test("rejects an attestation token not bound to the receipt", async () => {
    const input = await fixture();
    input.proof.record.registration.attestationToken = `${input.proof.record.registration.attestationToken}x`;
    const result = await verifyActiveEligibilityDirectoryRecordV3(input);
    expect(result.ok).toBe(false);
  });

  test("rejects an invalid passkey proof even when every outer record is signed around it", async () => {
    const input = await fixture((passkey) => {
      const signature = Buffer.from(
        passkey.proofOfPossession.assertion.signature,
        "base64url",
      );
      signature[signature.length - 1] ^= 1;
      passkey.proofOfPossession.assertion.signature = signature.toString("base64url");
    });
    const result = await verifyActiveEligibilityDirectoryRecordV3(input);
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected passkey proof rejection");
    expect(result.errors.join(";")).toContain(
      "directory_record_chain:identity_passkey_proof_invalid_signature",
    );
  });
});
