import { describe, expect, test } from "bun:test";
import {
  ACTIVE_ELIGIBILITY_DIRECTORY_RECORD_SCHEMA_V3,
  activeEligibilityDirectoryRecordSha256V3,
  assertActiveEligibilityDirectoryCheckpointV3,
  assertActiveEligibilityDirectoryRecordV3,
  attachDetachedSignature,
  buildActiveEligibilityDirectoryBundleV3,
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
  verifyActiveEligibilityDirectoryBundleIntegrityV3,
  verifyActiveEligibilityDirectoryRecordProofIntegrityV3,
} from "./index";

function digest(byte: number) {
  return Buffer.alloc(32, byte).toString("base64url");
}

const signature = {
  algorithm: "Ed25519" as const,
  keyId: "eligibility-key",
  value: Buffer.alloc(64, 3).toString("base64url"),
};

async function recordFixture(input: {
  byte: number;
  publicVoterId: string;
}) {
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
    key: `subject-${input.byte}`,
  };
  const registryEvidence = buildRegistryEvidenceV3({
    reviewId: `review-${input.byte}`,
    reviewerAuthority: "org.example",
    subject,
    recordUrl: `https://registry.example/${input.byte}`,
    checkedFullName: `Person ${input.byte}`,
    checkedEmail: `person-${input.byte}@example.test`,
    checkedAt: "2026-07-29T10:00:00.000Z",
  });
  const identityPolicy = buildIdentityAttestationPolicyV3({
    policyId: "identity-policy",
    audience: "email-verification",
    imageDigest: `sha256:${"a".repeat(64)}`,
    projectId: "project-a",
    serviceAccount: "verifier@example.test",
    expectedEnvironment: {
      QO_WEBAUTHN_ORIGIN: "https://example.test",
      QO_WEBAUTHN_RP_ID: "example.test",
    },
    allowDebug: false,
    pkiRootCertificateSha256: "AA:BB",
    identityOrigin: "https://example.test",
    rpId: "example.test",
  });
  const registrationPayload = {
    schema: "qualified-opinion.email-control-passkey.v3",
    claimedFullName: `Person ${input.byte}`,
    normalizedEmail: `person-${input.byte}@example.test`,
  };
  const registrationPayloadSha256 = await canonicalJsonSha256(registrationPayload);
  const assertionPayload = await buildEligibilityAssertionV3({
    assertionId: `assertion-${input.byte}`,
    publicVoterId: input.publicVoterId,
    binding,
    identityProof: {
      proofId: `proof-${input.byte}`,
      payloadSha256: registrationPayloadSha256,
    },
    identityAttestationPolicy: identityPolicy,
    rootKey: {
      credentialId: `credential-${input.byte}`,
      publicKeySpkiSha256: digest(input.byte),
    },
    qualificationClaim: "active_attorney",
    subject,
    registryEvidence,
    issuedAt: "2026-07-29T11:00:00.000Z",
    issuerKeyId: signature.keyId,
  });
  const assertion = await attachDetachedSignature(assertionPayload, signature);
  const decisionPayload = buildEligibilityDecisionV3({
    decisionId: `decision-${input.byte}`,
    assertionSha256: assertion.payloadSha256,
    publicVoterId: input.publicVoterId,
    sequence: 1,
    status: "active",
    reason: "initial_approval",
    effectiveAt: "2026-07-29T11:00:00.000Z",
    issuerKeyId: signature.keyId,
  });
  const decision = await attachDetachedSignature(decisionPayload, signature);
  return buildActiveEligibilityDirectoryRecordV3({
    publicVoterId: input.publicVoterId,
    registration: {
      proofId: `proof-${input.byte}`,
      payload: registrationPayload,
      payloadSha256: registrationPayloadSha256,
      attestationToken: ["header", `token-${input.byte}`, "signature"]
        .map((part) => Buffer.from(part).toString("base64url"))
        .join("."),
    },
    eligibilityAssertion: assertion,
    eligibilityDecision: decision,
  });
}

async function checkpointFixture(
  records: Awaited<ReturnType<typeof recordFixture>>[],
  sequence = 1,
) {
  const leaves = await buildActiveEligibilityDirectoryLeavesV3(records);
  const payload = await buildActiveEligibilityDirectoryCheckpointV3({
    directoryId: "org.example:active-eligibility",
    instanceId: "org.example",
    protocolBindingSha256: digest(8),
    sequence,
    previousCheckpointSha256: sequence === 1 ? null : digest(9),
    issuedAt: "2026-07-29T12:00:00.000Z",
    issuerKeyId: signature.keyId,
    leaves,
  });
  return attachDetachedSignature(payload, signature);
}

describe("active eligibility directory V3", () => {
  test("commits to one deterministic complete sorted current set", async () => {
    const first = await recordFixture({
      byte: 11,
      publicVoterId: "10000000-0000-4000-8000-000000000001",
    });
    const second = await recordFixture({
      byte: 12,
      publicVoterId: "20000000-0000-4000-8000-000000000002",
    });
    const checkpoint = await checkpointFixture([second, first]);
    const bundle = buildActiveEligibilityDirectoryBundleV3({
      checkpoint,
      records: [second, first],
    });

    expect(checkpoint.payload.treeSize).toBe(2);
    expect(
      (await buildActiveEligibilityDirectoryLeavesV3([second, first])).map(
        (leaf) => leaf.publicVoterId,
      ),
    ).toEqual([first.publicVoterId, second.publicVoterId]);
    expect(await verifyActiveEligibilityDirectoryBundleIntegrityV3(bundle)).toEqual({
      ok: true,
      value: bundle,
    });
  });

  test("rejects omitted, added, duplicated, and mutated record bodies", async () => {
    const first = await recordFixture({
      byte: 21,
      publicVoterId: "30000000-0000-4000-8000-000000000003",
    });
    const second = await recordFixture({
      byte: 22,
      publicVoterId: "40000000-0000-4000-8000-000000000004",
    });
    const checkpoint = await checkpointFixture([first, second]);

    expect(
      (
        await verifyActiveEligibilityDirectoryBundleIntegrityV3({
          schema: "qualified-opinion.active-eligibility-directory-bundle.v3",
          checkpoint,
          records: [first],
        })
      ).ok,
    ).toBe(false);
    expect(
      (
        await verifyActiveEligibilityDirectoryBundleIntegrityV3({
          schema: "qualified-opinion.active-eligibility-directory-bundle.v3",
          checkpoint,
          records: [first, second, structuredClone(second)],
        })
      ).ok,
    ).toBe(false);

    const mutated = structuredClone(second);
    (
      mutated.registration.payload as {
        normalizedEmail: string;
      }
    ).normalizedEmail = "changed@example.test";
    mutated.registration.payloadSha256 = await canonicalJsonSha256(
      mutated.registration.payload,
    );
    expect(
      (
        await verifyActiveEligibilityDirectoryBundleIntegrityV3({
          schema: "qualified-opinion.active-eligibility-directory-bundle.v3",
          checkpoint,
          records: [first, mutated],
        })
      ).ok,
    ).toBe(false);
  });

  test("proves one record without disclosing every record body", async () => {
    const first = await recordFixture({
      byte: 31,
      publicVoterId: "50000000-0000-4000-8000-000000000005",
    });
    const second = await recordFixture({
      byte: 32,
      publicVoterId: "60000000-0000-4000-8000-000000000006",
    });
    const checkpoint = await checkpointFixture([first, second]);
    const proof = await buildActiveEligibilityDirectoryRecordProofV3({
      checkpoint,
      records: [second, first],
      publicVoterId: second.publicVoterId,
    });

    expect(await verifyActiveEligibilityDirectoryRecordProofIntegrityV3(proof)).toEqual(
      { ok: true, value: proof },
    );
    const tampered = structuredClone(proof);
    tampered.auditPath[0] = digest(99);
    expect(
      (await verifyActiveEligibilityDirectoryRecordProofIntegrityV3(tampered)).ok,
    ).toBe(false);
  });

  test("rejects extension fields and invalid checkpoint predecessor chains", async () => {
    const record = await recordFixture({
      byte: 41,
      publicVoterId: "70000000-0000-4000-8000-000000000007",
    });
    const extended = structuredClone(record) as typeof record & {
      historicalVotes?: unknown;
    };
    extended.historicalVotes = [];
    expect(() => assertActiveEligibilityDirectoryRecordV3(extended)).toThrow(
      "must contain exactly",
    );

    const checkpoint = (await checkpointFixture([record])).payload;
    const invalid = {
      ...checkpoint,
      previousCheckpointSha256: digest(1),
    };
    expect(() => assertActiveEligibilityDirectoryCheckpointV3(invalid)).toThrow(
      "must be null at sequence 1",
    );
  });

  test("record digests cover the exact canonical record", async () => {
    const record = await recordFixture({
      byte: 51,
      publicVoterId: "80000000-0000-4000-8000-000000000008",
    });
    expect(record.schema).toBe(ACTIVE_ELIGIBILITY_DIRECTORY_RECORD_SCHEMA_V3);
    expect(await activeEligibilityDirectoryRecordSha256V3(record)).toHaveLength(43);
  });
});
