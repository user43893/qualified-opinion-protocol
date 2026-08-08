import { describe, expect, setDefaultTimeout, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalizeJson, sha256Base64Url } from "@qualified-opinion/protocol";
import { runCli } from "./cli";
import { verificationPolicySha256 } from "./policy";
import {
  type CryptographicV3CheckpointFixture,
  createGenericV3CryptographicCheckpointFixture,
} from "./testing/fixture";
import { verifyDownloadedVoteProof } from "./verifier";
import { verifyEligibilityDirectoryWitnessForAuthorization } from "./verifier-v3";

setDefaultTimeout(30_000);

let cachedFixture: Promise<CryptographicV3CheckpointFixture> | undefined;

async function fixture() {
  cachedFixture ??= createGenericV3CryptographicCheckpointFixture();
  return structuredClone(await cachedFixture);
}

async function verify(input: CryptographicV3CheckpointFixture) {
  return verifyDownloadedVoteProof({
    bundle: input.bundle,
    expectedPolicySha256: await verificationPolicySha256(input.policy),
    policy: input.policy,
    tallyCheckpoint: input.tallyCheckpoint,
  });
}

describe("offline V3 question-only vote-proof verification", () => {
  test("verifies real PKI and proof cryptography while allowing image-owned environment", async () => {
    const input = await fixture();
    const result = await verify(input);

    expect(result.cryptographicallyValid).toBe(true);
    expect(result.verificationTrusted).toBe(true);
    expect(result.protocolVersion).toBe("qualified-opinion.vote-event.v3");
    expect(result.questionAuthorizationAttestation).toMatchObject({
      imageDigest: `sha256:${"cd".repeat(32)}`,
      projectId: "qualified-opinion-v3-fixture",
    });
    expect(result.completeness).toBe("tally-checkpoint");
    expect(result.counted).toBe(true);
    expect(result.status).toBe("counted");
    expect(result.tallyCheckpointState).toMatchObject({
      schema: "qualified-voting.vote-state-at-checkpoint.v3",
      status: "counted_at_checkpoint",
      completenessScope: "complete_question_log_prefix",
    });
    expect(result.checks.every((entry) => entry.ok)).toBe(true);
    expect(check(result, "eligibility_directory_witness")).toMatchObject({
      ok: true,
    });
    expect(result.warnings.join(" ")).toContain("complete contiguous prefix");
  }, 30_000);

  test("verifies the embedded directory witness at authorization issuance time, not audit time", async () => {
    const input = await fixture();
    const identityPolicy = input.policy.identityAttestationPolicies[0];
    if (!identityPolicy) throw new Error("fixture identity policy missing");

    expect(() =>
      verifyEligibilityDirectoryWitnessForAuthorization({
        attestationPolicy: identityPolicy,
        authorization: input.bundle.questionAuthorization.payload,
      }),
    ).not.toThrow();
  });

  test("rejects a forged embedded witness signature and external key-pin substitution", async () => {
    const input = await fixture();
    const identityPolicy = input.policy.identityAttestationPolicies[0];
    if (!identityPolicy) throw new Error("fixture identity policy missing");
    const witness =
      input.bundle.questionAuthorization.payload.registryCheckpoint.witness;
    const envelope = JSON.parse(witness.canonicalEnvelope) as {
      signature: { value: string };
    };
    envelope.signature.value = "A".repeat(86);
    witness.canonicalEnvelope = canonicalizeJson(envelope);
    witness.envelopeSha256 = await sha256Base64Url(witness.canonicalEnvelope);

    expect(() =>
      verifyEligibilityDirectoryWitnessForAuthorization({
        attestationPolicy: identityPolicy,
        authorization: input.bundle.questionAuthorization.payload,
      }),
    ).toThrow();

    const fresh = await fixture();
    const freshPolicy = fresh.policy.identityAttestationPolicies[0];
    if (!freshPolicy) throw new Error("fixture identity policy missing");
    freshPolicy.expectedEnvironment.QO_ELIGIBILITY_DIRECTORY_WITNESS_PUBLIC_KEY_SPKI_SHA256 =
      "0".repeat(64);
    expect(() =>
      verifyEligibilityDirectoryWitnessForAuthorization({
        attestationPolicy: freshPolicy,
        authorization: fresh.bundle.questionAuthorization.payload,
      }),
    ).toThrow();
  });

  test("rejects stale, wrong-source, and wrong-latest directory witness commitments", async () => {
    const stale = await fixture();
    const stalePolicy = stale.policy.identityAttestationPolicies[0];
    if (!stalePolicy) throw new Error("fixture identity policy missing");
    stale.bundle.questionAuthorization.payload.issuedAt = new Date(
      Date.parse(stale.bundle.questionAuthorization.payload.issuedAt) + 301_000,
    ).toISOString();
    expect(() =>
      verifyEligibilityDirectoryWitnessForAuthorization({
        attestationPolicy: stalePolicy,
        authorization: stale.bundle.questionAuthorization.payload,
      }),
    ).toThrow("eligibility_directory_witness_invalid");

    const wrongSource = await fixture();
    const wrongSourcePolicy = wrongSource.policy.identityAttestationPolicies[0];
    if (!wrongSourcePolicy) throw new Error("fixture identity policy missing");
    wrongSourcePolicy.expectedEnvironment.QO_ELIGIBILITY_DIRECTORY_WITNESS_SOURCE_REVISION =
      "cd".repeat(20);
    expect(() =>
      verifyEligibilityDirectoryWitnessForAuthorization({
        attestationPolicy: wrongSourcePolicy,
        authorization: wrongSource.bundle.questionAuthorization.payload,
      }),
    ).toThrow("eligibility_directory_witness_invalid");

    const wrongLatest = await fixture();
    const wrongLatestPolicy = wrongLatest.policy.identityAttestationPolicies[0];
    if (!wrongLatestPolicy) throw new Error("fixture identity policy missing");
    wrongLatest.bundle.questionAuthorization.payload.registryCheckpoint.sha256 =
      "A".repeat(43);
    expect(() =>
      verifyEligibilityDirectoryWitnessForAuthorization({
        attestationPolicy: wrongLatestPolicy,
        authorization: wrongLatest.bundle.questionAuthorization.payload,
      }),
    ).toThrow("eligibility_directory_witness_invalid");
  });

  test.each(["tampered", "stale", "wrong-source", "wrong-checkpoint"] as const)(
    "rejects a %s directory witness carried only by a non-target tally authorization",
    async (failure) => {
      const input = await createGenericV3CryptographicCheckpointFixture({
        nonTargetTallyAuthorizationWitness: failure,
      });
      const result = await verify(input);

      expect(check(result, "eligibility_directory_witness")).toMatchObject({
        ok: true,
      });
      expect(check(result, "tally_checkpoint")).toMatchObject({ ok: false });
      expect(check(result, "tally_checkpoint").error).toContain("witness");
      expect(result.cryptographicallyValid).toBe(false);
    },
    30_000,
  );

  test("rejects a missing witness carried only by a non-target tally authorization", async () => {
    const input = await createGenericV3CryptographicCheckpointFixture({
      nonTargetTallyAuthorizationWitness: "valid",
    });
    const nonTarget = input.tallyCheckpoint.inputSet.questionVotingAuthorizations
      .filter(
        (authorization) =>
          authorization.payloadSha256 !==
          input.bundle.questionAuthorization.payloadSha256,
      )
      .at(0);
    if (!nonTarget) throw new Error("non-target authorization missing");
    (
      nonTarget.payload.registryCheckpoint as Partial<
        typeof nonTarget.payload.registryCheckpoint
      >
    ).witness = undefined;

    const result = await verify(input);
    expect(check(result, "eligibility_directory_witness")).toMatchObject({
      ok: true,
    });
    expect(check(result, "tally_checkpoint")).toMatchObject({ ok: false });
    expect(check(result, "tally_checkpoint").error).toContain("witness");
    expect(result.cryptographicallyValid).toBe(false);
  }, 30_000);

  test("keeps a valid standalone V3 bundle at explicit inclusion-only semantics", async () => {
    const input = await fixture();
    const result = await verifyDownloadedVoteProof({
      bundle: input.bundle,
      expectedPolicySha256: await verificationPolicySha256(input.policy),
      policy: input.policy,
    });

    expect(result.cryptographicallyValid).toBe(true);
    expect(result.includedReceiptCounted).toBe(true);
    expect(result.counted).toBe(false);
    expect(result.completeness).toBe("inclusion-only");
    expect(result.status).toBe("checkpoint_unverified");
    expect(result.warnings.join(" ")).toContain(
      "initial counted acceptance and inclusion",
    );
    expect(result.warnings.join(" ")).toContain(
      "later replacement, withdrawal, or adjudication",
    );
  });

  test("strictly rejects unknown V3 bundle fields", async () => {
    const input = await fixture();
    const malformed = {
      ...input.bundle,
      identityProof: { leaked: true },
    };
    const result = await verifyDownloadedVoteProof({
      bundle: malformed,
      expectedPolicySha256: await verificationPolicySha256(input.policy),
      policy: input.policy,
    });

    expect(result.cryptographicallyValid).toBe(false);
    expect(result.protocolVersion).toBe("qualified-opinion.vote-event.v3");
    expect(result.errors.join(" ")).toContain("$.identityProof is not allowed");
  });

  test("rejects a forged question-key vote signature", async () => {
    const input = await fixture();
    input.bundle.voteEvent.signature.value = "AA";
    const result = await verify(input);

    expect(result.cryptographicallyValid).toBe(false);
    expect(check(result, "question_vote_signature")).toMatchObject({
      ok: false,
      error: "invalid_question_vote_signature",
    });
    expect(check(result, "tally_checkpoint").error).toContain(
      "bundle verification failed",
    );
  });

  test("rejects an authorization token whose PKI signature was changed", async () => {
    const input = await fixture();
    const parts = input.bundle.questionAuthorization.attestationToken.split(".");
    const signature = parts[2];
    if (!signature) throw new Error("fixture attestation signature missing");
    parts[2] = `${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
    input.bundle.questionAuthorization.attestationToken = parts.join(".");
    const result = await verify(input);

    expect(result.cryptographicallyValid).toBe(false);
    expect(check(result, "question_authorization_attestation")).toMatchObject({
      ok: false,
      error: "invalid_attestation_signature",
    });
  });

  test("requires the exact independently pinned V3 workload environment", async () => {
    const input = await fixture();
    const identityPolicy = input.policy.identityAttestationPolicies[0];
    if (!identityPolicy) throw new Error("fixture identity policy missing");
    identityPolicy.expectedEnvironment.QO_RELEASE_IMAGE = "wrong-image";
    const result = await verify(input);

    expect(result.cryptographicallyValid).toBe(false);
    expect(check(result, "question_authorization_attestation").error).toContain(
      "unexpected_attestation_environment:QO_RELEASE_IMAGE",
    );
  });

  test("rejects unreviewed attested V3 operator overrides", async () => {
    const input = await createGenericV3CryptographicCheckpointFixture({
      environmentOverride: {
        QO_UNREVIEWED_OVERRIDE: "enabled",
      },
    });
    const result = await verify(input);

    expect(result.cryptographicallyValid).toBe(false);
    expect(check(result, "question_authorization_attestation").error).toContain(
      "unexpected_attestation_environment_keys",
    );
  });

  test("rejects a missing expected V3 effective environment value", async () => {
    const input = await fixture();
    const identityPolicy = input.policy.identityAttestationPolicies[0];
    if (!identityPolicy) throw new Error("fixture identity policy missing");
    identityPolicy.expectedEnvironment.QO_REQUIRED_BUT_MISSING = "value";
    const result = await verify(input);

    expect(result.cryptographicallyValid).toBe(false);
    expect(check(result, "question_authorization_attestation").error).toContain(
      "unexpected_attestation_environment:QO_REQUIRED_BUT_MISSING",
    );
  });

  test("uses an expected V3 override as the effective value", async () => {
    const input = await createGenericV3CryptographicCheckpointFixture({
      environment: {
        QO_WEBAUTHN_ORIGIN: "https://image-default.invalid",
      },
      environmentOverride: {
        QO_WEBAUTHN_ORIGIN: "https://proof-v3-fixture.example.test",
      },
    });
    const result = await verify(input);

    expect(result.cryptographicallyValid).toBe(true);
    expect(check(result, "question_authorization_attestation")).toMatchObject({
      ok: true,
    });
  });

  test("rejects a wrong V3 effective environment override", async () => {
    const input = await createGenericV3CryptographicCheckpointFixture({
      environmentOverride: {
        QO_WEBAUTHN_ORIGIN: "https://wrong.invalid",
      },
    });
    const result = await verify(input);

    expect(result.cryptographicallyValid).toBe(false);
    expect(check(result, "question_authorization_attestation").error).toContain(
      "unexpected_attestation_environment:QO_WEBAUTHN_ORIGIN",
    );
  });

  test("rejects a forged signed transparency head", async () => {
    const input = await fixture();
    input.bundle.voteEventTransparency.treeHead.signature.value = "AA";
    const result = await verify(input);

    expect(result.cryptographicallyValid).toBe(false);
    expect(check(result, "event_transparency_signature")).toMatchObject({
      ok: false,
      error: "invalid_receipt_signature",
    });
  });

  test("rejects a tampered V3 tally snapshot signature", async () => {
    const input = await fixture();
    input.tallyCheckpoint.snapshot.signature.value = "AA";
    const result = await verify(input);

    expect(result.cryptographicallyValid).toBe(false);
    expect(check(result, "tally_checkpoint").error).toContain("snapshot:");
    expect(check(result, "tally_checkpoint").error).toContain("invalid_signature");
  });

  test("rejects a V3 binding that is not in the independently pinned policy", async () => {
    const input = await fixture();
    const votingPolicy = input.policy.votingPolicies[0];
    if (!votingPolicy) throw new Error("fixture voting policy missing");
    votingPolicy.protocolBindingSha256 = "A".repeat(43);
    const result = await verify(input);

    expect(result.cryptographicallyValid).toBe(false);
    expect(check(result, "voting_policy").error).toBe("voting_policy_not_found");
  });

  test("CLI dispatches V3 and requires the verified tally supplement for a counted claim", async () => {
    const input = await fixture();
    const directory = await mkdtemp(join(tmpdir(), "qualified-opinion-v3-cli-"));
    try {
      const bundlePath = join(directory, "bundle.json");
      const policyPath = join(directory, "policy.json");
      const tallyPath = join(directory, "tally.json");
      await Promise.all([
        writeFile(bundlePath, JSON.stringify({ bundle: input.bundle })),
        writeFile(policyPath, JSON.stringify(input.policy)),
        writeFile(tallyPath, JSON.stringify(input.tallyCheckpoint)),
      ]);
      const hash = await verificationPolicySha256(input.policy);
      const withoutTally: string[] = [];
      const inclusionExit = await runCli(
        [
          "--bundle",
          bundlePath,
          "--policy",
          policyPath,
          "--expected-policy-sha256",
          hash,
          "--require-counted",
        ],
        { stdout: (value) => withoutTally.push(value) },
      );
      expect(inclusionExit).toBe(3);
      expect(withoutTally.join("\n")).toContain("INCLUSION ONLY");

      const withTally: string[] = [];
      const countedExit = await runCli(
        [
          "--bundle",
          bundlePath,
          "--policy",
          policyPath,
          "--tally-snapshot",
          tallyPath,
          "--expected-policy-sha256",
          hash,
          "--require-counted",
        ],
        { stdout: (value) => withTally.push(value) },
      );
      expect(countedExit).toBe(0);
      expect(withTally.join("\n")).toContain("COUNTED AT SIGNED TALLY CHECKPOINT");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }, 30_000);
});

function check(result: Awaited<ReturnType<typeof verify>>, id: string) {
  const entry = result.checks.find((candidate) => candidate.id === id);
  if (!entry) throw new Error(`missing ${id} check`);
  return entry;
}
