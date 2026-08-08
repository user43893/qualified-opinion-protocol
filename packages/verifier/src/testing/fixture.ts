import { execFileSync } from "node:child_process";
import {
  type KeyObject,
  X509Certificate,
  createHash,
  sign as cryptoSign,
  generateKeyPairSync,
  randomBytes,
} from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type PublicVoteProofBundleV3,
  type SignedPayload,
  type TallyInputSetV3,
  type TallySnapshotV3,
  type TransparencyInclusionV3,
  attachDetachedSignature,
  base64UrlDecode,
  base64UrlEncode,
  buildBallotManifestV3,
  buildMerkleTreeHeadV3,
  buildProtocolBindingV3,
  buildPublicVoteProofBundleV3,
  buildQuestionVotingAuthorizationPayloadV3,
  buildQuestionVotingAuthorizationV3,
  buildTallyInputSetV3,
  buildTallyPolicyV3,
  buildTallySnapshotV3,
  buildVoteAcceptanceV3,
  buildVoteEventV3,
  canonicalJsonSha256,
  canonicalizeJson,
  createMerkleInclusionProof,
  questionVoteLogIdV3,
  sha256Base64Url,
} from "@qualified-opinion/protocol";
import { GOOGLE_CONFIDENTIAL_SPACE_ISSUER } from "../gcs";
import type { EmailVerificationPasskeyBindingV3 } from "../identity-receipt";
import type { OfflineVerificationPolicyV3 } from "../policy";
import {
  type TransparencyWitnessStatusV3,
  signWitnessStatus,
} from "../witness-status-v3";

export type CryptographicV3ProofFixture = {
  bundle: PublicVoteProofBundleV3;
  policy: OfflineVerificationPolicyV3;
};

export type CryptographicV3CheckpointFixture = CryptographicV3ProofFixture & {
  tallyCheckpoint: {
    inputSet: TallyInputSetV3;
    snapshot: SignedPayload<TallySnapshotV3>;
  };
};

export type CryptographicV3AttestationEnvironmentFixture = {
  environment?: Record<string, string>;
  environmentOverride?: Record<string, string>;
  nonTargetTallyAuthorizationWitness?:
    | "valid"
    | "tampered"
    | "stale"
    | "wrong-checkpoint"
    | "wrong-source";
};

export function createIdentityPasskeyBindingFixture(input: {
  origin: string;
  rpId: string;
  signCount?: number;
}): EmailVerificationPasskeyBindingV3 {
  const signCount = input.signCount ?? 1;
  if (!Number.isSafeInteger(signCount) || signCount < 0) {
    throw new Error("fixture passkey sign counter is invalid");
  }
  const keyPair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const credentialId = randomBytes(32).toString("base64url");
  const userHandle = randomBytes(32).toString("base64url");
  const registrationChallenge = randomBytes(32).toString("base64url");
  const registrationClientData = Buffer.from(
    JSON.stringify({
      type: "webauthn.create",
      challenge: registrationChallenge,
      origin: input.origin,
      crossOrigin: false,
    }),
  );
  const registrationAuthenticatorData = createRegistrationAuthenticatorData({
    credentialId,
    keyJwk: keyPair.publicKey.export({ format: "jwk" }),
    rpId: input.rpId,
  });
  const attestationObject = encodeCbor(
    new Map<unknown, unknown>([
      ["fmt", "none"],
      ["attStmt", new Map()],
      ["authData", registrationAuthenticatorData],
    ]),
  );
  const assertionChallenge = randomBytes(32).toString("base64url");
  const assertion = webAuthnAssertion({
    challenge: assertionChallenge,
    credentialId,
    origin: input.origin,
    privateKey: keyPair.privateKey,
    rpId: input.rpId,
    signCount,
  });
  return {
    algorithm: "ES256",
    credentialId,
    origin: input.origin,
    proofOfPossession: {
      registration: {
        attestationObject: attestationObject.toString("base64url"),
        challenge: registrationChallenge,
        clientDataJson: registrationClientData.toString("base64url"),
      },
      assertion: {
        authenticatorData: assertion.authenticatorData,
        challenge: assertion.challenge,
        clientDataJson: assertion.clientDataJson,
        signature: assertion.signature,
        userHandle,
      },
    },
    publicKeySpki: spki(keyPair.publicKey),
    rpId: input.rpId,
    signCount,
    transports: ["internal"],
    userHandle,
  };
}

export async function createGenericV3CryptographicProofFixture(
  attestationEnvironment?: CryptographicV3AttestationEnvironmentFixture,
): Promise<CryptographicV3ProofFixture> {
  const fixture = await createV3ProofFixture(false, attestationEnvironment);
  return { bundle: fixture.bundle, policy: fixture.policy };
}

export async function createGenericV3CryptographicCheckpointFixture(
  attestationEnvironment?: CryptographicV3AttestationEnvironmentFixture,
): Promise<CryptographicV3CheckpointFixture> {
  const fixture = await createV3ProofFixture(true, attestationEnvironment);
  if (!fixture.tallyCheckpoint) {
    throw new Error("generic V3 fixture did not create a tally checkpoint");
  }
  return {
    bundle: fixture.bundle,
    policy: fixture.policy,
    tallyCheckpoint: fixture.tallyCheckpoint,
  };
}

async function createV3ProofFixture(
  includeTallyCheckpoint: boolean,
  attestationEnvironment: CryptographicV3AttestationEnvironmentFixture = {},
): Promise<
  CryptographicV3ProofFixture & {
    tallyCheckpoint?: CryptographicV3CheckpointFixture["tallyCheckpoint"];
  }
> {
  const epoch = Math.ceil(Date.now() / 1_000) * 1_000 + 30_000;
  const at = (offset: number) => new Date(epoch + offset).toISOString();
  const origin = "https://proof-v3-fixture.example.test";
  const rpId = "proof-v3-fixture.example.test";
  const authorizationAudience = "https://confidential-v3-verifier.example.test";
  const voteAudience = "https://vote-v3.example.test";
  const imageDigest = `sha256:${"cd".repeat(32)}`;
  const projectId = "qualified-opinion-v3-fixture";
  const serviceAccount =
    "proof-v3-fixture@qualified-opinion-v3-fixture.iam.gserviceaccount.com";
  const witnessSigningKey = generateKeyPairSync("ed25519");
  const witnessPrivateKey = witnessSigningKey.privateKey
    .export({ format: "der", type: "pkcs8" })
    .toString("base64url");
  const witnessPublicKeySpkiSha256 = createHash("sha256")
    .update(witnessSigningKey.publicKey.export({ format: "der", type: "spki" }))
    .digest("hex");
  const witnessSourceRevision = "ab".repeat(20);
  const witnessTrustRootSha256 = "ef".repeat(32);
  const globalVoteLogId = "fixture-global-vote-log";
  const witnessId = "fixture-gcp-directory-witness";
  const expectedEnvironment = {
    QO_APP_URL: origin,
    QO_ELIGIBILITY_DIRECTORY_WITNESS_ID: witnessId,
    QO_ELIGIBILITY_DIRECTORY_WITNESS_MAX_AGE_SECONDS: "300",
    QO_ELIGIBILITY_DIRECTORY_WITNESS_PUBLIC_KEY_SPKI_SHA256: witnessPublicKeySpkiSha256,
    QO_ELIGIBILITY_DIRECTORY_WITNESS_SOURCE_REVISION: witnessSourceRevision,
    QO_ELIGIBILITY_DIRECTORY_WITNESS_STATUS_URL:
      "https://gcp-witness.proof-v3-fixture.example.test/status",
    QO_ELIGIBILITY_DIRECTORY_WITNESS_TRUST_ROOT_SHA256: witnessTrustRootSha256,
    QO_VOTE_LOG_ID: globalVoteLogId,
    QO_WEBAUTHN_ORIGIN: origin,
    QO_WEBAUTHN_RP_ID: rpId,
  };
  const questionKey = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const nonTargetQuestionKey = attestationEnvironment.nonTargetTallyAuthorizationWitness
    ? generateKeyPairSync("ec", { namedCurve: "prime256v1" })
    : null;
  const receiptKey = generateKeyPairSync("ed25519");
  const eligibilityKey = generateKeyPairSync("ed25519");
  const questionPublicSpki = spki(questionKey.publicKey);
  const receiptPublicSpki = spki(receiptKey.publicKey);
  const eligibilityPublicSpki = spki(eligibilityKey.publicKey);
  const questionKeyId = await sha256Base64Url(base64UrlDecode(questionPublicSpki));
  const nonTargetQuestionPublicSpki = nonTargetQuestionKey
    ? spki(nonTargetQuestionKey.publicKey)
    : null;
  const nonTargetQuestionKeyId = nonTargetQuestionPublicSpki
    ? await sha256Base64Url(base64UrlDecode(nonTargetQuestionPublicSpki))
    : null;
  const receiptKeyId = `sha256:${await sha256Base64Url(
    base64UrlDecode(receiptPublicSpki),
  )}`;
  const eligibilityKeyId = `sha256:${await sha256Base64Url(
    base64UrlDecode(eligibilityPublicSpki),
  )}`;
  const tallyPolicy = buildTallyPolicyV3({
    policyId: "org.example.qualified-opinion-fixture.tally.v3",
    instanceId: "org.example.qualified-opinion-fixture",
    calculationVersion: "question-private-v3",
    positionEligibility: {
      requiredStatus: "counted",
      requireCurrent: true,
      requirePositiveCountWeight: true,
    },
    directVote: {
      precedence: "latest_event_per_nullifier_and_question",
      deduplicationKey: "question_nullifier_and_question_id",
      eventSelection: "highest_sequence",
      adjudicationSelection: "highest_sequence",
      countedDecision: "counted",
      countedEventTypes: ["cast", "replace"],
      groupCode: "qualified",
      weight: 1,
    },
    qualifiedVote: {
      eventSchema: "qualified-opinion.vote-event.v3",
      authorizationSchema: "qualified-opinion.question-voting-authorization.v3",
      authorizationVerification: "pinned_confidential_space_attestation",
      eventSignature: "question_scoped_es256_key",
      eligibilityClaim: "active-law-graduate",
    },
    crossChannelPrecedence: { mode: "independent_channels" },
    sourcePositionRules: [],
    unmatchedSourcePositionTreatment: "exclude",
    rounding: { method: "decimal_to_fixed", percentageDecimalPlaces: 1 },
    publishedAt: at(-1_000),
  });
  const binding = buildProtocolBindingV3({
    instanceId: tallyPolicy.instanceId,
    instanceProfileSha256: await sha256Base64Url("v3-fixture-instance"),
    eligibilityPolicy: {
      id: "example-law-graduate-v3",
      sha256: await sha256Base64Url("v3-fixture-eligibility-policy"),
    },
    tallyPolicy: {
      id: tallyPolicy.policyId,
      sha256: await canonicalJsonSha256(tallyPolicy),
    },
    trustPolicy: {
      id: "example-confidential-space-v3",
      sha256: await sha256Base64Url("v3-fixture-trust-policy"),
    },
    audience: voteAudience,
    origin,
  });
  const questionId = "fixture-question-v3";
  const ballotId = "fixture-ballot-v3";
  const logId = await questionVoteLogIdV3({
    instanceId: tallyPolicy.instanceId,
    questionId,
  });
  const manifestPayload = buildBallotManifestV3({
    manifestId: "fixture-manifest-v3",
    ballotId,
    questionId,
    nullifierKeyEpoch: 1,
    revision: 1,
    binding,
    meaningChoices: [
      {
        id: "yes",
        slug: "yes",
        semanticCode: "YES",
        displayOrder: 0,
        isCounted: true,
      },
      {
        id: "no",
        slug: "no",
        semanticCode: "NO",
        displayOrder: 1,
        isCounted: true,
      },
    ],
    locale: "en",
    questionText: "Fixture question?",
    presentationChoices: [
      { id: "yes", label: "Yes", description: "" },
      { id: "no", label: "No", description: "" },
    ],
    publishedAt: at(0),
    issuerKeyId: receiptKeyId,
  });
  const questionManifest = await signEd25519(
    manifestPayload,
    receiptKey.privateKey,
    receiptKeyId,
  );
  const registryCheckpointSha256 = await sha256Base64Url(
    "v3-fixture-registry-checkpoint",
  );
  const witnessObservedAt = at(500);
  const witnessCheckpoint = await signEd25519(
    {
      schema: "qualified-opinion.transparency-tree-head.v3" as const,
      logId: globalVoteLogId,
      treeSize: 1,
      rootHash: await sha256Base64Url("fixture-witness-tree-root"),
      previousTreeHeadSha256: null,
      issuedAt: witnessObservedAt,
      issuerKeyId: receiptKeyId,
    },
    receiptKey.privateKey,
    receiptKeyId,
  );
  const witnessStatement: TransparencyWitnessStatusV3 = {
    schema: "qualified-opinion.transparency-witness-status.v3",
    witnessId,
    provider: "gcp-cloud-run",
    sourceRevision: witnessSourceRevision,
    trustRootId: "fixture-witness-trust-root",
    trustRootSha256: witnessTrustRootSha256,
    logId: globalVoteLogId,
    origin,
    status: "verified",
    lastAttemptAt: witnessObservedAt,
    lastSuccessAt: witnessObservedAt,
    consecutiveFailures: 0,
    latestVerified: {
      observedAt: witnessObservedAt,
      checkpoint: witnessCheckpoint,
      latestEntryByType: {
        eligibility_directory_checkpoint: {
          entryId: "00000000-0000-4000-8000-000000000777",
          entryPayloadHash: registryCheckpointSha256,
          entryType: "eligibility_directory_checkpoint",
          leafIndex: 0,
        },
      },
    },
    failure: null,
  };
  const registryCheckpointWitness = signWitnessStatus(
    witnessStatement,
    witnessPrivateKey,
    witnessPublicKeySpkiSha256,
  );
  const registryCheckpointWitnessCanonicalEnvelope = canonicalizeJson(
    registryCheckpointWitness,
  );
  const authorizationPayload = await buildQuestionVotingAuthorizationPayloadV3({
    binding,
    questionId,
    questionNullifier: await sha256Base64Url("v3-fixture-question-nullifier"),
    nullifierKeyEpoch: 1,
    questionKeyPublicKeySpki: questionPublicSpki,
    eligibilityClaim: "active-law-graduate",
    registryCheckpointId: "fixture-registry-checkpoint-v3",
    registryCheckpointSha256,
    registryCheckpointWitnessCanonicalEnvelope,
    registryCheckpointWitnessEnvelopeSha256: await sha256Base64Url(
      registryCheckpointWitnessCanonicalEnvelope,
    ),
    issuedAt: at(1_000),
    expiresAt: at(20 * 60_000),
    issuerAttestationAudience: authorizationAudience,
  });
  const pki = await generateAttestationPki();
  let attestationToken: string;
  let nonTargetAuthorization: PublicVoteProofBundleV3["questionAuthorization"] | null =
    null;
  try {
    attestationToken = signAttestationJwt({
      audience: authorizationAudience,
      certificates: pki.certificates,
      environment: {
        HOSTNAME: "proof-v3-fixture",
        NODE_ENV: "production",
        PATH: "/usr/local/bin:/usr/bin",
        PORT: "8080",
        ...expectedEnvironment,
        ...attestationEnvironment.environment,
      },
      environmentOverride: attestationEnvironment.environmentOverride ?? {},
      imageDigest,
      issuedAtSeconds: Math.floor(Date.parse(at(1_000)) / 1_000),
      leafPrivateKeyPem: pki.leafPrivateKeyPem,
      nonce: await canonicalJsonSha256(authorizationPayload),
      projectId,
      serviceAccount,
    });
    const nonTargetWitnessFailure =
      attestationEnvironment.nonTargetTallyAuthorizationWitness;
    if (
      nonTargetWitnessFailure &&
      nonTargetQuestionPublicSpki &&
      nonTargetQuestionKeyId
    ) {
      const nonTargetObservedAt =
        nonTargetWitnessFailure === "stale" ? at(-400_000) : at(750);
      const nonTargetCheckpointSha256 =
        nonTargetWitnessFailure === "wrong-checkpoint"
          ? await sha256Base64Url("wrong-non-target-directory-checkpoint")
          : registryCheckpointSha256;
      const nonTargetStatement = structuredClone(witnessStatement);
      nonTargetStatement.sourceRevision =
        nonTargetWitnessFailure === "wrong-source"
          ? "bc".repeat(20)
          : witnessSourceRevision;
      nonTargetStatement.lastAttemptAt = nonTargetObservedAt;
      nonTargetStatement.lastSuccessAt = nonTargetObservedAt;
      if (!nonTargetStatement.latestVerified) {
        throw new Error("fixture witness latest state missing");
      }
      nonTargetStatement.latestVerified.observedAt = nonTargetObservedAt;
      nonTargetStatement.latestVerified.checkpoint = await signEd25519(
        {
          ...witnessCheckpoint.payload,
          issuedAt: nonTargetObservedAt,
        },
        receiptKey.privateKey,
        receiptKeyId,
      );
      const nonTargetLatest =
        nonTargetStatement.latestVerified.latestEntryByType
          .eligibility_directory_checkpoint;
      if (!nonTargetLatest) {
        throw new Error("fixture witness checkpoint entry missing");
      }
      nonTargetLatest.entryPayloadHash = nonTargetCheckpointSha256;
      const nonTargetWitness = signWitnessStatus(
        nonTargetStatement,
        witnessPrivateKey,
        witnessPublicKeySpkiSha256,
      );
      if (nonTargetWitnessFailure === "tampered") {
        nonTargetWitness.signature.value = "A".repeat(86);
      }
      const nonTargetWitnessCanonicalEnvelope = canonicalizeJson(nonTargetWitness);
      const nonTargetAuthorizationPayload =
        await buildQuestionVotingAuthorizationPayloadV3({
          binding,
          questionId,
          questionNullifier: await sha256Base64Url(
            "v3-fixture-non-target-question-nullifier",
          ),
          nullifierKeyEpoch: 1,
          questionKeyPublicKeySpki: nonTargetQuestionPublicSpki,
          eligibilityClaim: "active-law-graduate",
          registryCheckpointId: "fixture-registry-checkpoint-v3",
          registryCheckpointSha256,
          registryCheckpointWitnessCanonicalEnvelope: nonTargetWitnessCanonicalEnvelope,
          registryCheckpointWitnessEnvelopeSha256: await sha256Base64Url(
            nonTargetWitnessCanonicalEnvelope,
          ),
          issuedAt: at(1_500),
          expiresAt: at(20 * 60_000),
          issuerAttestationAudience: authorizationAudience,
        });
      nonTargetAuthorization = await buildQuestionVotingAuthorizationV3({
        payload: nonTargetAuthorizationPayload,
        attestationToken: signAttestationJwt({
          audience: authorizationAudience,
          certificates: pki.certificates,
          environment: {
            HOSTNAME: "proof-v3-fixture",
            NODE_ENV: "production",
            PATH: "/usr/local/bin:/usr/bin",
            PORT: "8080",
            ...expectedEnvironment,
            ...attestationEnvironment.environment,
          },
          environmentOverride: attestationEnvironment.environmentOverride ?? {},
          imageDigest,
          issuedAtSeconds: Math.floor(Date.parse(at(1_500)) / 1_000),
          leafPrivateKeyPem: pki.leafPrivateKeyPem,
          nonce: await canonicalJsonSha256(nonTargetAuthorizationPayload),
          projectId,
          serviceAccount,
        }),
      });
      if (nonTargetAuthorization.payload.questionKey.keyId !== nonTargetQuestionKeyId) {
        throw new Error("fixture non-target question key mismatch");
      }
    }
  } finally {
    await pki.cleanup();
  }
  const questionAuthorization = await buildQuestionVotingAuthorizationV3({
    payload: authorizationPayload,
    attestationToken,
  });
  const votePayload = buildVoteEventV3({
    eventId: "fixture-event-v3",
    eventType: "cast",
    binding,
    questionNullifier: authorizationPayload.questionNullifier,
    authorizationSha256: questionAuthorization.payloadSha256,
    publicationMode: "private",
    ballotManifestSha256: questionManifest.payloadSha256,
    ballotId,
    questionId,
    choiceId: "yes",
    sequence: 1,
    previousEventSha256: null,
    challenge: randomBytes(32).toString("base64url"),
    issuedAt: at(2_000),
    questionKeyId,
  });
  const voteEvent = await signP256(votePayload, questionKey.privateKey, questionKeyId);
  const acceptance = await signEd25519(
    buildVoteAcceptanceV3({
      receiptId: "fixture-acceptance-v3",
      voteEventSha256: voteEvent.payloadSha256,
      status: "counted",
      logId,
      receivedAt: at(3_000),
      issuerKeyId: receiptKeyId,
    }),
    receiptKey.privateKey,
    receiptKeyId,
  );
  let nonTargetVoteEvent: SignedPayload<typeof votePayload> | null = null;
  let nonTargetAcceptance: typeof acceptance | null = null;
  if (nonTargetAuthorization && nonTargetQuestionKey && nonTargetQuestionKeyId) {
    nonTargetVoteEvent = await signP256(
      buildVoteEventV3({
        eventId: "fixture-non-target-event-v3",
        eventType: "cast",
        binding,
        questionNullifier: nonTargetAuthorization.payload.questionNullifier,
        authorizationSha256: nonTargetAuthorization.payloadSha256,
        publicationMode: "private",
        ballotManifestSha256: questionManifest.payloadSha256,
        ballotId,
        questionId,
        choiceId: "no",
        sequence: 1,
        previousEventSha256: null,
        challenge: randomBytes(32).toString("base64url"),
        issuedAt: at(2_500),
        questionKeyId: nonTargetQuestionKeyId,
      }),
      nonTargetQuestionKey.privateKey,
      nonTargetQuestionKeyId,
    );
    nonTargetAcceptance = await signEd25519(
      buildVoteAcceptanceV3({
        receiptId: "fixture-non-target-acceptance-v3",
        voteEventSha256: nonTargetVoteEvent.payloadSha256,
        status: "counted",
        logId,
        receivedAt: at(3_500),
        issuerKeyId: receiptKeyId,
      }),
      receiptKey.privateKey,
      receiptKeyId,
    );
  }
  const logEntries = [
    {
      entryId: voteEvent.payload.eventId,
      entryPayloadHash: voteEvent.payloadSha256,
      entryType: "vote_event" as const,
    },
    ...(nonTargetVoteEvent
      ? [
          {
            entryId: nonTargetVoteEvent.payload.eventId,
            entryPayloadHash: nonTargetVoteEvent.payloadSha256,
            entryType: "vote_event" as const,
          },
        ]
      : []),
    {
      entryId: acceptance.payload.receiptId,
      entryPayloadHash: acceptance.payloadSha256,
      entryType: "vote_adjudication" as const,
    },
    ...(nonTargetAcceptance
      ? [
          {
            entryId: nonTargetAcceptance.payload.receiptId,
            entryPayloadHash: nonTargetAcceptance.payloadSha256,
            entryType: "vote_adjudication" as const,
          },
        ]
      : []),
  ];
  const leafData = logEntries.map((entry) => canonicalizeJson(entry));
  const inclusionProofs = await Promise.all(
    logEntries.map((_entry, index) => createMerkleInclusionProof(leafData, index)),
  );
  const eventProof = inclusionProofs[0];
  const acceptanceIndex = nonTargetVoteEvent ? 2 : 1;
  const acceptanceProof = inclusionProofs[acceptanceIndex];
  if (!eventProof || !acceptanceProof) {
    throw new Error("fixture transparency proof missing");
  }
  const treeHead = await signEd25519(
    buildMerkleTreeHeadV3({
      logId,
      treeSize: logEntries.length,
      rootHash: eventProof.rootHash,
      issuedAt: at(4_000),
      issuerKeyId: receiptKeyId,
    }),
    receiptKey.privateKey,
    receiptKeyId,
  );
  const voteEventTransparency: TransparencyInclusionV3 = {
    leafIndex: 0,
    leafHash: eventProof.leafHash,
    auditPath: eventProof.auditPath,
    treeHead,
  };
  const acceptanceTransparency: TransparencyInclusionV3 = {
    leafIndex: acceptanceIndex,
    leafHash: acceptanceProof.leafHash,
    auditPath: acceptanceProof.auditPath,
    treeHead,
  };
  const bundle = buildPublicVoteProofBundleV3({
    bundleId: voteEvent.payload.eventId,
    questionAuthorization,
    questionManifest,
    voteEvent,
    acceptance,
    voteEventTransparency,
    acceptanceTransparency,
  });
  const policy: OfflineVerificationPolicyV3 = {
    schemaVersion: "qualified-opinion.vote-proof-verification-policy.v3",
    policyId: "fixture-policy-v3",
    identityAttestationPolicies: [
      {
        audience: authorizationAudience,
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
        validFrom: at(-3_600_000),
        validUntil: at(3_600_000),
        webauthnOrigin: origin,
        webauthnRpId: rpId,
      },
    ],
    serverKeys: [
      {
        algorithm: "Ed25519",
        keyId: eligibilityKeyId,
        publicKeySpki: eligibilityPublicSpki,
        purpose: "eligibility",
        validFrom: at(-3_600_000),
        validUntil: at(3_600_000),
      },
      {
        algorithm: "Ed25519",
        keyId: receiptKeyId,
        publicKeySpki: receiptPublicSpki,
        purpose: "receipt",
        validFrom: at(-3_600_000),
        validUntil: at(3_600_000),
      },
    ],
    votingPolicies: [
      {
        protocolBindingSha256: await sha256Base64Url(canonicalizeJson(binding)),
        protocolVersion: "qualified-opinion.vote-event.v3",
        transparencyLogId: logId,
        validFrom: at(-3_600_000),
        validUntil: at(3_600_000),
        voteServiceAudience: voteAudience,
      },
    ],
  };
  if (!includeTallyCheckpoint) return { bundle, policy };
  const inputSet = buildTallyInputSetV3({
    questionId,
    questionManifest,
    ballotManifests: [questionManifest],
    questionVotingAuthorizations: [
      questionAuthorization,
      ...(nonTargetAuthorization ? [nonTargetAuthorization] : []),
    ],
    checkpoint: {
      logId,
      treeSize: treeHead.payload.treeSize,
      rootHash: treeHead.payload.rootHash,
      treeHeadPayloadSha256: treeHead.payloadSha256,
    },
    treeHead,
    questionLogLeaves: logEntries.map((entry, leafIndex) => {
      const proof = inclusionProofs[leafIndex];
      if (!proof) throw new Error("fixture transparency proof missing");
      return {
        leafIndex,
        entryType: entry.entryType,
        entryId: entry.entryId,
        entryPayloadSha256: entry.entryPayloadHash,
        leafHash: proof.leafHash,
      };
    }),
    voteEvents: [
      { proofVersion: "qualified-v3", envelope: voteEvent },
      ...(nonTargetVoteEvent
        ? [
            {
              proofVersion: "qualified-v3" as const,
              envelope: nonTargetVoteEvent,
            },
          ]
        : []),
    ],
    voteReceipts: [
      { envelope: acceptance },
      ...(nonTargetAcceptance ? [{ envelope: nonTargetAcceptance }] : []),
    ],
    sourcePositions: [],
  });
  const snapshotPayload = await buildTallySnapshotV3({
    snapshotId: "fixture-snapshot-v3",
    issueId: "fixture-issue-v3",
    policy: tallyPolicy,
    inputSet,
    generatedAt: at(5_000),
    issuerKeyId: receiptKeyId,
  });
  const snapshot = await signEd25519(
    snapshotPayload,
    receiptKey.privateKey,
    receiptKeyId,
  );
  return {
    bundle,
    policy,
    tallyCheckpoint: { inputSet, snapshot },
  };
}

export async function signEd25519<T>(
  payload: T,
  privateKey: KeyObject,
  keyId: string,
): Promise<
  SignedPayload<T> & {
    signature: {
      algorithm: "Ed25519";
      keyId: string;
      value: string;
    };
  }
> {
  const value = cryptoSign(
    null,
    Buffer.from(canonicalizeJson(payload)),
    privateKey,
  ).toString("base64url");
  const envelope = await attachDetachedSignature(payload, {
    algorithm: "Ed25519",
    keyId,
    value,
  });
  return envelope as SignedPayload<T> & {
    signature: {
      algorithm: "Ed25519";
      keyId: string;
      value: string;
    };
  };
}

async function signP256<T>(
  payload: T,
  privateKey: KeyObject,
  keyId: string,
): Promise<SignedPayload<T>> {
  const value = cryptoSign("sha256", Buffer.from(canonicalizeJson(payload)), {
    key: privateKey,
    dsaEncoding: "ieee-p1363",
  }).toString("base64url");
  return attachDetachedSignature(payload, {
    algorithm: "ES256",
    keyId,
    value,
  });
}

function webAuthnAssertion(input: {
  challenge: string;
  credentialId: string;
  origin: string;
  privateKey: KeyObject;
  rpId: string;
  signCount: number;
}) {
  const clientData = Buffer.from(
    JSON.stringify({
      type: "webauthn.get",
      challenge: input.challenge,
      origin: input.origin,
      crossOrigin: false,
    }),
  );
  const authenticatorData = createAuthenticatorData(input.rpId, input.signCount);
  const signedBytes = Buffer.concat([
    authenticatorData,
    createHash("sha256").update(clientData).digest(),
  ]);
  const signature = cryptoSign("sha256", signedBytes, {
    key: input.privateKey,
    dsaEncoding: "der",
  });
  return {
    algorithm: "ES256" as const,
    credentialId: input.credentialId,
    clientDataJson: clientData.toString("base64url"),
    authenticatorData: authenticatorData.toString("base64url"),
    signature: signature.toString("base64url"),
    challenge: input.challenge,
  };
}

function createAuthenticatorData(rpId: string, signCount: number) {
  const value = Buffer.alloc(37);
  createHash("sha256").update(rpId).digest().copy(value, 0);
  value[32] = 0x05;
  value.writeUInt32BE(signCount, 33);
  return value;
}

function createRegistrationAuthenticatorData(input: {
  credentialId: string;
  keyJwk: JsonWebKey;
  rpId: string;
}) {
  if (!input.keyJwk.x || !input.keyJwk.y) {
    throw new Error("fixture P-256 key is missing coordinates");
  }
  const credentialId = Buffer.from(input.credentialId, "base64url");
  const header = Buffer.alloc(55);
  createHash("sha256").update(input.rpId).digest().copy(header, 0);
  header[32] = 0x45;
  header.writeUInt32BE(0, 33);
  header.writeUInt16BE(credentialId.length, 53);
  const coseKey = encodeCbor(
    new Map<unknown, unknown>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, Buffer.from(input.keyJwk.x, "base64url")],
      [-3, Buffer.from(input.keyJwk.y, "base64url")],
    ]),
  );
  return Buffer.concat([header, credentialId, coseKey]);
}

function encodeCbor(value: unknown): Buffer {
  if (typeof value === "number" && Number.isSafeInteger(value)) {
    return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
  }
  if (typeof value === "string") {
    const bytes = Buffer.from(value);
    return Buffer.concat([cborHead(3, bytes.length), bytes]);
  }
  if (value instanceof Uint8Array) {
    const bytes = Buffer.from(value);
    return Buffer.concat([cborHead(2, bytes.length), bytes]);
  }
  if (value instanceof Map) {
    const children: Buffer[] = [cborHead(5, value.size)];
    for (const [key, child] of value) {
      children.push(encodeCbor(key), encodeCbor(child));
    }
    return Buffer.concat(children);
  }
  throw new Error("unsupported fixture CBOR value");
}

function cborHead(major: number, length: number) {
  if (length < 24) return Buffer.from([(major << 5) | length]);
  if (length <= 0xff) return Buffer.from([(major << 5) | 24, length]);
  if (length <= 0xffff) {
    const output = Buffer.alloc(3);
    output[0] = (major << 5) | 25;
    output.writeUInt16BE(length, 1);
    return output;
  }
  throw new Error("fixture CBOR length is too large");
}

function spki(key: ReturnType<typeof generateKeyPairSync>["publicKey"]) {
  return key.export({ format: "der", type: "spki" }).toString("base64url");
}

export async function generateAttestationPki() {
  const directory = await mkdtemp(join(tmpdir(), "qualified-opinion-proof-pki-"));
  const path = (name: string) => join(directory, name);
  try {
    await Promise.all([
      writeFile(
        path("intermediate.ext"),
        "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n",
      ),
      writeFile(
        path("leaf.ext"),
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n",
      ),
    ]);
    openssl([
      "genpkey",
      "-algorithm",
      "RSA",
      "-pkeyopt",
      "rsa_keygen_bits:2048",
      "-out",
      path("root.key"),
    ]);
    openssl([
      "req",
      "-x509",
      "-new",
      "-key",
      path("root.key"),
      "-sha256",
      "-days",
      "3650",
      "-subj",
      "/CN=Qualified Opinion Proof Fixture Root",
      "-addext",
      "basicConstraints=critical,CA:TRUE,pathlen:1",
      "-addext",
      "keyUsage=critical,keyCertSign,cRLSign",
      "-out",
      path("root.pem"),
    ]);
    openssl([
      "genpkey",
      "-algorithm",
      "RSA",
      "-pkeyopt",
      "rsa_keygen_bits:2048",
      "-out",
      path("intermediate.key"),
    ]);
    openssl([
      "req",
      "-new",
      "-key",
      path("intermediate.key"),
      "-subj",
      "/CN=Qualified Opinion Proof Fixture Intermediate",
      "-out",
      path("intermediate.csr"),
    ]);
    openssl([
      "x509",
      "-req",
      "-in",
      path("intermediate.csr"),
      "-CA",
      path("root.pem"),
      "-CAkey",
      path("root.key"),
      "-CAcreateserial",
      "-days",
      "3650",
      "-sha256",
      "-extfile",
      path("intermediate.ext"),
      "-out",
      path("intermediate.pem"),
    ]);
    openssl([
      "genpkey",
      "-algorithm",
      "RSA",
      "-pkeyopt",
      "rsa_keygen_bits:2048",
      "-out",
      path("leaf.key"),
    ]);
    openssl([
      "req",
      "-new",
      "-key",
      path("leaf.key"),
      "-subj",
      "/CN=Qualified Opinion Proof Fixture Signer",
      "-out",
      path("leaf.csr"),
    ]);
    openssl([
      "x509",
      "-req",
      "-in",
      path("leaf.csr"),
      "-CA",
      path("intermediate.pem"),
      "-CAkey",
      path("intermediate.key"),
      "-CAcreateserial",
      "-days",
      "3650",
      "-sha256",
      "-extfile",
      path("leaf.ext"),
      "-out",
      path("leaf.pem"),
    ]);
    const [leafPem, intermediatePem, rootPem, leafPrivateKeyPem] = await Promise.all([
      readFile(path("leaf.pem")),
      readFile(path("intermediate.pem")),
      readFile(path("root.pem")),
      readFile(path("leaf.key"), "utf8"),
    ]);
    const certificates = [leafPem, intermediatePem, rootPem].map(
      (certificate) => new X509Certificate(certificate),
    );
    const root = certificates[2];
    if (!root) throw new Error("fixture root certificate missing");
    return {
      certificates: certificates.map((certificate) =>
        certificate.raw.toString("base64"),
      ),
      leafPrivateKeyPem,
      rootFingerprint: root.fingerprint256,
      cleanup: () => rm(directory, { recursive: true, force: true }),
    };
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}

function openssl(arguments_: string[]) {
  execFileSync("openssl", arguments_, { stdio: "pipe" });
}

export function signAttestationJwt(input: {
  audience: string;
  certificates: string[];
  environment: Record<string, string>;
  environmentOverride: Record<string, string>;
  imageDigest: string;
  issuedAtSeconds: number;
  leafPrivateKeyPem: string;
  nonce: string;
  projectId: string;
  serviceAccount: string;
}) {
  const header = base64UrlJson({
    alg: "RS256",
    typ: "JWT",
    x5c: input.certificates,
  });
  const payload = base64UrlJson({
    iss: GOOGLE_CONFIDENTIAL_SPACE_ISSUER,
    aud: input.audience,
    sub: "fixture-confidential-workload",
    iat: input.issuedAtSeconds,
    nbf: input.issuedAtSeconds - 1,
    exp: input.issuedAtSeconds + 600,
    eat_nonce: [input.nonce],
    swname: "CONFIDENTIAL_SPACE",
    dbgstat: "disabled-since-boot",
    google_service_accounts: [input.serviceAccount],
    submods: {
      container: {
        image_digest: input.imageDigest,
        env: input.environment,
        env_override: input.environmentOverride,
      },
      gce: { project_id: input.projectId },
      confidential_space: {
        support_attributes: ["STABLE"],
        monitoring_enabled: { memory: false },
      },
    },
  });
  const signingInput = `${header}.${payload}`;
  const signature = cryptoSign(
    "RSA-SHA256",
    Buffer.from(signingInput),
    input.leafPrivateKeyPem,
  ).toString("base64url");
  return `${signingInput}.${signature}`;
}

function base64UrlJson(value: unknown) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}
