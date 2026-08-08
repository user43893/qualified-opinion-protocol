import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, sign as signBytes } from "node:crypto";
import {
  attachDetachedSignature,
  buildMerkleTreeHeadV3,
  buildVoteAcceptanceV3,
} from "./builders";
import { canonicalizeJson } from "./canonical";
import { base64UrlEncode, canonicalJsonSha256, sha256Base64Url } from "./encoding";
import { createMerkleInclusionProof } from "./merkle";
import {
  type ResolveTallyTrustedSigningKeyV3,
  verifyTallySnapshotCryptographicallyV3,
} from "./node";
import { questionVoteLogIdV3 } from "./question-vote-log-v3";
import {
  buildTallyInputSetV3,
  buildTallyPolicyV3,
  buildTallySnapshotV3,
  replayTallyV3,
  verifyTallySnapshotStructureV3,
} from "./tally-v3";
import type { SignedPayload } from "./types";
import {
  buildBallotManifestV3,
  buildProtocolBindingV3,
  buildQuestionVotingAuthorizationPayloadV3,
  buildQuestionVotingAuthorizationV3,
  buildVoteEventV3,
} from "./v3-builders";

const questionId = "question-private-1";
const ballotId = "ballot-private-1";
const serverKeyId = "receipt-key-1";
const dummySignature = "AA";

function digest(byte: number) {
  return base64UrlEncode(new Uint8Array(32).fill(byte));
}

function policy() {
  return buildTallyPolicyV3({
    policyId: "org.example.private-tally.v3",
    instanceId: "org.example.instance",
    calculationVersion: "private-question-vote-v3",
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
      groupCode: "individual",
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
    sourcePositionRules: [
      {
        ruleId: "individual-source",
        positionTypes: ["classified_public_statement"],
        credentialClasses: null,
        groupCode: "individual",
        weight: 1,
      },
    ],
    unmatchedSourcePositionTreatment: "exclude",
    rounding: { method: "decimal_to_fixed", percentageDecimalPlaces: 1 },
    publishedAt: "2026-07-24T00:00:00.000Z",
  });
}

async function fixture() {
  const tallyPolicy = policy();
  const logId = await questionVoteLogIdV3({
    instanceId: tallyPolicy.instanceId,
    questionId,
  });
  const binding = buildProtocolBindingV3({
    instanceId: tallyPolicy.instanceId,
    instanceProfileSha256: digest(1),
    eligibilityPolicy: { id: "eligibility.v3", sha256: digest(2) },
    tallyPolicy: {
      id: tallyPolicy.policyId,
      sha256: await canonicalJsonSha256(tallyPolicy),
    },
    trustPolicy: { id: "confidential-space.v3", sha256: digest(3) },
    audience: "https://example.test/api/voting",
    origin: "https://example.test",
  });
  const manifestPayload = buildBallotManifestV3({
    manifestId: "manifest-1",
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
    questionText: "Question?",
    presentationChoices: [
      { id: "yes", label: "Yes", description: "" },
      { id: "no", label: "No", description: "" },
    ],
    publishedAt: "2026-07-24T00:01:00.000Z",
    issuerKeyId: serverKeyId,
  });
  const manifest = await attachDetachedSignature(manifestPayload, {
    algorithm: "Ed25519",
    keyId: serverKeyId,
    value: dummySignature,
  });
  const questionKey = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const questionKeySpki = base64UrlEncode(
    new Uint8Array(await crypto.subtle.exportKey("spki", questionKey.publicKey)),
  );
  const authorizationPayload = await buildQuestionVotingAuthorizationPayloadV3({
    binding,
    questionId,
    questionNullifier: digest(4),
    nullifierKeyEpoch: 1,
    questionKeyPublicKeySpki: questionKeySpki,
    eligibilityClaim: "active-law-graduate",
    registryCheckpointId: "directory-1",
    registryCheckpointSha256: digest(5),
    registryCheckpointWitnessCanonicalEnvelope: "{}",
    registryCheckpointWitnessEnvelopeSha256: await sha256Base64Url("{}"),
    issuedAt: "2026-07-24T00:02:00.000Z",
    expiresAt: "2026-07-24T00:20:00.000Z",
    issuerAttestationAudience: "https://example.test/question-authorization",
  });
  const authorization = await buildQuestionVotingAuthorizationV3({
    payload: authorizationPayload,
    attestationToken: "header.payload.signature",
  });
  const eventPayload = buildVoteEventV3({
    eventId: "event-1",
    eventType: "cast",
    binding,
    questionNullifier: authorization.payload.questionNullifier,
    authorizationSha256: authorization.payloadSha256,
    publicationMode: "private",
    ballotManifestSha256: manifest.payloadSha256,
    ballotId,
    questionId,
    choiceId: "yes",
    sequence: 1,
    previousEventSha256: null,
    challenge: base64UrlEncode(new Uint8Array(24).fill(6)),
    issuedAt: "2026-07-24T00:03:00.000Z",
    questionKeyId: authorization.payload.questionKey.keyId,
  });
  const event = await attachDetachedSignature(eventPayload, {
    algorithm: "ES256",
    keyId: authorization.payload.questionKey.keyId,
    value: dummySignature,
  });
  const receiptPayload = buildVoteAcceptanceV3({
    receiptId: "receipt-1",
    voteEventSha256: event.payloadSha256,
    status: "counted",
    logId,
    receivedAt: "2026-07-24T00:04:00.000Z",
    issuerKeyId: serverKeyId,
  });
  const receipt = await attachDetachedSignature(receiptPayload, {
    algorithm: "Ed25519",
    keyId: serverKeyId,
    value: dummySignature,
  });
  const leaves = [
    canonicalizeJson({
      entryId: event.payload.eventId,
      entryPayloadHash: event.payloadSha256,
      entryType: "vote_event",
    }),
    canonicalizeJson({
      entryId: receipt.payload.receiptId,
      entryPayloadHash: receipt.payloadSha256,
      entryType: "vote_adjudication",
    }),
  ];
  const proofs = await Promise.all(
    leaves.map((_, index) => createMerkleInclusionProof(leaves, index)),
  );
  const rootHash = proofs[0]?.rootHash;
  if (!rootHash) throw new Error("missing test root");
  const treeHeadPayload = buildMerkleTreeHeadV3({
    logId,
    treeSize: leaves.length,
    rootHash,
    issuedAt: "2026-07-24T00:05:00.000Z",
    issuerKeyId: serverKeyId,
  });
  const treeHead = await attachDetachedSignature(treeHeadPayload, {
    algorithm: "Ed25519",
    keyId: serverKeyId,
    value: dummySignature,
  });
  const inputSet = buildTallyInputSetV3({
    questionId,
    questionManifest: manifest,
    ballotManifests: [manifest],
    questionVotingAuthorizations: [authorization],
    checkpoint: {
      logId,
      treeSize: treeHead.payload.treeSize,
      rootHash: treeHead.payload.rootHash,
      treeHeadPayloadSha256: treeHead.payloadSha256,
    },
    treeHead,
    questionLogLeaves: [
      {
        leafIndex: 0,
        entryType: "vote_event",
        entryId: event.payload.eventId,
        entryPayloadSha256: event.payloadSha256,
        leafHash: proofs[0]?.leafHash ?? "",
      },
      {
        leafIndex: 1,
        entryType: "vote_adjudication",
        entryId: receipt.payload.receiptId,
        entryPayloadSha256: receipt.payloadSha256,
        leafHash: proofs[1]?.leafHash ?? "",
      },
    ],
    voteEvents: [{ proofVersion: "qualified-v3", envelope: event }],
    voteReceipts: [{ envelope: receipt }],
    sourcePositions: [
      {
        inputKind: "source_position",
        positionId: "source-position-1",
        questionId,
        choiceId: "no",
        positionType: "classified_public_statement",
        credentialClass: null,
        status: "counted",
        isCurrent: true,
        countWeight: "1",
      },
    ],
  });
  return {
    authorization,
    event,
    inputSet,
    manifest,
    questionKey,
    receipt,
    tallyPolicy,
  };
}

function objectKeys(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap(objectKeys);
  if (!value || typeof value !== "object") return [];
  return Object.entries(value).flatMap(([key, child]) => [key, ...objectKeys(child)]);
}

function requiredFirst<T>(values: T[], label: string): T {
  const value = values[0];
  if (!value) throw new Error(`missing ${label} test fixture`);
  return value;
}

describe("private V3 tally", () => {
  test("replays latest question-nullifier votes and source positions as independent channels", async () => {
    const value = await fixture();
    const replay = await replayTallyV3(value.tallyPolicy, value.inputSet);

    expect(replay.result).toMatchObject({
      totalCount: 2,
      directVoteCount: 1,
      sourcePositionCount: 1,
    });
    expect(replay.result.choices).toEqual([
      expect.objectContaining({ choiceId: "yes", count: 1 }),
      expect.objectContaining({ choiceId: "no", count: 1 }),
    ]);
    expect(replay.acceptedDirectVotes).toEqual([
      expect.objectContaining({
        questionNullifier: value.authorization.payload.questionNullifier,
        voteEventId: value.event.payload.eventId,
      }),
    ]);
  });

  test("builds a replayable V3 snapshot and rejects another-question event", async () => {
    const value = await fixture();
    const snapshotPayload = await buildTallySnapshotV3({
      snapshotId: "snapshot-1",
      issueId: "issue-1",
      policy: value.tallyPolicy,
      inputSet: value.inputSet,
      generatedAt: "2026-07-24T00:06:00.000Z",
      issuerKeyId: serverKeyId,
    });
    const snapshot = await attachDetachedSignature(snapshotPayload, {
      algorithm: "Ed25519",
      keyId: serverKeyId,
      value: dummySignature,
    });
    expect(
      await verifyTallySnapshotStructureV3({
        snapshot,
        inputSet: value.inputSet,
      }),
    ).toEqual({ ok: true, result: snapshotPayload.result });

    const leaked = structuredClone(value.inputSet);
    const leakedEvent = requiredFirst(leaked.voteEvents, "leaked event");
    leakedEvent.envelope.payload.questionId = "question-other";
    leakedEvent.envelope.payloadSha256 = await canonicalJsonSha256(
      leakedEvent.envelope.payload,
    );
    await expect(replayTallyV3(value.tallyPolicy, leaked)).rejects.toThrow(
      /another question/,
    );
  });

  test("contains no reusable registration identity or source-to-vote link", async () => {
    const { inputSet } = await fixture();
    const keys = objectKeys(inputSet);
    for (const forbidden of [
      "publicVoterId",
      "identityProof",
      "identityProofSha256",
      "eligibilityAssertions",
      "eligibilityDecisions",
      "rootKeyDelegations",
      "qualificationSubject",
      "personId",
      "displayName",
      "normalizedEmail",
      "suppressedByDirectVote",
    ]) {
      expect(keys).not.toContain(forbidden);
    }

    const linked = structuredClone(inputSet) as typeof inputSet & {
      sourcePositions: Array<
        (typeof inputSet.sourcePositions)[number] & { personId?: string }
      >;
    };
    requiredFirst(linked.sourcePositions, "linked source").personId = "known-lawyer";
    expect(() => buildTallyInputSetV3(linked)).toThrow(/personId is not allowed/);

    const extendedAuthorization = structuredClone(inputSet) as typeof inputSet;
    Object.assign(
      requiredFirst(extendedAuthorization.questionVotingAuthorizations, "authorization")
        .payload,
      { accountId: "private-account-id" },
    );
    expect(() => buildTallyInputSetV3(extendedAuthorization)).toThrow(
      /accountId is not allowed/,
    );
  });

  test("rejects an authorization from a different pinned question epoch", async () => {
    const value = await fixture();
    value.inputSet.questionManifest.payload.nullifierKeyEpoch = 2;
    for (const manifest of value.inputSet.ballotManifests) {
      manifest.payload.nullifierKeyEpoch = 2;
    }
    await expect(replayTallyV3(value.tallyPolicy, value.inputSet)).rejects.toThrow(
      /different nullifier epochs/,
    );
  });

  test("fails closed if an authorization or question-log leaf is omitted", async () => {
    const value = await fixture();
    const noAuthorization = structuredClone(value.inputSet);
    noAuthorization.questionVotingAuthorizations = [];
    await expect(replayTallyV3(value.tallyPolicy, noAuthorization)).rejects.toThrow(
      /no public question authorization/,
    );

    const incompleteLog = structuredClone(value.inputSet);
    incompleteLog.questionLogLeaves = incompleteLog.questionLogLeaves.slice(1);
    await expect(replayTallyV3(value.tallyPolicy, incompleteLog)).rejects.toThrow(
      /prefix length|not contiguous|is not logged/,
    );
  });

  test("rejects incomplete, gapped, and duplicated question-log prefixes", async () => {
    const value = await fixture();
    for (const leaves of [
      value.inputSet.questionLogLeaves.slice(1),
      value.inputSet.questionLogLeaves.slice(0, -1),
    ]) {
      const omitted = structuredClone(value.inputSet);
      omitted.questionLogLeaves = structuredClone(leaves);
      await expect(replayTallyV3(value.tallyPolicy, omitted)).rejects.toThrow(
        /prefix length|not contiguous|is not logged/,
      );
    }

    const gapped = structuredClone(value.inputSet);
    const second = gapped.questionLogLeaves[1];
    if (!second) throw new Error("missing second question-log leaf");
    second.leafIndex = 3;
    await expect(replayTallyV3(value.tallyPolicy, gapped)).rejects.toThrow(
      /not contiguous/,
    );

    const duplicated = structuredClone(value.inputSet);
    const first = duplicated.questionLogLeaves[0];
    if (!first) throw new Error("missing first question-log leaf");
    duplicated.questionLogLeaves.push(structuredClone(first));
    await expect(replayTallyV3(value.tallyPolicy, duplicated)).rejects.toThrow(
      /prefix length|duplicate question log/,
    );
  });

  test("rejects a smaller otherwise signed checkpoint against an independent latest head", async () => {
    const value = await fixture();
    const snapshotPayload = await buildTallySnapshotV3({
      snapshotId: "snapshot-stale",
      issueId: "issue-1",
      policy: value.tallyPolicy,
      inputSet: value.inputSet,
      generatedAt: "2026-07-24T00:06:00.000Z",
      issuerKeyId: serverKeyId,
    });
    const snapshot = await attachDetachedSignature(snapshotPayload, {
      algorithm: "Ed25519",
      keyId: serverKeyId,
      value: dummySignature,
    });
    const latestPayload = buildMerkleTreeHeadV3({
      logId: value.inputSet.checkpoint.logId,
      treeSize: value.inputSet.checkpoint.treeSize + 1,
      rootHash: digest(31),
      previousTreeHeadSha256: value.inputSet.treeHead.payloadSha256,
      issuedAt: "2026-07-24T00:07:00.000Z",
      issuerKeyId: serverKeyId,
    });
    const latest = await attachDetachedSignature(latestPayload, {
      algorithm: "Ed25519",
      keyId: serverKeyId,
      value: dummySignature,
    });
    const verification = await verifyTallySnapshotStructureV3({
      snapshot,
      inputSet: value.inputSet,
      expectedLatestQuestionTreeHead: latest,
    });
    expect(verification.ok).toBe(false);
    if (!verification.ok) {
      expect(verification.errors.join("\n")).toContain(
        "independently supplied latest question tree head",
      );
    }
  });

  test("verifies attestation policy, question-key signatures, receipts and snapshot signatures", async () => {
    const value = await fixture();
    const server = generateKeyPairSync("ed25519");
    const signServer = (payload: unknown) =>
      base64UrlEncode(
        new Uint8Array(
          signBytes(null, Buffer.from(canonicalizeJson(payload)), server.privateKey),
        ),
      );
    value.inputSet.questionManifest.signature.value = signServer(
      value.inputSet.questionManifest.payload,
    );
    requiredFirst(value.inputSet.ballotManifests, "ballot manifest").signature.value =
      value.inputSet.questionManifest.signature.value;
    value.inputSet.treeHead.signature.value = signServer(
      value.inputSet.treeHead.payload,
    );
    const receipt = requiredFirst(value.inputSet.voteReceipts, "vote receipt");
    receipt.envelope.signature.value = signServer(receipt.envelope.payload);
    const event = requiredFirst(value.inputSet.voteEvents, "vote event");
    event.envelope.signature.value = base64UrlEncode(
      new Uint8Array(
        await crypto.subtle.sign(
          { name: "ECDSA", hash: "SHA-256" },
          value.questionKey.privateKey,
          new TextEncoder().encode(canonicalizeJson(event.envelope.payload)),
        ),
      ),
    );
    const snapshotPayload = await buildTallySnapshotV3({
      snapshotId: "snapshot-crypto",
      issueId: "issue-1",
      policy: value.tallyPolicy,
      inputSet: value.inputSet,
      generatedAt: "2026-07-24T00:06:00.000Z",
      issuerKeyId: serverKeyId,
    });
    const snapshot = await attachDetachedSignature(snapshotPayload, {
      algorithm: "Ed25519",
      keyId: serverKeyId,
      value: signServer(snapshotPayload),
    });
    const serverSpki = base64UrlEncode(
      new Uint8Array(server.publicKey.export({ format: "der", type: "spki" })),
    );
    const resolveTrustedKey: ResolveTallyTrustedSigningKeyV3 = () => ({
      algorithm: "Ed25519",
      keyId: serverKeyId,
      publicKeySpki: serverSpki,
      purpose: "receipt",
      validFrom: "2026-07-23T00:00:00.000Z",
      validUntil: null,
    });
    const attestationChecks: string[] = [];
    const verification = await verifyTallySnapshotCryptographicallyV3({
      snapshot,
      inputSet: value.inputSet,
      resolveTrustedKey,
      verifyQuestionAuthorization: (material) => {
        attestationChecks.push(material.expectedAttestationNonce);
        return { ok: true };
      },
    });

    expect(verification).toEqual({
      ok: true,
      result: snapshotPayload.result,
    });
    expect(attestationChecks).toEqual([value.authorization.payloadSha256]);

    const badEvent = structuredClone(value.inputSet);
    requiredFirst(badEvent.voteEvents, "bad event").envelope.signature.value = "AA";
    const badSnapshotPayload = await buildTallySnapshotV3({
      snapshotId: "snapshot-bad-event",
      issueId: "issue-1",
      policy: value.tallyPolicy,
      inputSet: badEvent,
      generatedAt: "2026-07-24T00:06:00.000Z",
      issuerKeyId: serverKeyId,
    });
    const badSnapshot = await attachDetachedSignature(badSnapshotPayload, {
      algorithm: "Ed25519",
      keyId: serverKeyId,
      value: signServer(badSnapshotPayload),
    });
    expect(
      await verifyTallySnapshotCryptographicallyV3({
        snapshot: badSnapshot,
        inputSet: badEvent,
        resolveTrustedKey,
        verifyQuestionAuthorization: () => ({ ok: true }),
      }),
    ).toEqual(
      expect.objectContaining({
        ok: false,
        errors: expect.arrayContaining([
          expect.stringContaining("invalid_question_key_signature"),
        ]),
      }),
    );
  });
});
