import {
  type ActiveEligibilityDirectoryBundleV3,
  type ActiveEligibilityDirectoryCheckpointV3,
  type ActiveEligibilityDirectoryRecordProofV3,
  type ActiveEligibilityDirectoryRecordV3,
  type IdentityAttestationPolicyV3 as SignedIdentityAttestationPolicyV3,
  VOTE_EVENT_SCHEMA_V3,
  base64UrlDecode,
  canonicalJsonSha256,
  sha256Base64Url,
  verifyActiveEligibilityDirectoryBundleIntegrityV3,
  verifyActiveEligibilityDirectoryRecordProofIntegrityV3,
  verifyEligibilityAssertionV3Integrity,
} from "@qualified-opinion/protocol";
import { verifyEd25519SignedPayload } from "@qualified-opinion/protocol/node";
import {
  attestationIssuedAt,
  verifyConfidentialSpacePkiAttestation,
} from "./attestation";
import { GOOGLE_CONFIDENTIAL_SPACE_ISSUER } from "./gcs";
import {
  type EmailVerificationReceiptPayload,
  emailVerificationPayloadHash,
  isEmailVerificationReceiptPayload,
  normalizeVerifiedEmail,
  normalizeVerifiedFullName,
} from "./identity-receipt";
import {
  type IdentityAttestationPolicyV3,
  type OfflineVerificationPolicyV3,
  normalizeCertificateFingerprint,
  selectIdentityPolicyCandidates,
  selectServerKey,
  selectVotingPolicyForBinding,
} from "./policy";
import { verifyIdentityPasskeyBinding } from "./webauthn-binding";

export type EligibilityDirectoryVerificationExpectationV3 = {
  directoryId: string;
  instanceId: string;
  protocolBindingSha256: string;
  qualificationClaim: string;
  reviewerAuthority: string;
  subjectIssuer: string;
  subjectKeyScheme: string;
};

export type WitnessedEligibilityDirectoryHeadV3 = {
  checkpointSha256: string;
  directoryId: string;
  sequence: number;
};

export type EligibilityDirectoryVerificationResultV3 =
  | {
      ok: true;
      asOf: string;
      checkpointSha256: string;
      current: boolean;
    }
  | { ok: false; errors: string[] };

/** Verifies one hash-only historical checkpoint envelope and its policy. */
export async function verifyActiveEligibilityDirectoryCheckpointV3(input: {
  checkpoint: ActiveEligibilityDirectoryRecordProofV3["checkpoint"];
  expected: EligibilityDirectoryVerificationExpectationV3;
  policy: OfflineVerificationPolicyV3;
  witnessedCurrentHead?: WitnessedEligibilityDirectoryHeadV3;
}): Promise<EligibilityDirectoryVerificationResultV3> {
  const errors = await verifyCheckpoint(input);
  return errors.length === 0
    ? {
        ok: true,
        asOf: input.checkpoint.payload.issuedAt,
        checkpointSha256: input.checkpoint.payloadSha256,
        current: input.witnessedCurrentHead !== undefined,
      }
    : { ok: false, errors };
}

/**
 * Fully verifies one current directory record and its membership proof. It
 * reports an as-of result unless an independently witnessed current head is
 * supplied; a self-signed timestamp alone cannot prove that no newer head
 * exists.
 */
export async function verifyActiveEligibilityDirectoryRecordV3(input: {
  expected: EligibilityDirectoryVerificationExpectationV3;
  policy: OfflineVerificationPolicyV3;
  proof: ActiveEligibilityDirectoryRecordProofV3;
  witnessedCurrentHead?: WitnessedEligibilityDirectoryHeadV3;
}): Promise<EligibilityDirectoryVerificationResultV3> {
  const integrity = await verifyActiveEligibilityDirectoryRecordProofIntegrityV3(
    input.proof,
  );
  if (!integrity.ok) return { ok: false, errors: integrity.errors };
  const errors = await verifyCheckpointAndRecord({
    checkpoint: input.proof.checkpoint,
    expected: input.expected,
    policy: input.policy,
    record: input.proof.record,
    witnessedCurrentHead: input.witnessedCurrentHead,
  });
  return errors.length === 0
    ? {
        ok: true,
        asOf: input.proof.checkpoint.payload.issuedAt,
        checkpointSha256: input.proof.checkpoint.payloadSha256,
        current: input.witnessedCurrentHead !== undefined,
      }
    : { ok: false, errors };
}

/**
 * Verifies exact full-list completeness and then verifies every registration,
 * eligibility assertion and active decision body.
 */
export async function verifyActiveEligibilityDirectoryBundleV3(input: {
  bundle: ActiveEligibilityDirectoryBundleV3;
  expected: EligibilityDirectoryVerificationExpectationV3;
  policy: OfflineVerificationPolicyV3;
  witnessedCurrentHead?: WitnessedEligibilityDirectoryHeadV3;
}): Promise<EligibilityDirectoryVerificationResultV3> {
  const integrity = await verifyActiveEligibilityDirectoryBundleIntegrityV3(
    input.bundle,
  );
  if (!integrity.ok) return { ok: false, errors: integrity.errors };
  const errors: string[] = [];
  for (const record of input.bundle.records) {
    errors.push(
      ...(await verifyCheckpointAndRecord({
        checkpoint: input.bundle.checkpoint,
        expected: input.expected,
        policy: input.policy,
        record,
        witnessedCurrentHead: input.witnessedCurrentHead,
      })),
    );
  }
  if (input.bundle.records.length === 0) {
    errors.push(
      ...(await verifyCheckpoint({
        checkpoint: input.bundle.checkpoint,
        expected: input.expected,
        policy: input.policy,
        witnessedCurrentHead: input.witnessedCurrentHead,
      })),
    );
  }
  return errors.length === 0
    ? {
        ok: true,
        asOf: input.bundle.checkpoint.payload.issuedAt,
        checkpointSha256: input.bundle.checkpoint.payloadSha256,
        current: input.witnessedCurrentHead !== undefined,
      }
    : { ok: false, errors: [...new Set(errors)] };
}

async function verifyCheckpointAndRecord(input: {
  checkpoint: ActiveEligibilityDirectoryRecordProofV3["checkpoint"];
  expected: EligibilityDirectoryVerificationExpectationV3;
  policy: OfflineVerificationPolicyV3;
  record: ActiveEligibilityDirectoryRecordV3;
  witnessedCurrentHead?: WitnessedEligibilityDirectoryHeadV3;
}) {
  const errors = await verifyCheckpoint(input);
  await checked(errors, "directory_record_chain", () => verifyRecordChain(input));
  return errors;
}

async function verifyCheckpoint(input: {
  checkpoint: ActiveEligibilityDirectoryRecordProofV3["checkpoint"];
  expected: EligibilityDirectoryVerificationExpectationV3;
  policy: OfflineVerificationPolicyV3;
  witnessedCurrentHead?: WitnessedEligibilityDirectoryHeadV3;
}) {
  const errors: string[] = [];
  const checkpoint = input.checkpoint.payload;
  if (
    checkpoint.directoryId !== input.expected.directoryId ||
    checkpoint.instanceId !== input.expected.instanceId ||
    checkpoint.protocolBindingSha256 !== input.expected.protocolBindingSha256
  ) {
    errors.push("directory_checkpoint_policy_mismatch");
  }
  await checked(errors, "directory_checkpoint_signature", async () => {
    const key = selectServerKey(input.policy, {
      keyId: input.checkpoint.signature.keyId,
      purpose: "eligibility",
      time: checkpoint.issuedAt,
    });
    if (
      checkpoint.issuer.keyId !== key.keyId ||
      input.checkpoint.signature.keyId !== key.keyId ||
      !(await verifyEd25519SignedPayload({
        envelope: input.checkpoint,
        expectedKeyId: key.keyId,
        publicKeySpki: key.publicKeySpki,
      }))
    ) {
      throw new Error("invalid_directory_checkpoint_signature");
    }
  });
  if (input.witnessedCurrentHead) {
    if (
      input.witnessedCurrentHead.directoryId !== checkpoint.directoryId ||
      input.witnessedCurrentHead.sequence !== checkpoint.sequence ||
      input.witnessedCurrentHead.checkpointSha256 !== input.checkpoint.payloadSha256
    ) {
      errors.push("directory_checkpoint_stale_or_equivocal");
    }
  }
  return errors;
}

async function verifyRecordChain(input: {
  checkpoint: ActiveEligibilityDirectoryRecordProofV3["checkpoint"];
  expected: EligibilityDirectoryVerificationExpectationV3;
  policy: OfflineVerificationPolicyV3;
  record: ActiveEligibilityDirectoryRecordV3;
}) {
  const { record } = input;
  const assertion = record.eligibilityAssertion.payload;
  const decision = record.eligibilityDecision.payload;
  const receipt = record.registration.payload;
  if (!isEmailVerificationReceiptPayload(receipt)) {
    throw new Error("directory_registration_payload_invalid");
  }
  const bindingSha256 = await canonicalJsonSha256(assertion.binding);
  if (
    record.publicVoterId !== assertion.publicVoterId ||
    record.publicVoterId !== decision.publicVoterId ||
    record.registration.proofId !== assertion.identityProof.proofId ||
    record.registration.payloadSha256 !== assertion.identityProof.payloadSha256 ||
    record.eligibilityAssertion.payloadSha256 !== decision.assertionSha256 ||
    assertion.issuer.keyId !== record.eligibilityAssertion.signature.keyId ||
    decision.issuerKeyId !== record.eligibilityDecision.signature.keyId ||
    decision.status !== "active" ||
    decision.sequence !== 1 ||
    decision.previousDecisionSha256 !== null ||
    assertion.binding.instance.id !== input.expected.instanceId ||
    bindingSha256 !== input.expected.protocolBindingSha256 ||
    input.checkpoint.payload.protocolBindingSha256 !== bindingSha256 ||
    assertion.qualification.claim !== input.expected.qualificationClaim ||
    assertion.registryEvidence.payload.reviewerAuthority !==
      input.expected.reviewerAuthority ||
    assertion.qualification.subject.issuer !== input.expected.subjectIssuer ||
    assertion.qualification.subject.scheme !== input.expected.subjectKeyScheme
  ) {
    throw new Error("directory_record_links_invalid");
  }
  selectVotingPolicyForBinding(input.policy, {
    protocolBindingSha256: bindingSha256,
    protocolVersion: VOTE_EVENT_SCHEMA_V3,
    time: assertion.issuedAt,
  });
  selectVotingPolicyForBinding(input.policy, {
    protocolBindingSha256: bindingSha256,
    protocolVersion: VOTE_EVENT_SCHEMA_V3,
    time: input.checkpoint.payload.issuedAt,
  });

  const checkpointTime = Date.parse(input.checkpoint.payload.issuedAt);
  const notBefore = Date.parse(assertion.notBefore);
  const expiresAt =
    assertion.expiresAt === null
      ? Number.POSITIVE_INFINITY
      : Date.parse(assertion.expiresAt);
  const decisionTime = Date.parse(decision.effectiveAt);
  if (
    !Number.isFinite(checkpointTime) ||
    !Number.isFinite(notBefore) ||
    (assertion.expiresAt !== null && !Number.isFinite(expiresAt)) ||
    !Number.isFinite(decisionTime) ||
    notBefore > checkpointTime ||
    expiresAt <= checkpointTime ||
    decisionTime > checkpointTime
  ) {
    throw new Error("directory_record_not_active_at_checkpoint");
  }

  const eligibilityKey = selectServerKey(input.policy, {
    keyId: record.eligibilityAssertion.signature.keyId,
    purpose: "eligibility",
    time: assertion.issuedAt,
  });
  const decisionKey = selectServerKey(input.policy, {
    keyId: record.eligibilityDecision.signature.keyId,
    purpose: "eligibility",
    time: decision.effectiveAt,
  });
  if (
    !(await verifyEligibilityAssertionV3Integrity(assertion)) ||
    !(await verifyEd25519SignedPayload({
      envelope: record.eligibilityAssertion,
      expectedKeyId: eligibilityKey.keyId,
      publicKeySpki: eligibilityKey.publicKeySpki,
    })) ||
    !(await verifyEd25519SignedPayload({
      envelope: record.eligibilityDecision,
      expectedKeyId: decisionKey.keyId,
      publicKeySpki: decisionKey.publicKeySpki,
    }))
  ) {
    throw new Error("directory_eligibility_signature_invalid");
  }

  await verifyReceiptAssertionLinks(receipt, assertion);
  const attestationPolicy = selectExactIdentityPolicy(
    input.policy,
    record.registration.attestationToken,
    assertion.identityAttestation.policy,
  );
  verifyConfidentialSpacePkiAttestation({
    token: record.registration.attestationToken,
    identityPayload: receipt,
    policy: attestationPolicy,
  });
  verifyIdentityPasskeyBinding({
    payload: receipt,
    policy: attestationPolicy,
  });
}

async function verifyReceiptAssertionLinks(
  receipt: EmailVerificationReceiptPayload,
  assertion: ActiveEligibilityDirectoryRecordV3["eligibilityAssertion"]["payload"],
) {
  const registryEvidence = assertion.registryEvidence.payload;
  if (
    emailVerificationPayloadHash(receipt).length !== 64 ||
    normalizeVerifiedEmail(receipt.normalizedEmail) !==
      normalizeVerifiedEmail(registryEvidence.checkedEmail) ||
    normalizeVerifiedFullName(receipt.claimedFullName) !==
      normalizeVerifiedFullName(registryEvidence.checkedFullName) ||
    receipt.passkey.credentialId !== assertion.rootKey.credentialId ||
    receipt.passkey.origin !== assertion.identityAttestation.policy.identityOrigin ||
    receipt.passkey.rpId !== assertion.identityAttestation.policy.rpId ||
    registryEvidence.subject.scheme !== assertion.qualification.subject.scheme ||
    registryEvidence.subject.issuer !== assertion.qualification.subject.issuer ||
    registryEvidence.subject.key !== assertion.qualification.subject.key
  ) {
    throw new Error("directory_registration_eligibility_links_invalid");
  }
  let url: URL;
  try {
    url = new URL(registryEvidence.recordUrl);
  } catch {
    throw new Error("directory_registry_url_invalid");
  }
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
    throw new Error("directory_registry_url_invalid");
  }
  const publicKeySha256 = await sha256Base64Url(
    base64UrlDecode(receipt.passkey.publicKeySpki),
  );
  if (publicKeySha256 !== assertion.rootKey.publicKeySpkiSha256) {
    throw new Error("directory_registration_root_key_invalid");
  }
}

function selectExactIdentityPolicy(
  policy: OfflineVerificationPolicyV3,
  token: string,
  signed: SignedIdentityAttestationPolicyV3,
) {
  const candidates = selectIdentityPolicyCandidates(
    policy,
    attestationIssuedAt(token),
  ).filter((candidate) => identityPoliciesMatch(candidate, signed));
  if (candidates.length !== 1) {
    throw new Error(
      candidates.length === 0
        ? "directory_identity_policy_not_found"
        : "directory_identity_policy_ambiguous",
    );
  }
  return candidates[0] as IdentityAttestationPolicyV3;
}

function identityPoliciesMatch(
  policy: IdentityAttestationPolicyV3,
  signed: SignedIdentityAttestationPolicyV3,
) {
  let signedRoot: string;
  try {
    signedRoot = normalizeCertificateFingerprint(signed.pkiRootCertificateSha256);
  } catch {
    return false;
  }
  return (
    signed.issuer === GOOGLE_CONFIDENTIAL_SPACE_ISSUER &&
    signed.audience === policy.audience &&
    signed.imageDigest === policy.imageDigest &&
    signed.projectId === policy.projectId &&
    signed.serviceAccount === policy.serviceAccount &&
    canonicalRecordEqual(signed.expectedEnvironment, policy.expectedEnvironment) &&
    signed.allowDebug === policy.debugAllowed &&
    signed.requirePki === true &&
    policy.trustedRootCertificateSha256.includes(signedRoot) &&
    signed.requireMemoryMonitoringDisabled === policy.memoryMonitoringDisabled &&
    signed.requireStable === policy.stable &&
    signed.identityOrigin === policy.webauthnOrigin &&
    signed.rpId === policy.webauthnRpId
  );
}

function canonicalRecordEqual(
  left: Record<string, string>,
  right: Record<string, string>,
) {
  const leftEntries = Object.entries(left).sort(([a], [b]) => a.localeCompare(b));
  const rightEntries = Object.entries(right).sort(([a], [b]) => a.localeCompare(b));
  return (
    leftEntries.length === rightEntries.length &&
    leftEntries.every(
      ([key, value], index) =>
        key === rightEntries[index]?.[0] && value === rightEntries[index]?.[1],
    )
  );
}

async function checked(
  errors: string[],
  label: string,
  operation: () => void | Promise<void>,
) {
  try {
    await operation();
  } catch (error) {
    errors.push(`${label}:${error instanceof Error ? error.message : String(error)}`);
  }
}
