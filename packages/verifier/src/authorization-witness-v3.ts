import type { QuestionVotingAuthorizationPayloadV3 } from "@qualified-opinion/protocol";
import { verifyEligibilityDirectoryWitnessStatusV3 } from "./eligibility-directory-witness-v3";

export type EligibilityDirectoryWitnessAuthorizationPolicy = {
  expectedEnvironment: Record<string, string>;
};

/**
 * Independently verifies the directory checkpoint witness committed into one
 * question authorization. This is shared by single-vote and complete-tally
 * verification so non-target votes receive the same full-chain check.
 */
export function verifyEligibilityDirectoryWitnessForAuthorization(input: {
  attestationPolicy: EligibilityDirectoryWitnessAuthorizationPolicy;
  authorization: QuestionVotingAuthorizationPayloadV3;
}) {
  const environment = input.attestationPolicy.expectedEnvironment;
  const statusUrl = requiredHttpsUrl(
    environment.QO_ELIGIBILITY_DIRECTORY_WITNESS_STATUS_URL,
    "eligibility_directory_witness_status_url_invalid",
  );
  if (statusUrl.hash || statusUrl.username || statusUrl.password) {
    throw new Error("eligibility_directory_witness_status_url_invalid");
  }
  const applicationUrl = requiredHttpsOrigin(
    environment.QO_APP_URL,
    "eligibility_directory_witness_application_url_invalid",
  );
  const maximumAgeSeconds = Number(
    environment.QO_ELIGIBILITY_DIRECTORY_WITNESS_MAX_AGE_SECONDS,
  );
  if (
    !/^[1-9]\d*$/.test(
      environment.QO_ELIGIBILITY_DIRECTORY_WITNESS_MAX_AGE_SECONDS ?? "",
    ) ||
    !Number.isSafeInteger(maximumAgeSeconds) ||
    maximumAgeSeconds > 3_600
  ) {
    throw new Error("eligibility_directory_witness_maximum_age_invalid");
  }
  let value: unknown;
  try {
    value = JSON.parse(
      input.authorization.registryCheckpoint.witness.canonicalEnvelope,
    );
  } catch {
    throw new Error("eligibility_directory_witness_envelope_invalid");
  }
  const verified = verifyEligibilityDirectoryWitnessStatusV3({
    expectedCheckpointSha256: input.authorization.registryCheckpoint.sha256,
    policy: {
      logId: requiredEnvironmentValue(environment, "QO_VOTE_LOG_ID"),
      maximumAgeSeconds,
      origin: applicationUrl.origin,
      publicKeySpkiSha256: requiredEnvironmentValue(
        environment,
        "QO_ELIGIBILITY_DIRECTORY_WITNESS_PUBLIC_KEY_SPKI_SHA256",
      ),
      sourceRevision: requiredEnvironmentValue(
        environment,
        "QO_ELIGIBILITY_DIRECTORY_WITNESS_SOURCE_REVISION",
      ),
      trustRootSha256: requiredEnvironmentValue(
        environment,
        "QO_ELIGIBILITY_DIRECTORY_WITNESS_TRUST_ROOT_SHA256",
      ),
      witnessId: requiredEnvironmentValue(
        environment,
        "QO_ELIGIBILITY_DIRECTORY_WITNESS_ID",
      ),
    },
    value,
    verificationTime: new Date(input.authorization.issuedAt),
  });
  if (
    verified.canonicalEnvelope !==
      input.authorization.registryCheckpoint.witness.canonicalEnvelope ||
    verified.envelopeSha256 !==
      input.authorization.registryCheckpoint.witness.envelopeSha256
  ) {
    throw new Error("eligibility_directory_witness_commitment_invalid");
  }
  return verified;
}

function requiredEnvironmentValue(environment: Record<string, string>, name: string) {
  const value = environment[name];
  if (!value) throw new Error("eligibility_directory_witness_policy_invalid");
  return value;
}

function requiredHttpsUrl(value: string | undefined, code: string) {
  if (!value) throw new Error(code);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(code);
  }
  if (url.protocol !== "https:" || url.toString() !== value) {
    throw new Error(code);
  }
  return url;
}

function requiredHttpsOrigin(value: string | undefined, code: string) {
  if (!value) throw new Error(code);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(code);
  }
  if (url.protocol !== "https:" || url.origin !== value) {
    throw new Error(code);
  }
  return url;
}
