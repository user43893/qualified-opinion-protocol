#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { verifyDownloadedVoteProof } from "./verifier";

type CliOptions = {
  allowUnpinnedPolicy: boolean;
  bundlePath: string;
  expectedPolicySha256?: string;
  json: boolean;
  latestQuestionHeadPath?: string;
  policyPath: string;
  requireCounted: boolean;
  tallyCheckpointPath?: string;
};

const USAGE = `Usage:
  qualified-opinion-verify --bundle VOTE_PROOF.json --policy POLICY.json [options]

Options:
  --expected-policy-sha256 HEX  Required independently obtained policy hash
                                 (or QUALIFIED_OPINION_POLICY_SHA256)
  --allow-unpinned-policy       UNSAFE: inspect with an unanchored policy;
                                 prints UNANCHORED and exits 4 even when valid
  --tally-snapshot TALLY.json   Verify the raw signed snapshot and replay
  --latest-question-head HEAD.json
                                Reject a snapshot that is not this independently
                                obtained latest signed question-log head
  --require-counted             Exit 3 unless a tally checkpoint proves the vote counted
  --json                        Emit the complete machine-readable result
  --help                        Show this help

Exit codes: 0 verified, 1 cryptographically invalid, 2 input error,
            3 valid inclusion proof without a counted checkpoint,
            4 valid under the supplied policy but policy is unanchored.`;

export async function runCli(
  argv: string[],
  io: {
    env?: Record<string, string | undefined>;
    stderr?: (value: string) => void;
    stdout?: (value: string) => void;
  } = {},
) {
  const stdout = io.stdout ?? ((value) => process.stdout.write(`${value}\n`));
  const stderr = io.stderr ?? ((value) => process.stderr.write(`${value}\n`));
  try {
    if (argv.includes("--help")) {
      stdout(USAGE);
      return 0;
    }
    const options = parseOptions(argv, io.env ?? process.env);
    const [download, policy, tallyCheckpoint, latestQuestionTreeHead] =
      await Promise.all([
        readJson(options.bundlePath, "vote proof bundle"),
        readJson(options.policyPath, "verification policy"),
        options.tallyCheckpointPath
          ? readJson(options.tallyCheckpointPath, "tally checkpoint")
          : Promise.resolve(undefined),
        options.latestQuestionHeadPath
          ? readJson(options.latestQuestionHeadPath, "latest question tree head")
          : Promise.resolve(undefined),
      ]);
    const bundle = downloadedBundle(download);
    const result = await verifyDownloadedVoteProof(
      options.allowUnpinnedPolicy
        ? {
            allowUnpinnedPolicy: true,
            bundle,
            latestQuestionTreeHead: downloadedCheckpoint(latestQuestionTreeHead),
            policy,
            tallyCheckpoint,
          }
        : {
            bundle,
            expectedPolicySha256: requiredPolicyHash(options),
            latestQuestionTreeHead: downloadedCheckpoint(latestQuestionTreeHead),
            policy,
            tallyCheckpoint,
          },
    );
    stdout(options.json ? JSON.stringify(result, null, 2) : humanResult(result));
    if (!result.cryptographicallyValid) return 1;
    if (!result.policyAnchored) return 4;
    if (options.requireCounted && !result.counted) return 3;
    return 0;
  } catch (error) {
    stderr(`Input error: ${error instanceof Error ? error.message : String(error)}`);
    stderr("Run with --help for usage.");
    return 2;
  }
}

function downloadedBundle(value: unknown) {
  if (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    "bundle" in value
  ) {
    return (value as { bundle: unknown }).bundle;
  }
  return value;
}

function downloadedCheckpoint(value: unknown) {
  if (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    "checkpoint" in value
  ) {
    return (value as { checkpoint: unknown }).checkpoint;
  }
  return value;
}

function parseOptions(
  argv: string[],
  env: Record<string, string | undefined>,
): CliOptions {
  let bundlePath: string | undefined;
  let policyPath: string | undefined;
  let expectedPolicySha256: string | undefined;
  let allowUnpinnedPolicy = false;
  let json = false;
  let latestQuestionHeadPath: string | undefined;
  let requireCounted = false;
  let tallyCheckpointPath: string | undefined;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--json") {
      json = true;
    } else if (argument === "--allow-unpinned-policy") {
      allowUnpinnedPolicy = true;
    } else if (argument === "--require-counted") {
      requireCounted = true;
    } else if (
      argument === "--bundle" ||
      argument === "--policy" ||
      argument === "--tally-snapshot" ||
      argument === "--latest-question-head" ||
      argument === "--expected-policy-sha256"
    ) {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) {
        throw new Error(`${argument} requires a value`);
      }
      index += 1;
      if (argument === "--bundle") bundlePath = value;
      if (argument === "--policy") policyPath = value;
      if (argument === "--tally-snapshot") tallyCheckpointPath = value;
      if (argument === "--latest-question-head") {
        latestQuestionHeadPath = value;
      }
      if (argument === "--expected-policy-sha256") {
        expectedPolicySha256 = value;
      }
    } else {
      throw new Error(`unknown argument: ${argument ?? ""}`);
    }
  }
  if (!bundlePath) throw new Error("--bundle is required");
  if (!policyPath) throw new Error("--policy is required");
  const environmentPolicySha256 = env.QUALIFIED_OPINION_POLICY_SHA256?.trim();
  if (
    expectedPolicySha256 &&
    environmentPolicySha256 &&
    expectedPolicySha256.toLowerCase() !== environmentPolicySha256.toLowerCase()
  ) {
    throw new Error(
      "--expected-policy-sha256 conflicts with QUALIFIED_OPINION_POLICY_SHA256",
    );
  }
  const pinned = expectedPolicySha256 ?? environmentPolicySha256;
  if (allowUnpinnedPolicy && pinned) {
    throw new Error(
      "--allow-unpinned-policy cannot be combined with an expected policy SHA-256",
    );
  }
  if (!allowUnpinnedPolicy && !pinned) {
    throw new Error(
      "--expected-policy-sha256 or QUALIFIED_OPINION_POLICY_SHA256 is required; use --allow-unpinned-policy only for explicitly untrusted inspection",
    );
  }
  if (pinned && !/^[0-9a-f]{64}$/i.test(pinned)) {
    throw new Error("expected policy SHA-256 must be 64 hexadecimal characters");
  }
  return {
    allowUnpinnedPolicy,
    bundlePath,
    expectedPolicySha256: pinned?.toLowerCase(),
    json,
    latestQuestionHeadPath,
    policyPath,
    requireCounted,
    tallyCheckpointPath,
  };
}

function requiredPolicyHash(options: CliOptions) {
  if (!options.expectedPolicySha256) {
    throw new Error("expected policy SHA-256 is required");
  }
  return options.expectedPolicySha256;
}

async function readJson(path: string, label: string) {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch {
    throw new Error(`cannot read ${label}: ${path}`);
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error(`${label} is not valid JSON: ${path}`);
  }
}

function humanResult(result: Awaited<ReturnType<typeof verifyDownloadedVoteProof>>) {
  const verificationSummary = result.cryptographicallyValid
    ? result.counted
      ? "COUNTED AT SIGNED TALLY CHECKPOINT"
      : result.completeness === "tally-checkpoint"
        ? result.status.replaceAll("_", " ").toUpperCase()
        : `INCLUSION ONLY (INCLUDED RECEIPT: ${
            result.includedReceiptStatus?.replaceAll("_", " ").toUpperCase() ??
            "UNAVAILABLE"
          })`
    : "INVALID UNDER SUPPLIED POLICY";
  const heading = result.policyAnchored
    ? result.cryptographicallyValid
      ? `VERIFIED — ${verificationSummary}`
      : "INVALID"
    : `UNANCHORED — ${verificationSummary}`;
  const lines = [
    heading,
    `Bundle: ${result.bundleId ?? "unavailable"}`,
    `Protocol: ${result.protocolVersion ?? "unavailable"}`,
    `Policy: ${result.policyId} (${result.policySha256})`,
  ];
  for (const check of result.checks) {
    lines.push(
      `${check.ok ? "✓" : "✗"} ${check.id}${check.error ? ` — ${check.error}` : ""}`,
    );
  }
  for (const warning of result.warnings) lines.push(`Warning: ${warning}`);
  return lines.join("\n");
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  process.exitCode = await runCli(process.argv.slice(2));
}
