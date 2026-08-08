#!/usr/bin/env bun

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";

const REPOSITORY_ROOT = resolve(import.meta.dir, "..");

export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(
      ([left], [right]) => Buffer.compare(Buffer.from(left), Buffer.from(right)),
    );
    return `{${entries
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(",")}}`;
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined) {
    throw new Error("Canonical JSON cannot encode this value");
  }
  return encoded;
}

function sha256Bytes(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function assertGitObjectId(value: string, name: string): string {
  if (!/^[0-9a-f]{40}$/.test(value)) {
    throw new Error(`${name} must be an exact SHA-1 commit identifier`);
  }
  return value;
}

function git(...arguments_: string[]): string {
  return execFileSync(
    "git",
    ["--no-replace-objects", "-C", REPOSITORY_ROOT, ...arguments_],
    {
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
      timeout: 30_000,
    },
  ).trim();
}

async function readJson(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, "utf8")) as unknown;
}

function parseArguments(values: string[]): Map<string, string> {
  if (values.length % 2 !== 0) throw new Error("Arguments must be name/value pairs");
  const parsed = new Map<string, string>();
  for (let index = 0; index < values.length; index += 2) {
    const rawName = values[index] ?? "";
    const value = values[index + 1] ?? "";
    if (!/^--[a-z][a-z-]*$/.test(rawName) || !value || parsed.has(rawName.slice(2))) {
      throw new Error("Invalid or duplicate command-line argument");
    }
    parsed.set(rawName.slice(2), value);
  }
  return parsed;
}

function argument(arguments_: Map<string, string>, name: string) {
  return arguments_.get(name);
}

function requiredArgument(arguments_: Map<string, string>, name: string) {
  const value = argument(arguments_, name);
  if (value === undefined) throw new Error(`Missing --${name}`);
  return value;
}

const DEFAULT_MANIFEST = new URL("../PUBLICATION-HARDENING.json", import.meta.url);
const DEFAULT_API_URL = "https://api.github.com";
const GITHUB_API_VERSION = "2022-11-28";
const WORKFLOW_PATH = ".github/workflows/post-public-hardening.yml";
const CREDENTIAL_SECRET = "PUBLICATION_HARDENING_TOKEN";
const FULL_SHA_ACTION = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@[0-9a-f]{40}$/;

type RequiredStatusCheck = { appId: number; context: string };

export type GitHubPublicationRepositoryManifest = {
  actions: {
    allowedActions: "selected";
    canApprovePullRequestReviews: false;
    defaultWorkflowPermissions: "read";
    enabled: true;
    githubOwnedAllowed: false;
    patternsAllowed: string[];
    shaPinningRequired: true;
    verifiedAllowed: false;
  };
  branchProtection: {
    allowDeletions: false;
    allowForcePushes: false;
    blockCreations: false;
    branch: string;
    dismissStaleReviews: true;
    enforceAdmins: true;
    requireCodeOwnerReviews: false;
    requireConversationResolution: true;
    requireLastPushApproval: false;
    requireLinearHistory: true;
    requirePullRequest: true;
    requireSignedCommits: true;
    requiredApprovingReviewCount: 0;
    requiredStatusChecks: RequiredStatusCheck[];
    strictStatusChecks: true;
  };
  credential: { secretName: typeof CREDENTIAL_SECRET };
  repository: {
    defaultBranch: string;
    description: string;
    homepage: string;
    name: string;
    owner: string;
    ownerId: number;
    repositoryId: number;
    settings: {
      allowMergeCommit: false;
      allowRebaseMerge: false;
      allowSquashMerge: true;
      deleteBranchOnMerge: true;
      hasDiscussions: false;
      hasIssues: true;
      hasProjects: false;
      hasWiki: false;
    };
    topics: string[];
    visibility: "public";
  };
  schema: "publication.github-repository-hardening-policy.current";
  security: {
    advancedSecurity: true;
    automatedSecurityFixes: true;
    dependencyGraph: true;
    privateVulnerabilityReporting: true;
    secretScanning: true;
    secretScanningPushProtection: true;
    vulnerabilityAlerts: true;
  };
};

export type HardeningInvocation = {
  actor: string;
  actorId: number;
  confirmation: string;
  eventName: "public" | "workflow_dispatch";
  ref: string;
  repository: string;
  repositoryId: number;
  repositoryOwnerId: number;
  repositoryVisibility: "public";
  runAttempt: number;
  sourceCommit: string;
  workflowRef: string;
  workflowSha: string;
};

export type GitHubResponse<T = unknown> = {
  status: number;
  value: T | null;
};

export type GitHubApi = {
  request<T = unknown>(
    method: "DELETE" | "GET" | "PATCH" | "POST" | "PUT",
    path: string,
    body?: unknown,
    acceptedStatuses?: number[],
  ): Promise<GitHubResponse<T>>;
};

type Inspection = {
  blockers: string[];
  credentialPresent: boolean;
  sourceCommit: string;
  targetReady: boolean;
  workflowId: number | null;
};

function record(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: string[], name: string) {
  const actual = Object.keys(value).sort();
  const target = [...expected].sort();
  if (canonicalJson(actual) !== canonicalJson(target)) {
    throw new Error(`${name} has unexpected fields`);
  }
}

function requiredText(value: unknown, name: string): string {
  if (typeof value !== "string" || !value.trim() || value !== value.trim()) {
    throw new Error(`${name} must be a non-empty trimmed string`);
  }
  return value;
}

function positiveInteger(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new Error(`${name} must be a positive integer`);
  }
  return value as number;
}

function sortedUniqueStrings(value: unknown, name: string): string[] {
  if (
    !Array.isArray(value) ||
    value.some((entry) => typeof entry !== "string" || !entry.trim())
  ) {
    throw new Error(`${name} must be an array of non-empty strings`);
  }
  const strings = value as string[];
  const sorted = [...strings].sort((left, right) => left.localeCompare(right));
  if (
    new Set(strings).size !== strings.length ||
    canonicalJson(strings) !== canonicalJson(sorted)
  ) {
    throw new Error(`${name} must be sorted and unique`);
  }
  return strings;
}

function requireExactBooleans(
  value: Record<string, unknown>,
  fields: string[],
  name: string,
) {
  for (const field of fields) {
    if (value[field] !== true) throw new Error(`${name}.${field} must be true`);
  }
}

export function validateGitHubPublicationRepositoryManifest(
  value: unknown,
): GitHubPublicationRepositoryManifest {
  const manifest = record(value, "publication repository policy");
  exactKeys(
    manifest,
    ["actions", "branchProtection", "credential", "repository", "schema", "security"],
    "publication repository policy",
  );
  if (manifest.schema !== "publication.github-repository-hardening-policy.current") {
    throw new Error("Unsupported publication repository policy schema");
  }

  const credential = record(manifest.credential, "credential policy");
  exactKeys(credential, ["secretName"], "credential policy");
  if (credential.secretName !== CREDENTIAL_SECRET) {
    throw new Error("The one-time credential secret name changed");
  }

  const repository = record(manifest.repository, "repository policy");
  exactKeys(
    repository,
    [
      "defaultBranch",
      "description",
      "homepage",
      "name",
      "owner",
      "ownerId",
      "repositoryId",
      "settings",
      "topics",
      "visibility",
    ],
    "repository policy",
  );
  const owner = requiredText(repository.owner, "repository owner");
  const name = requiredText(repository.name, "repository name");
  if (
    !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(owner) ||
    !/^[A-Za-z0-9_.-]{1,100}$/.test(name) ||
    repository.visibility !== "public" ||
    repository.defaultBranch !== "main" ||
    !/^https:\/\/[A-Za-z0-9.-]+(?:\/[^\s]*)?$/.test(
      requiredText(repository.homepage, "repository homepage"),
    )
  ) {
    throw new Error("Repository publication identity or metadata is invalid");
  }
  positiveInteger(repository.ownerId, "repository owner ID");
  positiveInteger(repository.repositoryId, "repository ID");
  requiredText(repository.description, "repository description");
  const topics = sortedUniqueStrings(repository.topics, "repository topics");
  if (topics.length < 2 || topics.some((topic) => !/^[a-z0-9-]{1,50}$/.test(topic))) {
    throw new Error("Repository topics are not a useful exact public set");
  }
  const settings = record(repository.settings, "repository settings");
  exactKeys(
    settings,
    [
      "allowMergeCommit",
      "allowRebaseMerge",
      "allowSquashMerge",
      "deleteBranchOnMerge",
      "hasDiscussions",
      "hasIssues",
      "hasProjects",
      "hasWiki",
    ],
    "repository settings",
  );
  if (
    settings.allowMergeCommit !== false ||
    settings.allowRebaseMerge !== false ||
    settings.allowSquashMerge !== true ||
    settings.deleteBranchOnMerge !== true ||
    settings.hasDiscussions !== false ||
    settings.hasIssues !== true ||
    settings.hasProjects !== false ||
    settings.hasWiki !== false
  ) {
    throw new Error("Repository settings differ from the reviewed public policy");
  }

  const actions = record(manifest.actions, "Actions policy");
  exactKeys(
    actions,
    [
      "allowedActions",
      "canApprovePullRequestReviews",
      "defaultWorkflowPermissions",
      "enabled",
      "githubOwnedAllowed",
      "patternsAllowed",
      "shaPinningRequired",
      "verifiedAllowed",
    ],
    "Actions policy",
  );
  if (
    actions.enabled !== true ||
    actions.allowedActions !== "selected" ||
    actions.shaPinningRequired !== true ||
    actions.defaultWorkflowPermissions !== "read" ||
    actions.canApprovePullRequestReviews !== false ||
    actions.githubOwnedAllowed !== false ||
    actions.verifiedAllowed !== false
  ) {
    throw new Error("Actions policy differs from the reviewed least-authority policy");
  }
  const patterns = sortedUniqueStrings(
    actions.patternsAllowed,
    "allowed Actions patterns",
  );
  if (
    patterns.length === 0 ||
    patterns.some((pattern) => !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@\*$/.test(pattern))
  ) {
    throw new Error("Allowed Actions patterns must name exact action repositories");
  }

  const protection = record(manifest.branchProtection, "branch protection policy");
  exactKeys(
    protection,
    [
      "allowDeletions",
      "allowForcePushes",
      "blockCreations",
      "branch",
      "dismissStaleReviews",
      "enforceAdmins",
      "requireCodeOwnerReviews",
      "requireConversationResolution",
      "requireLastPushApproval",
      "requireLinearHistory",
      "requirePullRequest",
      "requireSignedCommits",
      "requiredApprovingReviewCount",
      "requiredStatusChecks",
      "strictStatusChecks",
    ],
    "branch protection policy",
  );
  const trueFields = [
    "dismissStaleReviews",
    "enforceAdmins",
    "requireConversationResolution",
    "requireLinearHistory",
    "requirePullRequest",
    "requireSignedCommits",
    "strictStatusChecks",
  ];
  requireExactBooleans(protection, trueFields, "branch protection policy");
  if (
    protection.branch !== repository.defaultBranch ||
    protection.allowDeletions !== false ||
    protection.allowForcePushes !== false ||
    protection.blockCreations !== false ||
    protection.requireCodeOwnerReviews !== false ||
    protection.requireLastPushApproval !== false ||
    protection.requiredApprovingReviewCount !== 0
  ) {
    throw new Error(
      "Branch protection differs from the reviewed sole-maintainer policy",
    );
  }
  if (
    !Array.isArray(protection.requiredStatusChecks) ||
    protection.requiredStatusChecks.length < 1
  ) {
    throw new Error("At least one required status check is required");
  }
  const checkKeys = new Set<string>();
  for (const candidate of protection.requiredStatusChecks) {
    const check = record(candidate, "required status check");
    exactKeys(check, ["appId", "context"], "required status check");
    const context = requiredText(check.context, "required status check context");
    positiveInteger(check.appId, "required status check App ID");
    if (checkKeys.has(context))
      throw new Error("Required status checks must be unique");
    checkKeys.add(context);
  }

  const security = record(manifest.security, "security policy");
  const securityFields = [
    "advancedSecurity",
    "automatedSecurityFixes",
    "dependencyGraph",
    "privateVulnerabilityReporting",
    "secretScanning",
    "secretScanningPushProtection",
    "vulnerabilityAlerts",
  ];
  exactKeys(security, securityFields, "security policy");
  requireExactBooleans(security, securityFields, "security policy");
  return manifest as GitHubPublicationRepositoryManifest;
}

export async function loadGitHubPublicationRepositoryManifest(
  path = DEFAULT_MANIFEST.pathname,
) {
  return validateGitHubPublicationRepositoryManifest(await readJson(path));
}

function numericEnvironment(environment: NodeJS.ProcessEnv, name: string): number {
  return positiveInteger(Number(environment[name]), name);
}

export function invocationFromEnvironment(
  manifest: GitHubPublicationRepositoryManifest,
  environment: NodeJS.ProcessEnv = process.env,
): HardeningInvocation {
  const eventName = environment.GITHUB_EVENT_NAME;
  if (eventName !== "public" && eventName !== "workflow_dispatch") {
    throw new Error("Hardening accepts only public or workflow_dispatch events");
  }
  const confirmation = environment.PUBLICATION_HARDENING_CONFIRMATION ?? "";
  if (
    eventName === "workflow_dispatch" &&
    confirmation !== "harden-public-repository"
  ) {
    throw new Error("Manual hardening requires the exact confirmation phrase");
  }
  if (eventName === "public" && confirmation !== "") {
    throw new Error("The public event cannot carry a manual confirmation");
  }
  const sourceCommit = assertGitObjectId(environment.GITHUB_SHA ?? "", "GITHUB_SHA");
  const workflowSha = assertGitObjectId(
    environment.PUBLICATION_GITHUB_WORKFLOW_SHA ?? "",
    "PUBLICATION_GITHUB_WORKFLOW_SHA",
  );
  const invocation: HardeningInvocation = {
    actor: requiredText(environment.GITHUB_ACTOR, "GITHUB_ACTOR"),
    actorId: numericEnvironment(environment, "PUBLICATION_GITHUB_ACTOR_ID"),
    confirmation,
    eventName,
    ref: requiredText(environment.GITHUB_REF, "GITHUB_REF"),
    repository: requiredText(environment.GITHUB_REPOSITORY, "GITHUB_REPOSITORY"),
    repositoryId: numericEnvironment(environment, "PUBLICATION_GITHUB_REPOSITORY_ID"),
    repositoryOwnerId: numericEnvironment(
      environment,
      "PUBLICATION_GITHUB_REPOSITORY_OWNER_ID",
    ),
    repositoryVisibility: requiredText(
      environment.PUBLICATION_GITHUB_REPOSITORY_VISIBILITY,
      "PUBLICATION_GITHUB_REPOSITORY_VISIBILITY",
    ) as "public",
    runAttempt: numericEnvironment(environment, "GITHUB_RUN_ATTEMPT"),
    sourceCommit,
    workflowRef: requiredText(environment.GITHUB_WORKFLOW_REF, "GITHUB_WORKFLOW_REF"),
    workflowSha,
  };
  const repositoryName = `${manifest.repository.owner}/${manifest.repository.name}`;
  if (
    invocation.actor !== manifest.repository.owner ||
    invocation.actorId !== manifest.repository.ownerId ||
    invocation.repository !== repositoryName ||
    invocation.repositoryId !== manifest.repository.repositoryId ||
    invocation.repositoryOwnerId !== manifest.repository.ownerId ||
    invocation.repositoryVisibility !== "public" ||
    invocation.ref !== `refs/heads/${manifest.repository.defaultBranch}` ||
    invocation.workflowRef !==
      `${repositoryName}/${WORKFLOW_PATH}@refs/heads/${manifest.repository.defaultBranch}` ||
    invocation.workflowSha !== sourceCommit ||
    invocation.runAttempt !== 1
  ) {
    throw new Error("Workflow invocation is outside the reviewed publication boundary");
  }
  return invocation;
}

async function workflowFiles(root: string): Promise<string[]> {
  const directory = resolve(root, ".github/workflows");
  return (await readdir(directory))
    .filter((name) => name.endsWith(".yml") || name.endsWith(".yaml"))
    .map((name) => resolve(directory, name))
    .sort();
}

export async function verifyPublicationHardeningSource(
  manifest: GitHubPublicationRepositoryManifest,
  root = REPOSITORY_ROOT,
) {
  const actions = new Set<string>();
  const runnerLabels: string[] = [];
  for (const path of await workflowFiles(root)) {
    const source = await readFile(path, "utf8");
    for (const match of source.matchAll(/^\s*runs-on:\s*(.+?)\s*$/gm)) {
      runnerLabels.push(match[1] ?? "");
    }
    for (const match of source.matchAll(/^\s*uses:\s*([^\s#]+).*$/gm)) {
      const reference = match[1] ?? "";
      if (reference.startsWith("./")) continue;
      if (!FULL_SHA_ACTION.test(reference)) {
        throw new Error(`Workflow action is not pinned to a full SHA: ${reference}`);
      }
      actions.add(`${reference.slice(0, reference.indexOf("@"))}@*`);
    }
  }
  if (
    runnerLabels.length === 0 ||
    runnerLabels.some((label) => label !== "ubuntu-24.04")
  ) {
    throw new Error("Every workflow job must use the fixed ubuntu-24.04 runner");
  }
  const expected = [...manifest.actions.patternsAllowed].sort();
  const actual = [...actions].sort();
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    throw new Error("Allowed Actions patterns do not exactly match workflow sources");
  }
  const ci = await readFile(resolve(root, ".github/workflows/ci.yml"), "utf8");
  const secretScan = await readFile(
    resolve(root, ".github/workflows/secret-scan.yml"),
    "utf8",
  );
  const checkSources = [ci, secretScan];
  for (const check of manifest.branchProtection.requiredStatusChecks) {
    let count = checkSources.reduce(
      (sum, source) => sum + source.split(`name: ${check.context}`).length - 1,
      0,
    );
    if (count === 0) {
      for (const source of checkSources) {
        for (const line of source.split("\n")) {
          const declaration = line.match(
            /^\s*name:\s*(.+\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}.+)$/,
          );
          if (!declaration?.[1] || !declaration[2]) continue;
          const escaped = declaration[1]
            .replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
            .replace(/\\\$\\\{\\\{\s*matrix\\\.([A-Za-z0-9_-]+)\s*\\\}\\\}/, "(.+)");
          const match = check.context.match(new RegExp(`^${escaped}$`));
          if (
            match?.[1] &&
            new RegExp(
              `^\\s*-\\s+${declaration[2]}:\\s*[\"']?${match[1].replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}[\"']?\\s*$`,
              "m",
            ).test(source)
          ) {
            count += 1;
          }
        }
      }
    }
    if (count !== 1) {
      throw new Error(
        `Required check name is not declared exactly once: ${check.context}`,
      );
    }
  }
  const hardening = await readFile(resolve(root, WORKFLOW_PATH), "utf8");
  for (const required of [
    "  public:",
    "  workflow_dispatch:",
    "permissions:\n  contents: read",
    "--operation validate-source",
    "--operation apply-and-retire",
    `secrets.${CREDENTIAL_SECRET}`,
  ]) {
    if (!hardening.includes(required)) {
      throw new Error(`Hardening workflow is missing its source contract: ${required}`);
    }
  }
  const secretReference = `\${{ secrets.${CREDENTIAL_SECRET} }}`;
  const expectedSecretStep = [
    "      - name: Apply, audit, and retire publication authority",
    "        env:",
    `          ${CREDENTIAL_SECRET}: ${secretReference}`,
    "        run: >-",
    "          bun publication:harden-repository",
    "          --operation apply-and-retire",
  ].join("\n");
  if (
    hardening.split(secretReference).length !== 2 ||
    !hardening.includes(expectedSecretStep)
  ) {
    throw new Error(
      "The owner token must be exposed only to the exact local apply-and-retire step",
    );
  }
  return {
    actionPatterns: actual,
    requiredChecks: manifest.branchProtection.requiredStatusChecks,
  };
}

export function assertLocalPublicationSource(
  manifest: GitHubPublicationRepositoryManifest,
  invocation: HardeningInvocation,
) {
  if (git("rev-parse", "HEAD") !== invocation.sourceCommit) {
    throw new Error("Checked-out source does not match GITHUB_SHA");
  }
  if (git("status", "--porcelain", "--untracked-files=all") !== "") {
    throw new Error("Publication hardening requires a clean checkout");
  }
  const manifestPath = "PUBLICATION-HARDENING.json";
  const committed = git("show", `${invocation.sourceCommit}:${manifestPath}`);
  const current = readFileSync(resolve(REPOSITORY_ROOT, manifestPath), "utf8").trim();
  if (committed !== current) {
    throw new Error("Publication hardening manifest is not the committed source copy");
  }
  if (manifest.repository.defaultBranch !== "main") {
    throw new Error("Publication hardening is restricted to main");
  }
}

function responseRecord<T>(response: GitHubResponse<T>, name: string) {
  return record(response.value, name);
}

function basePath(manifest: GitHubPublicationRepositoryManifest) {
  return `/repos/${encodeURIComponent(manifest.repository.owner)}/${encodeURIComponent(manifest.repository.name)}`;
}

async function paginated(
  api: GitHubApi,
  path: string,
  field: string,
): Promise<unknown[]> {
  if (!path.includes("per_page=100") || path.includes("&page=")) {
    throw new Error("Invalid paginated API path");
  }
  const entries: unknown[] = [];
  let total: number | null = null;
  for (let page = 1; page <= 20; page += 1) {
    const response = await api.request("GET", `${path}&page=${page}`);
    const value = responseRecord(response, `${field} inventory`);
    if (!Number.isSafeInteger(value.total_count) || !Array.isArray(value[field])) {
      throw new Error(`${field} inventory is malformed`);
    }
    if (total === null) total = value.total_count as number;
    if (value.total_count !== total || (value[field] as unknown[]).length > 100) {
      throw new Error(`${field} inventory changed during pagination`);
    }
    entries.push(...(value[field] as unknown[]));
    if (entries.length === total) return entries;
    if (entries.length > total || (value[field] as unknown[]).length === 0) {
      throw new Error(`${field} pagination did not converge`);
    }
  }
  throw new Error(`${field} inventory exceeds the reviewed bound`);
}

async function arrayPaginated(api: GitHubApi, path: string, name: string) {
  if (!path.includes("per_page=100") || path.includes("&page=")) {
    throw new Error("Invalid array-paginated API path");
  }
  const entries: unknown[] = [];
  for (let page = 1; page <= 20; page += 1) {
    const response = await api.request("GET", `${path}&page=${page}`);
    if (!Array.isArray(response.value) || response.value.length > 100) {
      throw new Error(`${name} inventory is malformed`);
    }
    entries.push(...response.value);
    if (response.value.length < 100) return entries;
  }
  throw new Error(`${name} inventory exceeds the reviewed bound`);
}

function hardeningWorkflow(
  entries: unknown[],
  expectedState: "active" | "disabled_manually",
) {
  const matches = entries.filter((candidate) => {
    const workflow = record(candidate, "Actions workflow");
    return workflow.path === WORKFLOW_PATH;
  });
  if (matches.length !== 1) {
    throw new Error("Hardening workflow inventory is not exact");
  }
  const workflow = record(matches[0], "hardening workflow");
  const id = positiveInteger(workflow.id, "hardening workflow ID");
  if (workflow.path !== WORKFLOW_PATH || workflow.state !== expectedState) {
    throw new Error(`Hardening workflow is not ${expectedState}`);
  }
  return { id, path: WORKFLOW_PATH, state: expectedState } as const;
}

function securityStatus(value: unknown, field: string) {
  try {
    const security = record(value, "security_and_analysis");
    const setting = record(security[field], `security_and_analysis.${field}`);
    return setting.status === "enabled";
  } catch {
    return false;
  }
}

function securityFieldPresent(value: unknown, field: string) {
  try {
    return record(value, "security_and_analysis")[field] !== undefined;
  } catch {
    return false;
  }
}

function expectedProtection(manifest: GitHubPublicationRepositoryManifest) {
  const policy = manifest.branchProtection;
  return {
    allow_deletions: policy.allowDeletions,
    allow_force_pushes: policy.allowForcePushes,
    allow_fork_syncing: false,
    block_creations: policy.blockCreations,
    enforce_admins: policy.enforceAdmins,
    lock_branch: false,
    required_conversation_resolution: policy.requireConversationResolution,
    required_linear_history: policy.requireLinearHistory,
    required_pull_request_reviews: {
      // bypass_pull_request_allowances is deliberately absent: GitHub rejects
      // actor allowances on user-account repositories.
      dismiss_stale_reviews: policy.dismissStaleReviews,
      require_code_owner_reviews: policy.requireCodeOwnerReviews,
      require_last_push_approval: policy.requireLastPushApproval,
      required_approving_review_count: policy.requiredApprovingReviewCount,
    },
    required_status_checks: {
      checks: policy.requiredStatusChecks.map(({ appId, context }) => ({
        app_id: appId,
        context,
      })),
      strict: policy.strictStatusChecks,
    },
    restrictions: null,
  };
}

function emptyActorAllowance(value: unknown): boolean {
  if (value === undefined || value === null) return true;
  const allowance = record(value, "branch protection actor allowance");
  return ["apps", "teams", "users"].every(
    (field) => Array.isArray(allowance[field]) && allowance[field].length === 0,
  );
}

function expectedNormalizedProtection(manifest: GitHubPublicationRepositoryManifest) {
  const expected = expectedProtection(manifest);
  return {
    ...expected,
    required_pull_request_reviews: {
      ...expected.required_pull_request_reviews,
      bypass_pull_request_allowances_empty: true,
      dismissal_restrictions_empty: true,
    },
  };
}

function normalizedProtection(value: unknown) {
  const protection = record(value, "branch protection");
  const enabled = (name: string) =>
    record(protection[name], `branch protection ${name}`).enabled === true;
  const statuses = record(protection.required_status_checks, "required status checks");
  const reviews = record(
    protection.required_pull_request_reviews,
    "required pull-request reviews",
  );
  const checks = Array.isArray(statuses.checks)
    ? statuses.checks.map((candidate) => {
        const check = record(candidate, "required status check");
        return { app_id: Number(check.app_id), context: String(check.context) };
      })
    : [];
  checks.sort((left, right) => left.context.localeCompare(right.context));
  return {
    allow_deletions: enabled("allow_deletions"),
    allow_force_pushes: enabled("allow_force_pushes"),
    allow_fork_syncing: enabled("allow_fork_syncing"),
    block_creations: enabled("block_creations"),
    enforce_admins: enabled("enforce_admins"),
    lock_branch: enabled("lock_branch"),
    required_conversation_resolution: enabled("required_conversation_resolution"),
    required_linear_history: enabled("required_linear_history"),
    required_pull_request_reviews: {
      bypass_pull_request_allowances_empty: emptyActorAllowance(
        reviews.bypass_pull_request_allowances,
      ),
      dismissal_restrictions_empty: emptyActorAllowance(reviews.dismissal_restrictions),
      dismiss_stale_reviews: reviews.dismiss_stale_reviews === true,
      require_code_owner_reviews: reviews.require_code_owner_reviews === true,
      require_last_push_approval: reviews.require_last_push_approval === true,
      required_approving_review_count: Number(reviews.required_approving_review_count),
    },
    required_status_checks: { checks, strict: statuses.strict === true },
    restrictions: protection.restrictions ?? null,
  };
}

async function inspect(
  manifest: GitHubPublicationRepositoryManifest,
  api: GitHubApi,
  invocation: HardeningInvocation,
): Promise<Inspection> {
  const blockers: string[] = [];
  const base = basePath(manifest);
  const user = responseRecord(await api.request("GET", "/user"), "authenticated user");
  if (
    user.login !== manifest.repository.owner ||
    user.id !== manifest.repository.ownerId ||
    user.type !== "User"
  ) {
    throw new Error("Hardening token is not the exact repository owner");
  }
  const repository = responseRecord(await api.request("GET", base), "repository");
  const owner = record(repository.owner, "repository owner");
  const permissions = record(repository.permissions, "repository permissions");
  if (
    repository.id !== manifest.repository.repositoryId ||
    repository.name !== manifest.repository.name ||
    owner.login !== manifest.repository.owner ||
    owner.id !== manifest.repository.ownerId ||
    repository.private !== false ||
    repository.visibility !== "public" ||
    repository.default_branch !== manifest.repository.defaultBranch ||
    repository.fork !== false ||
    repository.archived !== false ||
    repository.disabled !== false ||
    permissions.admin !== true
  ) {
    throw new Error(
      "Target is not the exact public repository with owner administration",
    );
  }
  const ref = responseRecord(
    await api.request(
      "GET",
      `${base}/git/ref/heads/${encodeURIComponent(manifest.repository.defaultBranch)}`,
    ),
    "default branch ref",
  );
  const object = record(ref.object, "default branch ref object");
  if (object.type !== "commit" || object.sha !== invocation.sourceCommit) {
    throw new Error("Default branch moved away from the hardening source commit");
  }
  const checkRuns = await paginated(
    api,
    `${base}/commits/${invocation.sourceCommit}/check-runs?filter=latest&per_page=100`,
    "check_runs",
  );
  for (const expected of manifest.branchProtection.requiredStatusChecks) {
    const matching = checkRuns.filter((candidate) => {
      const run = record(candidate, "check run");
      return run.name === expected.context;
    });
    if (matching.length !== 1) {
      blockers.push(`required_check_inventory:${expected.context}`);
      continue;
    }
    const run = record(matching[0], "required check run");
    const app = record(run.app, "required check run app");
    if (
      run.head_sha !== invocation.sourceCommit ||
      run.status !== "completed" ||
      run.conclusion !== "success" ||
      app.id !== expected.appId
    ) {
      blockers.push(`required_check_not_successful:${expected.context}`);
    }
  }
  const secrets = await paginated(
    api,
    `${base}/actions/secrets?per_page=100`,
    "secrets",
  );
  const secretNames = secrets.map((candidate) =>
    requiredText(record(candidate, "repository secret").name, "repository secret name"),
  );
  const credentialPresent = secretNames.includes(manifest.credential.secretName);
  if (
    canonicalJson([...secretNames].sort()) !==
    canonicalJson([manifest.credential.secretName])
  ) {
    blockers.push("repository_secret_inventory_not_one_time_only");
  }
  const collaborators = await arrayPaginated(
    api,
    `${base}/collaborators?affiliation=all&per_page=100`,
    "collaborators",
  );
  if (collaborators.length !== 1) {
    blockers.push("repository_collaborator_inventory");
  } else {
    const collaborator = record(collaborators[0], "repository collaborator");
    const collaboratorPermissions = record(
      collaborator.permissions,
      "repository collaborator permissions",
    );
    if (
      collaborator.login !== manifest.repository.owner ||
      collaborator.id !== manifest.repository.ownerId ||
      collaborator.role_name !== "admin" ||
      collaboratorPermissions.admin !== true
    ) {
      blockers.push("repository_collaborator_inventory");
    }
  }
  const deployKeys = await arrayPaginated(
    api,
    `${base}/keys?per_page=100`,
    "deploy keys",
  );
  if (deployKeys.length !== 0) blockers.push("repository_deploy_keys");
  const invitations = await arrayPaginated(
    api,
    `${base}/invitations?per_page=100`,
    "repository invitations",
  );
  if (invitations.length !== 0) {
    blockers.push("repository_collaborator_invitations");
  }
  const rulesets = await arrayPaginated(
    api,
    `${base}/rulesets?per_page=100`,
    "repository rulesets",
  );
  if (rulesets.length !== 0) blockers.push("repository_rulesets");
  let workflowId: number | null = null;
  try {
    const workflows = await paginated(
      api,
      `${base}/actions/workflows?per_page=100`,
      "workflows",
    );
    workflowId = hardeningWorkflow(workflows, "active").id;
  } catch {
    blockers.push("hardening_workflow_not_active");
  }

  const settings = manifest.repository.settings;
  for (const [field, expected] of [
    ["allow_merge_commit", settings.allowMergeCommit],
    ["allow_rebase_merge", settings.allowRebaseMerge],
    ["allow_squash_merge", settings.allowSquashMerge],
    ["delete_branch_on_merge", settings.deleteBranchOnMerge],
    ["has_discussions", settings.hasDiscussions],
    ["has_issues", settings.hasIssues],
    ["has_projects", settings.hasProjects],
    ["has_wiki", settings.hasWiki],
  ] as const) {
    if (repository[field] !== expected) blockers.push(`repository_setting:${field}`);
  }
  if (
    repository.description !== manifest.repository.description ||
    repository.homepage !== manifest.repository.homepage
  ) {
    blockers.push("repository_metadata");
  }
  const security = repository.security_and_analysis;
  for (const field of [
    "advanced_security",
    "secret_scanning",
    "secret_scanning_push_protection",
  ]) {
    if (field === "advanced_security" && !securityFieldPresent(security, field)) {
      // GitHub omits this field for public repositories, where advanced
      // security is unconditionally available; the preflight separately
      // requires public visibility.
      continue;
    }
    if (!securityStatus(security, field)) blockers.push(`security:${field}`);
  }

  const topics = responseRecord(await api.request("GET", `${base}/topics`), "topics");
  const observedTopics = Array.isArray(topics.names)
    ? topics.names.map((topic) => requiredText(topic, "repository topic")).sort()
    : [];
  if (canonicalJson(observedTopics) !== canonicalJson(manifest.repository.topics)) {
    blockers.push("repository_topics");
  }
  const actions = responseRecord(
    await api.request("GET", `${base}/actions/permissions`),
    "Actions permissions",
  );
  if (
    actions.enabled !== true ||
    actions.allowed_actions !== "selected" ||
    actions.sha_pinning_required !== true
  ) {
    blockers.push("actions_permissions");
  }
  const selectedResponse = await api.request(
    "GET",
    `${base}/actions/permissions/selected-actions`,
    undefined,
    [200, 409],
  );
  const selected =
    selectedResponse.status === 200
      ? responseRecord(selectedResponse, "selected Actions")
      : null;
  const observedPatterns = Array.isArray(selected?.patterns_allowed)
    ? selected.patterns_allowed
        .map((pattern) => requiredText(pattern, "selected Actions pattern"))
        .sort()
    : [];
  if (
    selected === null ||
    selected.github_owned_allowed !== false ||
    selected.verified_allowed !== false ||
    canonicalJson(observedPatterns) !== canonicalJson(manifest.actions.patternsAllowed)
  ) {
    blockers.push("selected_actions");
  }
  const workflow = responseRecord(
    await api.request("GET", `${base}/actions/permissions/workflow`),
    "workflow permissions",
  );
  if (
    workflow.default_workflow_permissions !== "read" ||
    workflow.can_approve_pull_request_reviews !== false
  ) {
    blockers.push("workflow_permissions");
  }
  const protectionResponse = await api.request(
    "GET",
    `${base}/branches/${encodeURIComponent(manifest.branchProtection.branch)}/protection`,
    undefined,
    [200, 404],
  );
  const expected = expectedNormalizedProtection(manifest);
  expected.required_status_checks.checks.sort((left, right) =>
    left.context.localeCompare(right.context),
  );
  if (
    protectionResponse.status !== 200 ||
    canonicalJson(normalizedProtection(protectionResponse.value)) !==
      canonicalJson(expected)
  ) {
    blockers.push("branch_protection");
  }
  const signaturesResponse = await api.request(
    "GET",
    `${base}/branches/${encodeURIComponent(manifest.branchProtection.branch)}/protection/required_signatures`,
    undefined,
    [200, 404],
  );
  const signatures =
    signaturesResponse.status === 200
      ? responseRecord(signaturesResponse, "required signatures")
      : null;
  if (signatures?.enabled !== true) blockers.push("required_signatures");
  const vulnerabilityAlerts = await api.request(
    "GET",
    `${base}/vulnerability-alerts`,
    undefined,
    [204, 404],
  );
  if (vulnerabilityAlerts.status !== 204) blockers.push("vulnerability_alerts");
  const automatedFixes = await api.request(
    "GET",
    `${base}/automated-security-fixes`,
    undefined,
    [200, 404],
  );
  const automatedFixesState =
    automatedFixes.status === 200
      ? responseRecord(automatedFixes, "automated security fixes")
      : null;
  if (automatedFixesState?.enabled !== true || automatedFixesState.paused !== false) {
    blockers.push("automated_security_fixes");
  }
  const reporting = responseRecord(
    await api.request("GET", `${base}/private-vulnerability-reporting`),
    "private vulnerability reporting",
  );
  if (reporting.enabled !== true) blockers.push("private_vulnerability_reporting");
  return {
    blockers: [...new Set(blockers)].sort(),
    credentialPresent,
    sourceCommit: invocation.sourceCommit,
    targetReady: blockers.length === 0,
    workflowId,
  };
}

export async function applyAndRetireGitHubPublicationRepository(
  manifest: GitHubPublicationRepositoryManifest,
  api: GitHubApi,
  invocation: HardeningInvocation,
  options: {
    auditAttempts?: number;
    auditDeadlineMs?: number;
    auditDelayMs?: number;
    now?: () => number;
    sleep?: (milliseconds: number) => Promise<void>;
  } = {},
) {
  const preflight = await inspect(manifest, api, invocation);
  const allowedPreflight = new Set([
    "actions_permissions",
    "automated_security_fixes",
    "branch_protection",
    "private_vulnerability_reporting",
    "repository_metadata",
    "repository_topics",
    "required_signatures",
    "selected_actions",
    "vulnerability_alerts",
    "workflow_permissions",
    ...["advanced_security", "secret_scanning", "secret_scanning_push_protection"].map(
      (field) => `security:${field}`,
    ),
    ...[
      "allow_merge_commit",
      "allow_rebase_merge",
      "allow_squash_merge",
      "delete_branch_on_merge",
      "has_discussions",
      "has_issues",
      "has_projects",
      "has_wiki",
    ].map((field) => `repository_setting:${field}`),
  ]);
  const unsafe = preflight.blockers.filter((blocker) => !allowedPreflight.has(blocker));
  if (!preflight.credentialPresent || unsafe.length > 0) {
    throw new Error(`Publication hardening preflight failed: ${unsafe.join(",")}`);
  }
  const base = basePath(manifest);
  const settings = manifest.repository.settings;
  await api.request("PATCH", base, {
    allow_merge_commit: settings.allowMergeCommit,
    allow_rebase_merge: settings.allowRebaseMerge,
    allow_squash_merge: settings.allowSquashMerge,
    delete_branch_on_merge: settings.deleteBranchOnMerge,
    description: manifest.repository.description,
    has_discussions: settings.hasDiscussions,
    has_issues: settings.hasIssues,
    has_projects: settings.hasProjects,
    has_wiki: settings.hasWiki,
    homepage: manifest.repository.homepage,
    security_and_analysis: {
      // advanced_security is deliberately absent: GitHub rejects setting it
      // on public repositories, where it is always available.
      secret_scanning: { status: "enabled" },
      secret_scanning_push_protection: { status: "enabled" },
    },
  });
  await api.request("PUT", `${base}/topics`, {
    names: manifest.repository.topics,
  });
  await api.request("PUT", `${base}/actions/permissions`, {
    allowed_actions: "selected",
    enabled: true,
    sha_pinning_required: true,
  });
  await api.request("PUT", `${base}/actions/permissions/selected-actions`, {
    github_owned_allowed: false,
    patterns_allowed: manifest.actions.patternsAllowed,
    verified_allowed: false,
  });
  await api.request("PUT", `${base}/actions/permissions/workflow`, {
    can_approve_pull_request_reviews: false,
    default_workflow_permissions: "read",
  });
  await api.request(
    "PUT",
    `${base}/branches/${encodeURIComponent(manifest.branchProtection.branch)}/protection`,
    expectedProtection(manifest),
  );
  await api.request(
    "POST",
    `${base}/branches/${encodeURIComponent(manifest.branchProtection.branch)}/protection/required_signatures`,
  );
  await api.request("PUT", `${base}/vulnerability-alerts`);
  await api.request("PUT", `${base}/automated-security-fixes`);
  await api.request("PUT", `${base}/private-vulnerability-reporting`);

  const auditAttempts = options.auditAttempts ?? 24;
  const auditDeadlineMs = options.auditDeadlineMs ?? 120_000;
  const auditDelayMs = options.auditDelayMs ?? 5_000;
  const now = options.now ?? Date.now;
  const sleep = options.sleep ?? Bun.sleep;
  if (
    !Number.isSafeInteger(auditAttempts) ||
    auditAttempts < 1 ||
    !Number.isSafeInteger(auditDeadlineMs) ||
    auditDeadlineMs < 1 ||
    !Number.isSafeInteger(auditDelayMs) ||
    auditDelayMs < 0
  ) {
    throw new Error("Invalid bounded post-apply audit policy");
  }
  const auditDeadline = now() + auditDeadlineMs;
  let finalInspection: Inspection | null = null;
  for (let attempt = 1; attempt <= auditAttempts; attempt += 1) {
    finalInspection = await inspect(manifest, api, invocation);
    if (finalInspection.targetReady && finalInspection.credentialPresent) break;
    if (attempt === auditAttempts || now() + auditDelayMs > auditDeadline) {
      break;
    }
    await sleep(auditDelayMs);
  }
  if (
    !finalInspection?.targetReady ||
    !finalInspection.credentialPresent ||
    finalInspection.workflowId === null
  ) {
    throw new Error(
      `Publication hardening audit failed: ${finalInspection?.blockers.join(",") ?? "deadline"}`,
    );
  }
  await api.request(
    "DELETE",
    `${base}/actions/secrets/${encodeURIComponent(manifest.credential.secretName)}`,
  );
  const remainingSecrets = await paginated(
    api,
    `${base}/actions/secrets?per_page=100`,
    "secrets",
  );
  if (remainingSecrets.length !== 0) {
    throw new Error("Temporary repository secret was not removed exactly");
  }
  await api.request(
    "PUT",
    `${base}/actions/workflows/${finalInspection.workflowId}/disable`,
  );
  const retiredWorkflow = responseRecord(
    await api.request("GET", `${base}/actions/workflows/${finalInspection.workflowId}`),
    "retired hardening workflow",
  );
  const retired = hardeningWorkflow([retiredWorkflow], "disabled_manually");
  if (retired.id !== finalInspection.workflowId) {
    throw new Error("The retired hardening workflow identity changed");
  }
  return {
    manifestSha256: sha256Bytes(canonicalJson(manifest)),
    repository: `${manifest.repository.owner}/${manifest.repository.name}`,
    repositoryId: manifest.repository.repositoryId,
    repositorySecretRemoved: true,
    schema: "publication.github-repository-hardening-evidence.current",
    sourceCommit: invocation.sourceCommit,
    targetReady: true,
    workflowRetired: true,
  } as const;
}

export class GitHubRestApi implements GitHubApi {
  constructor(
    private readonly token: string,
    private readonly baseUrl = DEFAULT_API_URL,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {
    if (!token.trim()) throw new Error(`Missing ${CREDENTIAL_SECRET}`);
    if (new URL(baseUrl).href !== `${DEFAULT_API_URL}/`) {
      throw new Error("GitHub API URL must be the reviewed api.github.com origin");
    }
  }

  async request<T>(
    method: "DELETE" | "GET" | "PATCH" | "POST" | "PUT",
    path: string,
    body?: unknown,
    acceptedStatuses = [200, 201, 202, 204],
  ): Promise<GitHubResponse<T>> {
    if (!path.startsWith("/")) throw new Error("GitHub API path must be absolute");
    const url = new URL(path, this.baseUrl);
    if (url.origin !== DEFAULT_API_URL || url.username !== "" || url.password !== "") {
      throw new Error("GitHub API path escaped the reviewed api.github.com origin");
    }
    const response = await this.fetchImpl(url, {
      body: body === undefined ? undefined : canonicalJson(body),
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${this.token}`,
        "content-type": "application/json",
        "x-github-api-version": GITHUB_API_VERSION,
      },
      method,
      redirect: "error",
      signal: AbortSignal.timeout(30_000),
    });
    if (!acceptedStatuses.includes(response.status)) {
      throw new Error(`GitHub API ${method} ${path} failed (${response.status})`);
    }
    return {
      status: response.status,
      value: response.status === 204 ? null : ((await response.json()) as T),
    };
  }
}

function requiredEnvironment(name: string) {
  const value = process.env[name];
  if (!value?.trim()) throw new Error(`Missing ${name}`);
  return value;
}

async function main() {
  const args = parseArguments(Bun.argv.slice(2));
  const operation = requiredArgument(args, "operation");
  if (args.size !== 1) {
    throw new Error("Publication hardening accepts only --operation");
  }
  const manifest = await loadGitHubPublicationRepositoryManifest();
  await verifyPublicationHardeningSource(manifest);
  const invocation = invocationFromEnvironment(manifest);
  assertLocalPublicationSource(manifest, invocation);
  if (operation === "validate-source") {
    console.log(
      canonicalJson({
        repository: `${manifest.repository.owner}/${manifest.repository.name}`,
        schema: "publication.github-repository-hardening-source.current",
        sourceCommit: invocation.sourceCommit,
      }),
    );
    return;
  }
  if (operation !== "apply-and-retire") {
    throw new Error("--operation must be validate-source or apply-and-retire");
  }
  const api = new GitHubRestApi(requiredEnvironment(CREDENTIAL_SECRET));
  console.log(
    canonicalJson(
      await applyAndRetireGitHubPublicationRepository(manifest, api, invocation),
    ),
  );
}

if (import.meta.main) await main();
