import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import publicationManifestJson from "../PUBLICATION-HARDENING.json";
import {
  type GitHubApi,
  type GitHubPublicationRepositoryManifest,
  type GitHubResponse,
  GitHubRestApi,
  type HardeningInvocation,
  applyAndRetireGitHubPublicationRepository,
  canonicalJson,
  invocationFromEnvironment,
  validateGitHubPublicationRepositoryManifest,
  verifyPublicationHardeningSource,
} from "./publication-hardening";

const sourceCommit = "a".repeat(40);
const manifest = validateGitHubPublicationRepositoryManifest(publicationManifestJson);

function invocation(overrides: Partial<HardeningInvocation> = {}): HardeningInvocation {
  return {
    actor: manifest.repository.owner,
    actorId: manifest.repository.ownerId,
    confirmation: "",
    eventName: "public",
    ref: "refs/heads/main",
    repository: `${manifest.repository.owner}/${manifest.repository.name}`,
    repositoryId: manifest.repository.repositoryId,
    repositoryOwnerId: manifest.repository.ownerId,
    repositoryVisibility: "public",
    runAttempt: 1,
    sourceCommit,
    workflowRef: `${manifest.repository.owner}/${manifest.repository.name}/.github/workflows/post-public-hardening.yml@refs/heads/main`,
    workflowSha: sourceCommit,
    ...overrides,
  };
}

function environment(overrides: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    GITHUB_ACTOR: manifest.repository.owner,
    PUBLICATION_GITHUB_ACTOR_ID: String(manifest.repository.ownerId),
    GITHUB_EVENT_NAME: "public",
    GITHUB_REF: "refs/heads/main",
    GITHUB_REPOSITORY: `${manifest.repository.owner}/${manifest.repository.name}`,
    PUBLICATION_GITHUB_REPOSITORY_ID: String(manifest.repository.repositoryId),
    PUBLICATION_GITHUB_REPOSITORY_OWNER_ID: String(manifest.repository.ownerId),
    PUBLICATION_GITHUB_REPOSITORY_VISIBILITY: "public",
    GITHUB_RUN_ATTEMPT: "1",
    GITHUB_SHA: sourceCommit,
    GITHUB_WORKFLOW_REF: `${manifest.repository.owner}/${manifest.repository.name}/.github/workflows/post-public-hardening.yml@refs/heads/main`,
    PUBLICATION_GITHUB_WORKFLOW_SHA: sourceCommit,
    PUBLICATION_HARDENING_CONFIRMATION: "",
    ...overrides,
  };
}

function enabled(value: boolean) {
  return { enabled: value };
}

class FakeApi implements GitHubApi {
  actionsReady = false;
  automatedFixesReady = false;
  branchReady = false;
  calls: Array<{ body: unknown; method: string; path: string }> = [];
  checksReady = true;
  credentialPresent = true;
  authenticatedUserId = manifest.repository.ownerId;
  authenticatedUserLogin = manifest.repository.owner;
  metadataReady = false;
  privateReportingReady = false;
  protectionBody: Record<string, unknown> | null = null;
  securityReady = false;
  signaturesReady = false;
  topicsReady = false;
  topicLagReads = 0;
  vulnerabilityAlertsReady = false;
  workflowReady = false;
  hardeningWorkflowId = 987_654_321;
  hardeningWorkflowPath = ".github/workflows/post-public-hardening.yml";
  hardeningWorkflowState = "active";
  breakFinalTopics = false;
  breakFinalBypass = false;
  breakSecretDeletionProof = false;
  breakWorkflowRetirement = false;
  deployKeys: unknown[] = [];
  extraCollaborators: unknown[] = [];
  extraSecrets: string[] = [];
  invitations: unknown[] = [];
  rulesets: unknown[] = [];

  constructor(readonly policy: GitHubPublicationRepositoryManifest = manifest) {}

  private response<T>(status: number, value: T | null = null) {
    return { status, value } as GitHubResponse<T>;
  }

  private base() {
    return `/repos/${this.policy.repository.owner}/${this.policy.repository.name}`;
  }

  private repository() {
    const settings = this.policy.repository.settings;
    return {
      allow_merge_commit: this.metadataReady ? settings.allowMergeCommit : true,
      allow_rebase_merge: this.metadataReady ? settings.allowRebaseMerge : true,
      allow_squash_merge: this.metadataReady ? settings.allowSquashMerge : false,
      archived: false,
      default_branch: "main",
      delete_branch_on_merge: this.metadataReady ? settings.deleteBranchOnMerge : false,
      description: this.metadataReady ? this.policy.repository.description : null,
      disabled: false,
      fork: false,
      has_discussions: this.metadataReady ? settings.hasDiscussions : true,
      has_issues: this.metadataReady ? settings.hasIssues : false,
      has_projects: this.metadataReady ? settings.hasProjects : true,
      has_wiki: this.metadataReady ? settings.hasWiki : true,
      homepage: this.metadataReady ? this.policy.repository.homepage : null,
      id: this.policy.repository.repositoryId,
      name: this.policy.repository.name,
      owner: {
        id: this.policy.repository.ownerId,
        login: this.policy.repository.owner,
      },
      permissions: { admin: true },
      private: false,
      security_and_analysis: {
        advanced_security: {
          status: this.securityReady ? "enabled" : "disabled",
        },
        secret_scanning: {
          status: this.securityReady ? "enabled" : "disabled",
        },
        secret_scanning_push_protection: {
          status: this.securityReady ? "enabled" : "disabled",
        },
      },
      visibility: "public",
    };
  }

  private protection() {
    const body = this.protectionBody ?? {};
    const toggle = (name: string) => enabled(body[name] === true);
    const reviews = structuredClone(body.required_pull_request_reviews) as Record<
      string,
      unknown
    >;
    if (this.breakFinalBypass) {
      reviews.bypass_pull_request_allowances = {
        apps: [{ slug: "unexpected-app" }],
        teams: [],
        users: [],
      };
    }
    return {
      allow_deletions: toggle("allow_deletions"),
      allow_force_pushes: toggle("allow_force_pushes"),
      allow_fork_syncing: toggle("allow_fork_syncing"),
      block_creations: toggle("block_creations"),
      enforce_admins: toggle("enforce_admins"),
      lock_branch: toggle("lock_branch"),
      required_conversation_resolution: toggle("required_conversation_resolution"),
      required_linear_history: toggle("required_linear_history"),
      required_pull_request_reviews: reviews,
      required_status_checks: body.required_status_checks,
      restrictions: body.restrictions ?? null,
    };
  }

  async request<T>(
    method: "DELETE" | "GET" | "PATCH" | "POST" | "PUT",
    path: string,
    body?: unknown,
    _acceptedStatuses?: number[],
  ): Promise<GitHubResponse<T>> {
    this.calls.push({ body: structuredClone(body), method, path });
    const base = this.base();
    if (method === "GET" && path === "/user") {
      return this.response(200, {
        id: this.authenticatedUserId,
        login: this.authenticatedUserLogin,
        type: "User",
      }) as GitHubResponse<T>;
    }
    if (path === base) {
      if (method === "GET") {
        return this.response(200, this.repository()) as GitHubResponse<T>;
      }
      if (method === "PATCH") {
        const patch = body as Record<string, unknown>;
        const security = patch.security_and_analysis as Record<string, unknown>;
        if (Object.hasOwn(security, "dependency_graph")) {
          throw new Error("unsupported dependency_graph was sent");
        }
        this.metadataReady = true;
        this.securityReady = true;
        return this.response(200, this.repository()) as GitHubResponse<T>;
      }
    }
    if (method === "GET" && path === `${base}/git/ref/heads/main`) {
      return this.response(200, {
        object: { sha: sourceCommit, type: "commit" },
      }) as GitHubResponse<T>;
    }
    if (
      method === "GET" &&
      path ===
        `${base}/commits/${sourceCommit}/check-runs?filter=latest&per_page=100&page=1`
    ) {
      const check_runs = this.policy.branchProtection.requiredStatusChecks.map(
        ({ appId, context }, index) => ({
          app: { id: appId },
          conclusion: this.checksReady || index > 0 ? "success" : "failure",
          head_sha: sourceCommit,
          name: context,
          status: "completed",
        }),
      );
      return this.response(200, {
        check_runs,
        total_count: check_runs.length,
      }) as GitHubResponse<T>;
    }
    if (method === "GET" && path === `${base}/actions/secrets?per_page=100&page=1`) {
      const secrets = this.credentialPresent
        ? [
            { name: this.policy.credential.secretName },
            ...this.extraSecrets.map((name) => ({ name })),
          ]
        : this.extraSecrets.map((name) => ({ name }));
      return this.response(200, {
        secrets,
        total_count: secrets.length,
      }) as GitHubResponse<T>;
    }
    if (
      method === "GET" &&
      path === `${base}/collaborators?affiliation=all&per_page=100&page=1`
    ) {
      return this.response(200, [
        {
          id: this.policy.repository.ownerId,
          login: this.policy.repository.owner,
          permissions: { admin: true },
          role_name: "admin",
        },
        ...this.extraCollaborators,
      ]) as GitHubResponse<T>;
    }
    if (method === "GET" && path === `${base}/keys?per_page=100&page=1`) {
      return this.response(200, this.deployKeys) as GitHubResponse<T>;
    }
    if (method === "GET" && path === `${base}/invitations?per_page=100&page=1`) {
      return this.response(200, this.invitations) as GitHubResponse<T>;
    }
    if (method === "GET" && path === `${base}/rulesets?per_page=100&page=1`) {
      return this.response(200, this.rulesets) as GitHubResponse<T>;
    }
    if (method === "GET" && path === `${base}/actions/workflows?per_page=100&page=1`) {
      return this.response(200, {
        total_count: 1,
        workflows: [
          {
            id: this.hardeningWorkflowId,
            path: this.hardeningWorkflowPath,
            state: this.hardeningWorkflowState,
          },
        ],
      }) as GitHubResponse<T>;
    }
    if (path === `${base}/actions/workflows/${this.hardeningWorkflowId}/disable`) {
      if (method !== "PUT") throw new Error("Unexpected workflow retirement method");
      if (!this.breakWorkflowRetirement) {
        this.hardeningWorkflowState = "disabled_manually";
      }
      return this.response(204) as GitHubResponse<T>;
    }
    if (
      method === "GET" &&
      path === `${base}/actions/workflows/${this.hardeningWorkflowId}`
    ) {
      return this.response(200, {
        id: this.hardeningWorkflowId,
        path: this.hardeningWorkflowPath,
        state: this.hardeningWorkflowState,
      }) as GitHubResponse<T>;
    }
    if (path === `${base}/topics`) {
      if (method === "PUT") {
        this.topicsReady = true;
        return this.response(200, body) as GitHubResponse<T>;
      }
      return this.response(200, {
        names:
          this.topicsReady && !this.breakFinalTopics && this.topicLagReads-- <= 0
            ? this.policy.repository.topics
            : [],
      }) as GitHubResponse<T>;
    }
    if (path === `${base}/actions/permissions`) {
      if (method === "PUT") {
        this.actionsReady = true;
        return this.response(204) as GitHubResponse<T>;
      }
      return this.response(200, {
        allowed_actions: this.actionsReady ? "selected" : "all",
        enabled: true,
        sha_pinning_required: this.actionsReady,
      }) as GitHubResponse<T>;
    }
    if (path === `${base}/actions/permissions/selected-actions`) {
      if (method === "PUT") return this.response(204) as GitHubResponse<T>;
      if (!this.actionsReady) return this.response(409) as GitHubResponse<T>;
      return this.response(200, {
        github_owned_allowed: false,
        patterns_allowed: this.policy.actions.patternsAllowed,
        verified_allowed: false,
      }) as GitHubResponse<T>;
    }
    if (path === `${base}/actions/permissions/workflow`) {
      if (method === "PUT") {
        this.workflowReady = true;
        return this.response(204) as GitHubResponse<T>;
      }
      return this.response(200, {
        can_approve_pull_request_reviews: false,
        default_workflow_permissions: this.workflowReady ? "read" : "write",
      }) as GitHubResponse<T>;
    }
    if (path === `${base}/branches/main/protection`) {
      if (method === "PUT") {
        this.branchReady = true;
        this.protectionBody = structuredClone(body) as Record<string, unknown>;
        return this.response(200, this.protection()) as GitHubResponse<T>;
      }
      return this.branchReady
        ? (this.response(200, this.protection()) as GitHubResponse<T>)
        : (this.response(404) as GitHubResponse<T>);
    }
    if (path === `${base}/branches/main/protection/required_signatures`) {
      if (method === "POST") {
        this.signaturesReady = true;
        return this.response(200, { enabled: true }) as GitHubResponse<T>;
      }
      return this.signaturesReady
        ? (this.response(200, { enabled: true }) as GitHubResponse<T>)
        : (this.response(404) as GitHubResponse<T>);
    }
    if (path === `${base}/vulnerability-alerts`) {
      if (method === "PUT") {
        this.vulnerabilityAlertsReady = true;
        return this.response(204) as GitHubResponse<T>;
      }
      return this.response(
        this.vulnerabilityAlertsReady ? 204 : 404,
      ) as GitHubResponse<T>;
    }
    if (path === `${base}/automated-security-fixes`) {
      if (method === "PUT") {
        this.automatedFixesReady = true;
        return this.response(204) as GitHubResponse<T>;
      }
      return this.automatedFixesReady
        ? (this.response(200, {
            enabled: true,
            paused: false,
          }) as GitHubResponse<T>)
        : (this.response(404) as GitHubResponse<T>);
    }
    if (path === `${base}/private-vulnerability-reporting`) {
      if (method === "PUT") {
        this.privateReportingReady = true;
        return this.response(204) as GitHubResponse<T>;
      }
      return this.response(200, {
        enabled: this.privateReportingReady,
      }) as GitHubResponse<T>;
    }
    if (
      method === "DELETE" &&
      path === `${base}/actions/secrets/${this.policy.credential.secretName}`
    ) {
      if (!this.breakSecretDeletionProof) this.credentialPresent = false;
      return this.response(204) as GitHubResponse<T>;
    }
    throw new Error(`Unexpected fake API call: ${method} ${path}`);
  }
}

describe("GitHub publication repository hardening", () => {
  test("validates the current reusable manifest and exact source workflow", async () => {
    expect(
      validateGitHubPublicationRepositoryManifest(publicationManifestJson),
    ).toEqual(manifest);
    const source = await verifyPublicationHardeningSource(manifest);
    expect(source.requiredChecks.map(({ context }) => context)).toEqual([
      "CI / Build, test, and inspect packages",
      "Secret Scan / Gitleaks 8.30.1 exact-tree scan",
    ]);
    const workflow = await readFile(
      ".github/workflows/post-public-hardening.yml",
      "utf8",
    );
    const reference = "${{ secrets.PUBLICATION_HARDENING_TOKEN }}";
    expect(workflow.split(reference).length - 1).toBe(1);
    expect(workflow).toContain(
      `      - name: Apply, audit, and retire publication authority\n        env:\n          PUBLICATION_HARDENING_TOKEN: ${reference}\n        run: >-`,
    );
  });

  test("binds automatic and manual invocations to owner, repository, main and first attempt", () => {
    expect(invocationFromEnvironment(manifest, environment())).toEqual(invocation());
    expect(
      invocationFromEnvironment(
        manifest,
        environment({
          GITHUB_EVENT_NAME: "workflow_dispatch",
          PUBLICATION_HARDENING_CONFIRMATION: "harden-public-repository",
        }),
      ).eventName,
    ).toBe("workflow_dispatch");
    const invalidInvocations: Array<Record<string, string>> = [
      { PUBLICATION_GITHUB_ACTOR_ID: "9" },
      { PUBLICATION_GITHUB_REPOSITORY_ID: "9" },
      { PUBLICATION_GITHUB_REPOSITORY_VISIBILITY: "private" },
      { GITHUB_RUN_ATTEMPT: "2" },
      { PUBLICATION_GITHUB_WORKFLOW_SHA: "b".repeat(40) },
    ];
    for (const overrides of invalidInvocations) {
      expect(() =>
        invocationFromEnvironment(manifest, environment(overrides)),
      ).toThrow();
    }
  });

  test("applies every target, audits it, removes the secret, and disables itself", async () => {
    const api = new FakeApi();
    const evidence = await applyAndRetireGitHubPublicationRepository(
      manifest,
      api,
      invocation(),
      { auditDelayMs: 0 },
    );
    expect(evidence.targetReady).toBe(true);
    expect(evidence.repositorySecretRemoved).toBe(true);
    expect(evidence.workflowRetired).toBe(true);
    expect(api.credentialPresent).toBe(false);
    expect(api.hardeningWorkflowState).toBe("disabled_manually");
    expect(api.calls.slice(-4)).toEqual([
      {
        body: undefined,
        method: "DELETE",
        path: `/repos/${manifest.repository.owner}/${manifest.repository.name}/actions/secrets/PUBLICATION_HARDENING_TOKEN`,
      },
      {
        body: undefined,
        method: "GET",
        path: `/repos/${manifest.repository.owner}/${manifest.repository.name}/actions/secrets?per_page=100&page=1`,
      },
      {
        body: undefined,
        method: "PUT",
        path: `/repos/${manifest.repository.owner}/${manifest.repository.name}/actions/workflows/${api.hardeningWorkflowId}/disable`,
      },
      {
        body: undefined,
        method: "GET",
        path: `/repos/${manifest.repository.owner}/${manifest.repository.name}/actions/workflows/${api.hardeningWorkflowId}`,
      },
    ]);
    const patch = api.calls.find(
      (call) =>
        call.method === "PATCH" &&
        call.path === `/repos/${manifest.repository.owner}/${manifest.repository.name}`,
    );
    expect(
      Object.hasOwn(
        (patch?.body as Record<string, Record<string, unknown>>).security_and_analysis,
        "dependency_graph",
      ),
    ).toBe(false);
    expect(
      Object.hasOwn(
        api.protectionBody?.required_pull_request_reviews as Record<string, unknown>,
        "bypass_pull_request_allowances",
      ),
    ).toBe(false);
    expect(
      api.calls
        .filter((call) => call.method !== "GET")
        .map(({ method, path }) => `${method} ${path}`),
    ).toEqual([
      `PATCH /repos/${manifest.repository.owner}/${manifest.repository.name}`,
      `PUT /repos/${manifest.repository.owner}/${manifest.repository.name}/topics`,
      `PUT /repos/${manifest.repository.owner}/${manifest.repository.name}/actions/permissions`,
      `PUT /repos/${manifest.repository.owner}/${manifest.repository.name}/actions/permissions/selected-actions`,
      `PUT /repos/${manifest.repository.owner}/${manifest.repository.name}/actions/permissions/workflow`,
      `PUT /repos/${manifest.repository.owner}/${manifest.repository.name}/branches/main/protection`,
      `POST /repos/${manifest.repository.owner}/${manifest.repository.name}/branches/main/protection/required_signatures`,
      `PUT /repos/${manifest.repository.owner}/${manifest.repository.name}/vulnerability-alerts`,
      `PUT /repos/${manifest.repository.owner}/${manifest.repository.name}/automated-security-fixes`,
      `PUT /repos/${manifest.repository.owner}/${manifest.repository.name}/private-vulnerability-reporting`,
      `DELETE /repos/${manifest.repository.owner}/${manifest.repository.name}/actions/secrets/PUBLICATION_HARDENING_TOKEN`,
      `PUT /repos/${manifest.repository.owner}/${manifest.repository.name}/actions/workflows/${api.hardeningWorkflowId}/disable`,
    ]);
  });

  test("does not mutate when a required source check is not successful", async () => {
    const api = new FakeApi();
    api.checksReady = false;
    await expect(
      applyAndRetireGitHubPublicationRepository(manifest, api, invocation()),
    ).rejects.toThrow(
      "required_check_not_successful:CI / Build, test, and inspect packages",
    );
    expect(api.calls.some((call) => call.method !== "GET")).toBe(false);
    expect(api.credentialPresent).toBe(true);
  });

  test("does not mutate without the exact active workflow retirement target", async () => {
    for (const configure of [
      (api: FakeApi) => {
        api.hardeningWorkflowPath = ".github/workflows/unexpected.yml";
      },
      (api: FakeApi) => {
        api.hardeningWorkflowState = "disabled_manually";
      },
    ]) {
      const api = new FakeApi();
      configure(api);
      await expect(
        applyAndRetireGitHubPublicationRepository(manifest, api, invocation()),
      ).rejects.toThrow("hardening_workflow_not_active");
      expect(api.calls.some((call) => call.method !== "GET")).toBe(false);
      expect(api.credentialPresent).toBe(true);
    }
  });

  test("refuses unexpected collaborators, invitations, deploy keys, or rulesets before mutation", async () => {
    for (const configure of [
      (api: FakeApi) => {
        api.extraCollaborators = [
          {
            id: 9,
            login: "unexpected-writer",
            permissions: { push: true },
            role_name: "write",
          },
        ];
      },
      (api: FakeApi) => {
        api.deployKeys = [{ id: 9, read_only: false, title: "unexpected" }];
      },
      (api: FakeApi) => {
        api.invitations = [{ id: 9, permissions: "write" }];
      },
      (api: FakeApi) => {
        api.rulesets = [{ id: 9, name: "unexpected" }];
      },
    ]) {
      const api = new FakeApi();
      configure(api);
      await expect(
        applyAndRetireGitHubPublicationRepository(manifest, api, invocation()),
      ).rejects.toThrow(
        /repository_(collaborator_inventory|collaborator_invitations|deploy_keys|rulesets)/,
      );
      expect(api.calls.some((call) => call.method !== "GET")).toBe(false);
      expect(api.credentialPresent).toBe(true);
    }
  });

  test("refuses a non-owner token or any additional repository secret before mutation", async () => {
    for (const configure of [
      (api: FakeApi) => {
        api.authenticatedUserId = 9;
        api.authenticatedUserLogin = "not-the-owner";
      },
      (api: FakeApi) => {
        api.extraSecrets = ["UNEXPECTED_SECRET"];
      },
    ]) {
      const api = new FakeApi();
      configure(api);
      await expect(
        applyAndRetireGitHubPublicationRepository(manifest, api, invocation()),
      ).rejects.toThrow();
      expect(api.calls.some((call) => call.method !== "GET")).toBe(false);
      expect(api.credentialPresent).toBe(true);
    }
  });

  test("retains the one-time secret when the exact post-apply audit fails", async () => {
    const api = new FakeApi();
    api.breakFinalTopics = true;
    await expect(
      applyAndRetireGitHubPublicationRepository(manifest, api, invocation(), {
        auditAttempts: 2,
        auditDelayMs: 0,
      }),
    ).rejects.toThrow("repository_topics");
    expect(api.credentialPresent).toBe(true);
    expect(api.calls.some((call) => call.method === "DELETE")).toBe(false);
  });

  test("rejects a post-apply branch-protection bypass allowance", async () => {
    const api = new FakeApi();
    api.breakFinalBypass = true;
    await expect(
      applyAndRetireGitHubPublicationRepository(manifest, api, invocation(), {
        auditAttempts: 1,
        auditDelayMs: 0,
      }),
    ).rejects.toThrow("branch_protection");
    expect(api.credentialPresent).toBe(true);
    expect(api.hardeningWorkflowState).toBe("active");
  });

  test("re-audits eventual consistency without repeating mutations", async () => {
    const api = new FakeApi();
    api.topicLagReads = 1;
    await applyAndRetireGitHubPublicationRepository(manifest, api, invocation(), {
      auditAttempts: 3,
      auditDelayMs: 0,
    });
    expect(
      api.calls.filter(
        (call) =>
          call.method === "PATCH" &&
          call.path ===
            `/repos/${manifest.repository.owner}/${manifest.repository.name}`,
      ),
    ).toHaveLength(1);
    expect(api.credentialPresent).toBe(false);
  });

  test("fails closed without retirement evidence when workflow disablement is not observed", async () => {
    const api = new FakeApi();
    api.breakWorkflowRetirement = true;
    await expect(
      applyAndRetireGitHubPublicationRepository(manifest, api, invocation(), {
        auditDelayMs: 0,
      }),
    ).rejects.toThrow("Hardening workflow is not disabled_manually");
    expect(api.credentialPresent).toBe(false);
    expect(api.hardeningWorkflowState).toBe("active");
    expect(api.calls.at(-1)).toMatchObject({
      method: "GET",
      path: `/repos/${manifest.repository.owner}/${manifest.repository.name}/actions/workflows/${api.hardeningWorkflowId}`,
    });
  });

  test("does not disable the workflow unless the repository secret is proven absent", async () => {
    const api = new FakeApi();
    api.breakSecretDeletionProof = true;
    await expect(
      applyAndRetireGitHubPublicationRepository(manifest, api, invocation(), {
        auditDelayMs: 0,
      }),
    ).rejects.toThrow("Temporary repository secret was not removed exactly");
    expect(api.credentialPresent).toBe(true);
    expect(api.hardeningWorkflowState).toBe("active");
    expect(
      api.calls.some(
        ({ method, path }) =>
          method === "PUT" && path.endsWith("/actions/workflows/987654321/disable"),
      ),
    ).toBe(false);
  });

  test("accepts the existing owner token without constraining its GitHub token class", async () => {
    const token = "existing-owner-token";
    const calls: Array<{
      body: string;
      headers: Headers;
      method: string;
      url: string;
    }> = [];
    const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
      calls.push({
        body: String(init?.body ?? ""),
        headers: new Headers(init?.headers),
        method: init?.method ?? "GET",
        url: String(input),
      });
      return Response.json({ id: manifest.repository.ownerId }, { status: 200 });
    }) as typeof fetch;
    const api = new GitHubRestApi(token, "https://api.github.com", fetchImpl);
    await api.request("GET", "/user");

    expect(calls.map(({ method, url }) => [method, new URL(url).pathname])).toEqual([
      ["GET", "/user"],
    ]);
    expect(calls[0]?.headers.get("authorization")).toBe(`Bearer ${token}`);
    expect(calls[0]?.headers.get("x-github-api-version")).toBe("2022-11-28");
    expect(() => new GitHubRestApi(" ")).toThrow("Missing PUBLICATION_HARDENING_TOKEN");
  });

  test("rejects manifest weakening and extra fields", () => {
    for (const candidate of [
      {
        ...publicationManifestJson,
        credential: { secretName: "SOME_TOKEN" },
      },
      {
        ...publicationManifestJson,
        security: {
          ...publicationManifestJson.security,
          secretScanning: false,
        },
      },
      {
        ...publicationManifestJson,
        branchProtection: {
          ...publicationManifestJson.branchProtection,
          requiredApprovingReviewCount: 1,
        },
      },
      { ...publicationManifestJson, unexpectedField: true },
    ]) {
      expect(() => validateGitHubPublicationRepositoryManifest(candidate)).toThrow();
    }
    expect(canonicalJson(manifest)).not.toContain("unexpectedField");
  });

  test("keeps the standalone hardener free of controller and provider identifiers", async () => {
    const paths = [
      "PUBLICATION-HARDENING.json",
      ".github/workflows/post-public-hardening.yml",
      "docs/publication-hardening.md",
      "scripts/publication-hardening.ts",
    ];
    const source = (
      await Promise.all(paths.map((path) => readFile(path, "utf8")))
    ).join("\n");
    expect(source).not.toContain("/credentials/revoke");
    expect(source).not.toContain("github_pat_");
    for (const forbidden of [
      String.fromCodePoint(104, 117, 107, 117, 107, 99, 97),
      String.fromCodePoint(104, 117, 107, 117, 107, 231, 97),
      ["CLOUD", "FLARE"].join(""),
      ["G", "CS_"].join(""),
      ["GOO", "GLE_"].join(""),
      ["VER", "CEL"].join(""),
    ]) {
      expect(source.toLocaleLowerCase("en")).not.toContain(
        forbidden.toLocaleLowerCase("en"),
      );
    }
  });
});
