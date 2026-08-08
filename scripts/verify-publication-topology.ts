#!/usr/bin/env bun

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const manifestPath = "PUBLICATION-PROVENANCE.json";
const expectedContract = {
  history: { expectedRootCount: 1, mode: "parentless-standalone" },
  repository: {
    id: "qualified-opinion-protocol",
    releaseBoundary: "current-v3-only",
  },
  rootPackage: {
    name: "qualified-opinion-protocol-v3-workspace",
    private: true,
    version: "3.0.0",
    workspaces: ["packages/*"],
  },
  repositoryControls: {
    hardeningManifest: "PUBLICATION-HARDENING.json",
    hardeningSource: "scripts/publication-hardening.ts",
    mode: "repository-local-product-neutral-current",
    workflow: ".github/workflows/post-public-hardening.yml",
  },
  schema: "standalone-publication-provenance-current",
  sourceTree: {
    algorithm: "sha256-path-length-content-current",
    excludes: [manifestPath],
    sha256: "",
  },
  upstream: {
    adaptation: "country-agnostic-qualified-opinion-current-v3",
    dependencySourcePaths: [
      "packages/domain/src/email-verification.ts",
      "packages/domain/src/google-confidential-space.ts",
      "packages/transparency-monitor/src/eligibility-directory-witness.ts",
      "packages/transparency-monitor/src/witness-status.ts",
    ],
    objectFormat: "sha1",
    reviewedBaselineSourceSha256:
      "0a67b76c76098e46455fc8ba916377c1dcc8b877c32972139de12708c70c0b32",
    revision: "6277f328d8c8b539d21eae6e64471078acae7bbd",
    sourcePaths: ["packages/proof", "packages/proof-verifier"],
  },
  topology: {
    forbiddenPathPrefixes: ["apps", "infrastructure", "packages/db", "packages/domain"],
    requiredPaths: [
      ".github/workflows/ci.yml",
      ".github/workflows/post-public-hardening.yml",
      ".github/workflows/secret-scan.yml",
      ".gitleaks.toml",
      "LICENSE",
      "PUBLICATION-HARDENING.json",
      "README.md",
      "docs/protocol.md",
      "docs/publication-hardening.md",
      "package.json",
      "packages/protocol/package.json",
      "packages/verifier/package.json",
      "scripts/check-boundaries.ts",
      "scripts/publication-hardening.test.ts",
      "scripts/publication-hardening.ts",
      "scripts/run-gitleaks.ts",
      "scripts/resolve-scanner-release.sh",
      "scripts/resolve-scanner-release.test.ts",
      "scripts/verify-publication-topology.ts",
      "vectors/v3/canonicalization.json",
    ],
    topLevelPaths: [
      ".github",
      ".gitignore",
      ".gitleaks.toml",
      ".npmrc",
      "CODE_OF_CONDUCT.md",
      "CONTRIBUTING.md",
      "LICENSE",
      "NOTICE",
      "PUBLICATION-HARDENING.json",
      manifestPath,
      "README.md",
      "SECURITY.md",
      "biome.json",
      "bun.lock",
      "docs",
      "package.json",
      "packages",
      "scripts",
      "tsconfig.json",
      "vectors",
    ],
    workspacePackages: [
      {
        name: "@qualified-opinion/protocol",
        path: "packages/protocol",
        private: false,
        version: "3.0.0",
      },
      {
        name: "@qualified-opinion/verifier",
        path: "packages/verifier",
        private: false,
        version: "3.0.0",
      },
    ],
  },
} as const;

function git(arguments_: string[]): Buffer {
  return execFileSync("git", ["--no-replace-objects", "-C", root, ...arguments_], {
    encoding: "buffer",
    maxBuffer: 64 * 1024 * 1024,
    timeout: 30_000,
  });
}

function compareText(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left), Buffer.from(right));
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(
      ([left], [right]) => compareText(left, right),
    );
    return `{${entries
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonical(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function safePath(path: string): void {
  if (
    path === "" ||
    path.startsWith("/") ||
    path.includes("\\") ||
    path !== path.normalize("NFC") ||
    path.split("/").some((part) => !part || part === "." || part === "..") ||
    [...path].some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint < 0x20 || codePoint === 0x7f;
    })
  ) {
    throw new Error(`Unsafe repository path: ${JSON.stringify(path)}`);
  }
}

async function exactSourcePaths(): Promise<string[]> {
  const output = git(["ls-files", "--cached", "--others", "--exclude-standard", "-z"]);
  const paths: string[] = [];
  let start = 0;
  for (let index = 0; index < output.length; index += 1) {
    if (output[index] !== 0) continue;
    const raw = output.subarray(start, index);
    start = index + 1;
    if (raw.length === 0) continue;
    const path = raw.toString("utf8");
    if (!Buffer.from(path).equals(raw)) {
      throw new Error("Repository path is not valid UTF-8");
    }
    safePath(path);
    const stats = await lstat(resolve(root, path)).catch(
      (error: NodeJS.ErrnoException) => {
        if (error.code === "ENOENT") return undefined;
        throw error;
      },
    );
    if (!stats) continue;
    if (!stats.isFile() || stats.isSymbolicLink()) {
      throw new Error(`Source entry is not a regular file: ${path}`);
    }
    paths.push(path);
  }
  if (start !== output.length) throw new Error("Unterminated Git path list");
  paths.sort(compareText);
  if (new Set(paths).size !== paths.length) {
    throw new Error("Duplicate source paths are not allowed");
  }
  return paths;
}

async function sourceSha256(paths: readonly string[]): Promise<string> {
  const hash = createHash("sha256");
  hash.update("standalone-publication-source-tree-current\0");
  for (const path of paths) {
    if (path === manifestPath) continue;
    const content = await readFile(resolve(root, path));
    hash.update(JSON.stringify({ bytes: content.byteLength, path }));
    hash.update("\0");
    hash.update(content);
    hash.update("\0");
  }
  return hash.digest("hex");
}

function historyRootCount(): number {
  const head = git(["rev-parse", "HEAD^{commit}"]).toString("utf8").trim();
  const pending = [head];
  const visited = new Set<string>();
  const roots = new Set<string>();
  while (pending.length > 0) {
    const commit = pending.pop();
    if (!commit || visited.has(commit)) continue;
    if (!/^[a-f0-9]{40,64}$/u.test(commit)) {
      throw new Error("Invalid commit identifier in history");
    }
    visited.add(commit);
    if (visited.size > 100_000) throw new Error("History exceeds verifier bound");
    const object = git(["cat-file", "-p", commit]).toString("utf8");
    const header = object.split("\n\n", 1)[0] ?? "";
    const parents = header
      .split("\n")
      .filter((line) => line.startsWith("parent "))
      .map((line) => line.slice("parent ".length));
    if (parents.length === 0) roots.add(commit);
    else pending.push(...parents);
  }
  return roots.size;
}

async function manifest(): Promise<Record<string, unknown>> {
  const parsed: unknown = JSON.parse(
    await readFile(resolve(root, manifestPath), "utf8"),
  );
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${manifestPath} must be an object`);
  }
  return parsed as Record<string, unknown>;
}

async function packageIdentity(path: string) {
  const value = JSON.parse(
    await readFile(resolve(root, path, "package.json"), "utf8"),
  ) as Record<string, unknown>;
  return {
    name: value.name,
    path,
    private: value.private === true,
    version: value.version,
  };
}

async function verify(printDigest: boolean): Promise<void> {
  const actualRoot = resolve(
    git(["rev-parse", "--show-toplevel"]).toString("utf8").trim(),
  );
  if (actualRoot !== root) throw new Error("Unexpected Git repository root");

  const provenance = await manifest();
  const sourceTree = provenance.sourceTree;
  if (!sourceTree || typeof sourceTree !== "object" || Array.isArray(sourceTree)) {
    throw new Error("sourceTree must be an object");
  }
  const declaredDigest = (sourceTree as Record<string, unknown>).sha256;
  if (typeof declaredDigest !== "string" || !/^[a-f0-9]{64}$/u.test(declaredDigest)) {
    throw new Error("sourceTree.sha256 must be a SHA-256 digest");
  }
  (sourceTree as Record<string, unknown>).sha256 = "";
  if (canonical(provenance) !== canonical(expectedContract)) {
    throw new Error(
      "Publication provenance contract differs from the reviewed topology",
    );
  }

  const paths = await exactSourcePaths();
  const digest = await sourceSha256(paths);
  if (printDigest) {
    console.log(digest);
    return;
  }
  if (digest !== declaredDigest) {
    throw new Error(`Exact source digest ${digest} is not the reviewed digest`);
  }
  if (historyRootCount() !== 1) {
    throw new Error("History is not derived from exactly one parentless root");
  }

  const pathSet = new Set(paths);
  for (const path of expectedContract.topology.requiredPaths) {
    if (!pathSet.has(path)) throw new Error(`Required path is missing: ${path}`);
  }
  for (const prefix of expectedContract.topology.forbiddenPathPrefixes) {
    const violation = paths.find(
      (path) => path === prefix || path.startsWith(`${prefix}/`),
    );
    if (violation) throw new Error(`Forbidden topology path: ${violation}`);
  }
  const topLevelPaths = [...new Set(paths.map((path) => path.split("/")[0] ?? ""))]
    .filter(Boolean)
    .sort(compareText);
  if (canonical(topLevelPaths) !== canonical(expectedContract.topology.topLevelPaths)) {
    throw new Error("Top-level source topology differs from the reviewed topology");
  }

  const rootPackage = JSON.parse(
    await readFile(resolve(root, "package.json"), "utf8"),
  ) as Record<string, unknown>;
  const rootIdentity = {
    name: rootPackage.name,
    private: rootPackage.private === true,
    version: rootPackage.version,
    workspaces: rootPackage.workspaces ?? [],
  };
  if (canonical(rootIdentity) !== canonical(expectedContract.rootPackage)) {
    throw new Error("Root package identity differs from the reviewed topology");
  }
  const workspacePaths = paths
    .filter((path) => /^packages\/[^/]+\/package[.]json$/u.test(path))
    .map((path) => path.slice(0, -"/package.json".length))
    .sort(compareText);
  const expectedWorkspacePaths = expectedContract.topology.workspacePackages.map(
    ({ path }) => path,
  );
  if (canonical(workspacePaths) !== canonical(expectedWorkspacePaths)) {
    throw new Error("Workspace package paths differ from the reviewed topology");
  }
  const identities = await Promise.all(workspacePaths.map(packageIdentity));
  if (
    canonical(identities) !== canonical(expectedContract.topology.workspacePackages)
  ) {
    throw new Error("Workspace package identities differ from the reviewed topology");
  }
  console.log(
    `Verified standalone provenance, one history root, and ${paths.length} exact source paths (${digest}).`,
  );
}

const arguments_ = process.argv.slice(2);
if (
  arguments_.length > 1 ||
  (arguments_.length === 1 && arguments_[0] !== "--print-source-sha256")
) {
  throw new Error("Usage: verify-publication-topology.ts [--print-source-sha256]");
}
await verify(arguments_[0] === "--print-source-sha256");
