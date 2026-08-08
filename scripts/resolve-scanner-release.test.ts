import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const resolver = resolve(import.meta.dir, "resolve-scanner-release.sh");
const workflowPaths = ["ci.yml", "post-public-hardening.yml", "secret-scan.yml"].map(
  (name) => resolve(root, ".github", "workflows", name),
);

const releases = [
  {
    arch: "X64",
    output:
      "gitleaks_8.30.1_linux_x64.tar.gz\t551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb\n",
  },
  {
    arch: "ARM64",
    output:
      "gitleaks_8.30.1_linux_arm64.tar.gz\te4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080\n",
  },
] as const;

describe("CI scanner release selection", () => {
  for (const release of releases) {
    test(`selects Gitleaks for ${release.arch}`, () => {
      const result = runResolver("gitleaks", release.arch);
      expect(result.exitCode).toBe(0);
      expect(result.stderr).toBe("");
      expect(result.stdout).toBe(release.output);
    });
  }

  test("fails closed when RUNNER_ARCH is unset or unsupported", () => {
    for (const arch of [undefined, "", "ARM", "X86", "arm64"]) {
      const result = runResolver("gitleaks", arch);
      expect(result.exitCode).toBe(64);
      expect(result.stdout).toBe("");
      expect(result.stderr).toContain("Unsupported scanner or RUNNER_ARCH");
    }
  });

  test("fails closed for an unknown scanner", () => {
    const result = runResolver("unknown", "ARM64");
    expect(result.exitCode).toBe(64);
    expect(result.stdout).toBe("");
  });

  test("uses only the fixed reviewed hosted runner", async () => {
    const sources = await Promise.all(
      workflowPaths.map((path) => readFile(path, "utf8")),
    );
    const runnerLines = sources
      .join("\n")
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.startsWith("runs-on:"));
    expect(runnerLines).toEqual([
      "runs-on: ubuntu-24.04",
      "runs-on: ubuntu-24.04",
      "runs-on: ubuntu-24.04",
      "runs-on: ubuntu-24.04",
    ]);
    const secretScan = sources.at(-1) ?? "";
    expect(secretScan.match(/resolve-scanner-release[.]sh/g)?.length).toBe(1);
    expect(sources.join("\n")).not.toContain("CI_RUNNER_LABEL");
    expect(secretScan).not.toContain("linux_x64.tar.gz");
  });
});

function runResolver(scanner: string, arch: string | undefined) {
  const env = { ...process.env };
  env.RUNNER_ARCH = arch;
  const result = Bun.spawnSync(["bash", resolver, scanner], {
    cwd: root,
    env,
    stderr: "pipe",
    stdout: "pipe",
  });
  return {
    exitCode: result.exitCode,
    stderr: new TextDecoder().decode(result.stderr),
    stdout: new TextDecoder().decode(result.stdout),
  };
}
