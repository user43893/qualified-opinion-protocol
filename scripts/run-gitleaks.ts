import {
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";

const requiredVersion = "8.30.1";
const decoder = new TextDecoder();

function output(result: Bun.SyncSubprocess) {
  return {
    stderr: decoder.decode(result.stderr),
    stdout: decoder.decode(result.stdout),
  };
}

function checked(command: string[], cwd: string): string {
  const result = Bun.spawnSync(command, { cwd, stderr: "pipe", stdout: "pipe" });
  const captured = output(result);
  if (result.exitCode !== 0) {
    throw new Error(
      `${command.join(" ")} failed with exit code ${result.exitCode}\n${captured.stderr}${captured.stdout}`,
    );
  }
  return captured.stdout;
}

const repositoryRoot = resolve(
  checked(["git", "rev-parse", "--show-toplevel"], process.cwd()).trim(),
);
const binary = process.env.QUALIFIED_OPINION_GITLEAKS_BIN?.trim() || "gitleaks";
const versionResult = Bun.spawnSync([binary, "version"], {
  cwd: repositoryRoot,
  stderr: "pipe",
  stdout: "pipe",
});
if (
  versionResult.exitCode !== 0 ||
  output(versionResult).stdout.trim() !== requiredVersion
) {
  throw new Error(`Gitleaks ${requiredVersion} is required for the release gate.`);
}

const temporaryRoot = await mkdtemp(join(tmpdir(), "qualified-opinion-gitleaks-"));
const snapshot = join(temporaryRoot, "source");
const selfTest = join(temporaryRoot, "self-test");

try {
  await mkdir(snapshot);
  await mkdir(selfTest);
  await writeFile(
    join(selfTest, "must-be-detected.txt"),
    ['api_key="', "xY7pQ2mN9vK4cR8tL3wF6sH1", "jD5bG0zA", '"\n'].join(""),
  );
  const common = [
    "dir",
    "--no-banner",
    "--redact",
    "--config",
    join(repositoryRoot, ".gitleaks.toml"),
  ];
  const selfTestResult = Bun.spawnSync([binary, ...common, selfTest], {
    cwd: repositoryRoot,
    stderr: "ignore",
    stdout: "ignore",
  });
  if (selfTestResult.exitCode !== 1) {
    throw new Error(
      `Gitleaks detector self-test returned ${selfTestResult.exitCode}; expected 1.`,
    );
  }

  const paths = checked(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
    repositoryRoot,
  )
    .split("\0")
    .filter(Boolean);
  let copied = 0;
  for (const path of paths) {
    if (isAbsolute(path) || path.includes("\\") || path.split("/").includes("..")) {
      throw new Error(`Unsafe repository path: ${path}`);
    }
    const source = join(repositoryRoot, path);
    const stats = await lstat(source).catch((error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") return undefined;
      throw error;
    });
    if (!stats) continue;
    if (!stats.isFile() || stats.isSymbolicLink()) {
      throw new Error(`Exact source entry is not a regular file: ${path}`);
    }
    const destination = join(snapshot, path);
    await mkdir(dirname(destination), { recursive: true });
    await copyFile(source, destination);
    copied += 1;
  }
  if (copied === 0) throw new Error("Exact source tree is empty");

  const scan = Bun.spawnSync([binary, ...common, snapshot], {
    cwd: repositoryRoot,
    stderr: "pipe",
    stdout: "pipe",
  });
  const scanOutput = output(scan);
  process.stdout.write(scanOutput.stdout);
  process.stderr.write(scanOutput.stderr);
  if (scan.exitCode !== 0) process.exitCode = scan.exitCode;
  else console.log(`Gitleaks ${requiredVersion} scanned ${copied} exact source files.`);
} finally {
  await rm(temporaryRoot, { force: true, recursive: true });
}
