import { readFile, readdir } from "node:fs/promises";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = fileURLToPath(new URL("../", import.meta.url));

export async function run(
  command: string[],
  options: {
    captureStdout?: boolean;
    cwd?: string;
    env?: Record<string, string>;
  } = {},
): Promise<string> {
  const captureStdout = options.captureStdout ?? false;
  const child = Bun.spawn(command, {
    cwd: options.cwd ?? ROOT,
    env: { ...process.env, ...options.env },
    stderr: "inherit",
    stdout: captureStdout ? "pipe" : "inherit",
  });
  const stdout =
    captureStdout && child.stdout ? await new Response(child.stdout).text() : "";
  const exitCode = await child.exited;
  if (exitCode !== 0) {
    throw new Error(
      `${command.map(shellDisplay).join(" ")} exited with status ${exitCode}`,
    );
  }
  return stdout;
}

export async function readJson<T = unknown>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
}

export async function listFiles(
  start: string,
  options: {
    skipDirectories?: Set<string>;
  } = {},
): Promise<string[]> {
  const files: string[] = [];
  const visit = async (directory: string): Promise<void> => {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (!options.skipDirectories?.has(entry.name)) await visit(path);
      } else if (entry.isFile()) {
        files.push(path);
      }
    }
  };
  await visit(start);
  return files;
}

export function repositoryPath(path: string): string {
  return relative(ROOT, path).split("\\").join("/");
}

function shellDisplay(value: string): string {
  return /^[A-Za-z0-9_./:@=-]+$/.test(value) ? value : JSON.stringify(value);
}
