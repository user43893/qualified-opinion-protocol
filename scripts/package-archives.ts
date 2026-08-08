import { mkdir } from "node:fs/promises";
import { basename, join } from "node:path";
import { ROOT, run } from "./shared";

export type NpmPackFile = {
  mode: number;
  path: string;
  size: number;
};

export type NpmPackResult = {
  filename: string;
  files: NpmPackFile[];
  id: string;
  integrity: string;
  name: string;
  shasum: string;
  size: number;
  unpackedSize: number;
  version: string;
};

export async function packPackages(destination: string): Promise<NpmPackResult[]> {
  await mkdir(destination, { recursive: true });
  const results: NpmPackResult[] = [];
  for (const packageName of ["protocol", "verifier"]) {
    const packageDirectory = join(ROOT, "packages", packageName);
    const output = await run(
      [
        "npm",
        "pack",
        "--ignore-scripts",
        "--json",
        "--pack-destination",
        destination,
        packageDirectory,
      ],
      { captureStdout: true },
    );
    const parsed = JSON.parse(output) as NpmPackResult[];
    if (parsed.length !== 1 || !parsed[0]) {
      throw new Error(`npm pack returned no result for ${packageName}`);
    }
    const result = parsed[0];
    if (basename(result.filename) !== result.filename) {
      throw new Error(`npm pack returned an unsafe filename for ${packageName}`);
    }
    results.push(result);
  }
  return results;
}
