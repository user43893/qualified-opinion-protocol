import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { ROOT, listFiles, readJson, repositoryPath } from "./shared";

type Manifest = {
  license?: string;
  name?: string;
  version?: string;
};

const errors: string[] = [];
const rootLicense = await readFile(join(ROOT, "LICENSE"), "utf8");
const rootNotice = await readFile(join(ROOT, "NOTICE"), "utf8");
if (
  !rootLicense.includes("Apache License") ||
  !rootLicense.includes("Version 2.0, January 2004") ||
  !rootLicense.includes("END OF TERMS AND CONDITIONS")
) {
  errors.push("LICENSE: complete Apache-2.0 terms were not found");
}
if (!rootNotice.includes("Qualified Opinion Protocol")) {
  errors.push("NOTICE: project attribution is missing");
}

for (const packageName of ["protocol", "verifier"]) {
  const packageDirectory = join(ROOT, "packages", packageName);
  const manifest = await readJson<Manifest>(join(packageDirectory, "package.json"));
  if (manifest.license !== "Apache-2.0") {
    errors.push(`packages/${packageName}/package.json: unexpected license`);
  }
  if ((await readFile(join(packageDirectory, "LICENSE"), "utf8")) !== rootLicense) {
    errors.push(`packages/${packageName}/LICENSE: must match the root license`);
  }
  if ((await readFile(join(packageDirectory, "NOTICE"), "utf8")) !== rootNotice) {
    errors.push(`packages/${packageName}/NOTICE: must match the root notice`);
  }
}

const allowedDependencyLicenses = new Set([
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "ISC",
  "MIT",
  "MIT OR Apache-2.0",
]);
const dependencyManifests = (await listFiles(join(ROOT, "node_modules"))).filter(
  (path) => path.endsWith("/package.json"),
);
const dependencies = new Map<string, string>();
for (const path of dependencyManifests) {
  let manifest: Manifest;
  try {
    manifest = await readJson<Manifest>(path);
  } catch {
    errors.push(`${repositoryPath(path)}: invalid dependency manifest`);
    continue;
  }
  if (!manifest.name || !manifest.version) continue;
  const key = `${manifest.name}@${manifest.version}`;
  const license = manifest.license ?? "";
  dependencies.set(key, license);
  if (!allowedDependencyLicenses.has(license)) {
    errors.push(`${key}: unapproved or missing dependency license ${license}`);
  }
}
if (dependencies.size === 0) {
  errors.push("node_modules: no installed dependencies to inspect");
}

if (errors.length > 0) {
  throw new Error(`License check failed:\n- ${errors.join("\n- ")}`);
}
console.log(
  `Verified Apache-2.0 release files and ${dependencies.size} installed dependency licenses.`,
);
