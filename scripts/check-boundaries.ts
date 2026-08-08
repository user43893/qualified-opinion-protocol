import { readFile, readdir } from "node:fs/promises";
import { extname, join } from "node:path";
import { ROOT, listFiles, readJson, repositoryPath } from "./shared";

type PackageManifest = {
  dependencies?: Record<string, string>;
  files?: string[];
  license?: string;
  name?: string;
  private?: boolean;
  version?: string;
  workspaces?: string[];
};

const errors: string[] = [];
const skippedDirectories = new Set([".git", "artifacts", "dist", "node_modules"]);
const sourceFiles = await listFiles(ROOT, {
  skipDirectories: skippedDirectories,
});
const productNames = [
  String.fromCodePoint(104, 117, 107, 117, 107, 231, 97),
  String.fromCodePoint(104, 117, 107, 117, 107, 99, 97),
];
const retiredSchema =
  /\b(?:qualified-opinion|qualified-voting)[a-z0-9._-]*[.]v(?:1|2)\b/gi;
const retiredLabels = [1, 2].map((version) => `V${version}`).join("|");
const retiredIdentifier = new RegExp(
  String.raw`\b[A-Za-z][A-Za-z0-9_]*(?:${retiredLabels})\b`,
  "g",
);
const retiredPhrase = new RegExp(
  String.raw`\b(?:(?:${retiredLabels})[ -]?(?:protocol|schema|proof|bundle|vote|tally)|(?:protocol|schema|proof|bundle|vote|tally)[ -]?(?:${retiredLabels}))\b`,
  "gi",
);
const supersededWord = ["leg", "acy"].join("");
const supersededPhrase = new RegExp(
  String.raw`\b(?:${supersededWord}.{0,24}(?:protocol|schema|proof|bundle|vote|tally)|(?:protocol|schema|proof|bundle|vote|tally).{0,24}${supersededWord})\b`,
  "gi",
);

for (const path of sourceFiles) {
  const relativePath = repositoryPath(path);
  const extension = extname(relativePath).toLowerCase();
  if (
    [".gif", ".ico", ".jpeg", ".jpg", ".pdf", ".png", ".tgz", ".webp"].includes(
      extension,
    )
  ) {
    continue;
  }
  const text = await readFile(path, "utf8");
  const lower = text.toLocaleLowerCase("en");
  for (const productName of productNames) {
    if (lower.includes(productName)) {
      errors.push(`${relativePath}: contains a product-specific identifier`);
    }
  }

  if (isApplicationBoundary(relativePath)) {
    for (const pattern of [
      retiredSchema,
      retiredIdentifier,
      retiredPhrase,
      supersededPhrase,
    ]) {
      pattern.lastIndex = 0;
      if (pattern.test(text)) {
        errors.push(
          `${relativePath}: contains an application artifact outside the current protocol`,
        );
      }
    }
  }

  if (
    /\.(?:env|key|p12|pfx|pkcs12)$/i.test(relativePath) ||
    /(?:^|\/)id_(?:rsa|ecdsa|ed25519)(?:\.|$)/i.test(relativePath)
  ) {
    errors.push(`${relativePath}: private configuration or key file is forbidden`);
  }
  if (/^packages\/[^/]+\/src\/.*[.]d[.]ts(?:[.]map)?$/.test(relativePath)) {
    errors.push(`${relativePath}: generated declarations belong in dist`);
  }
}

await checkManifests();
await checkProductionImports();
await checkSymlinks(ROOT);

if (errors.length > 0) {
  throw new Error(`Public-boundary check failed:\n- ${errors.join("\n- ")}`);
}
console.log(
  `Checked ${sourceFiles.length} source and release files for public V3 boundaries.`,
);

function isApplicationBoundary(path: string): boolean {
  return (
    path === "README.md" ||
    path.startsWith("docs/") ||
    path.startsWith("vectors/") ||
    /^packages\/[^/]+\/(?:README|NOTICE|package[.]json)/.test(path) ||
    (/^packages\/[^/]+\/src\//.test(path) &&
      !path.endsWith(".test.ts") &&
      !path.includes("/testing/"))
  );
}

async function checkManifests(): Promise<void> {
  const rootManifest = await readJson<PackageManifest>(join(ROOT, "package.json"));
  if (rootManifest.private !== true) {
    errors.push("package.json: workspace root must remain private");
  }
  if (JSON.stringify(rootManifest.workspaces) !== JSON.stringify(["packages/*"])) {
    errors.push("package.json: workspace boundary must be packages/*");
  }

  const protocol = await readJson<PackageManifest>(
    join(ROOT, "packages/protocol/package.json"),
  );
  const verifier = await readJson<PackageManifest>(
    join(ROOT, "packages/verifier/package.json"),
  );
  for (const [path, manifest, expectedName] of [
    ["packages/protocol/package.json", protocol, "@qualified-opinion/protocol"],
    ["packages/verifier/package.json", verifier, "@qualified-opinion/verifier"],
  ] as const) {
    if (manifest.name !== expectedName) {
      errors.push(`${path}: unexpected public package name`);
    }
    if (manifest.version !== "3.0.0") {
      errors.push(`${path}: public package version must be 3.0.0`);
    }
    if (manifest.license !== "Apache-2.0") {
      errors.push(`${path}: public package license must be Apache-2.0`);
    }
    if (
      JSON.stringify(manifest.files) !==
      JSON.stringify(["dist", "README.md", "LICENSE", "NOTICE"])
    ) {
      errors.push(`${path}: package files must use the public allowlist`);
    }
  }

  if (protocol.dependencies && Object.keys(protocol.dependencies).length !== 0) {
    errors.push("packages/protocol/package.json: runtime must be dependency-free");
  }
  if (
    JSON.stringify(verifier.dependencies) !==
    JSON.stringify({ "@qualified-opinion/protocol": "3.0.0" })
  ) {
    errors.push(
      "packages/verifier/package.json: unexpected runtime dependency boundary",
    );
  }
}

async function checkProductionImports(): Promise<void> {
  for (const packageName of ["protocol", "verifier"]) {
    const sourceRoot = join(ROOT, "packages", packageName, "src");
    const files = (await listFiles(sourceRoot)).filter(
      (path) =>
        path.endsWith(".ts") &&
        !path.endsWith(".test.ts") &&
        !path.includes("/testing/"),
    );
    for (const path of files) {
      const text = await readFile(path, "utf8");
      const imports = text.matchAll(/(?:from\s+|import\s*\(\s*)["']([^"']+)["']/g);
      for (const match of imports) {
        const specifier = match[1] ?? "";
        const allowed =
          specifier.startsWith(".") ||
          specifier.startsWith("node:") ||
          (packageName === "verifier" &&
            (specifier === "@qualified-opinion/protocol" ||
              specifier === "@qualified-opinion/protocol/node"));
        if (!allowed) {
          errors.push(
            `${repositoryPath(path)}: import crosses the public package boundary: ${specifier}`,
          );
        }
      }
    }
  }
}

async function checkSymlinks(directory: string): Promise<void> {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    if (skippedDirectories.has(entry.name)) continue;
    const path = join(directory, entry.name);
    if (entry.isSymbolicLink()) {
      errors.push(`${repositoryPath(path)}: source symlinks are not allowed`);
    } else if (entry.isDirectory()) {
      await checkSymlinks(path);
    }
  }
}
