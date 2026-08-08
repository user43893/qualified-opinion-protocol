import { readFile } from "node:fs/promises";
import { extname } from "node:path";
import { ROOT, listFiles, repositoryPath } from "./shared";

const skipDirectories = new Set([".git", "artifacts", "node_modules"]);
const files = await listFiles(ROOT, { skipDirectories });
const findings: string[] = [];
const privateKeyMarker = ["-----BEGIN ", "PRIVATE KEY-----"].join("");
const patterns: Array<{ id: string; pattern: RegExp }> = [
  {
    id: "private-key",
    pattern: new RegExp(privateKeyMarker, "g"),
  },
  {
    id: "aws-access-key",
    pattern: /A(?:KIA|SIA)[A-Z0-9]{16}/g,
  },
  {
    id: "github-token",
    pattern: /gh[pousr]_[A-Za-z0-9]{20,}/g,
  },
  {
    id: "google-api-key",
    pattern: /AIza[0-9A-Za-z_-]{30,}/g,
  },
  {
    id: "slack-token",
    pattern: /xox[baprs]-[0-9A-Za-z-]{10,}/g,
  },
];

for (const path of files) {
  const relativePath = repositoryPath(path);
  if (
    relativePath === "bun.lock" ||
    [".gif", ".ico", ".jpeg", ".jpg", ".pdf", ".png", ".tgz", ".webp"].includes(
      extname(relativePath).toLowerCase(),
    )
  ) {
    continue;
  }
  const data = await readFile(path);
  if (data.length > 5_000_000 || data.includes(0)) continue;
  const text = data.toString("utf8");
  for (const { id, pattern } of patterns) {
    pattern.lastIndex = 0;
    if (pattern.test(text)) findings.push(`${relativePath}: ${id}`);
  }
}

if (findings.length > 0) {
  throw new Error(`Potential secrets found:\n- ${findings.join("\n- ")}`);
}
console.log(`Scanned ${files.length} repository files for secret material.`);
