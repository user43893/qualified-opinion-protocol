import { createHash } from "node:crypto";
import { mkdir, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { packPackages } from "./package-archives";
import { ROOT } from "./shared";

const destination = join(ROOT, "artifacts/packages");
await rm(destination, { force: true, recursive: true });
await mkdir(destination, { recursive: true });

for (const archive of await packPackages(destination)) {
  const path = join(destination, archive.filename);
  const sha256 = createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
  console.log(`${archive.filename}  sha256:${sha256}`);
}
