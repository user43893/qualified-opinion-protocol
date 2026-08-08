import { readdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { ROOT } from "./shared";

const generatedDirectories = [
  join(ROOT, "packages/protocol/dist"),
  join(ROOT, "packages/verifier/dist"),
  join(ROOT, "artifacts"),
];

for (const path of generatedDirectories) {
  await rm(path, { force: true, recursive: true });
}

for (const directory of [
  ROOT,
  join(ROOT, "packages/protocol"),
  join(ROOT, "packages/verifier"),
]) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.isFile() && entry.name.endsWith(".tgz")) {
      await rm(join(directory, entry.name));
    }
  }
}

console.log("Removed generated distributions and package archives.");
