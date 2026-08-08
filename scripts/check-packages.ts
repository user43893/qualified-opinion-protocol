import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type NpmPackResult, packPackages } from "./package-archives";
import { ROOT, listFiles, readJson, repositoryPath, run } from "./shared";

type PackedManifest = {
  license?: string;
  name?: string;
  private?: boolean;
  version?: string;
};

const temporaryDirectory = await mkdtemp(
  join(tmpdir(), "qualified-opinion-package-check-"),
);
try {
  const archives = await packPackages(temporaryDirectory);
  for (const archive of archives) {
    await checkArchive(archive);
  }
  await checkConsumerInstall(archives);
  console.log(
    "Verified public file boundaries and a clean Node.js install for 2 package archives.",
  );
} finally {
  await rm(temporaryDirectory, { force: true, recursive: true });
}

async function checkConsumerInstall(archives: NpmPackResult[]): Promise<void> {
  const consumerDirectory = join(temporaryDirectory, "consumer");
  await mkdir(consumerDirectory);
  await writeFile(
    join(consumerDirectory, "package.json"),
    `${JSON.stringify(
      {
        name: "qualified-opinion-package-smoke",
        private: true,
        type: "module",
        version: "0.0.0",
      },
      null,
      2,
    )}\n`,
  );
  await run(
    [
      "npm",
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--package-lock=false",
      ...archives.map((archive) => join(temporaryDirectory, archive.filename)),
    ],
    { cwd: consumerDirectory },
  );

  const smoke = `
    import {
      canonicalizeJson,
      questionVoteLogIdV3
    } from "@qualified-opinion/protocol";
    import {
      verifyActiveEligibilityDirectoryRecordV3,
      verifyDownloadedVoteProof
    } from "@qualified-opinion/verifier";
    if (canonicalizeJson({ b: 2, a: 1 }) !== '{"a":1,"b":2}') {
      throw new Error("packed protocol import failed");
    }
    if ((await questionVoteLogIdV3({
      instanceId: "example-instance",
      questionId: "example-question"
    })).startsWith("qualified-opinion.question-votes.v3:") !== true) {
      throw new Error("packed question log export failed");
    }
    if (
      typeof verifyDownloadedVoteProof !== "function" ||
      typeof verifyActiveEligibilityDirectoryRecordV3 !== "function"
    ) {
      throw new Error("packed verifier import failed");
    }
  `;
  await run(["node", "--input-type=module", "--eval", smoke], {
    cwd: consumerDirectory,
  });
  await writeFile(
    join(consumerDirectory, "index.ts"),
    `
      import {
        type ActiveEligibilityDirectoryCheckpointV3,
        canonicalizeJson,
        questionVoteLogIdV3,
        type VoteEventV3
      } from "@qualified-opinion/protocol";
      import {
        verifyP256SpkiSignature
      } from "@qualified-opinion/protocol/node";
      import {
        type OfflineVerificationPolicyV3,
        verifyActiveEligibilityDirectoryRecordV3,
        verifyDownloadedVoteProof
      } from "@qualified-opinion/verifier";
      declare const event: VoteEventV3;
      declare const policy: OfflineVerificationPolicyV3;
      declare const directory: ActiveEligibilityDirectoryCheckpointV3;
      void event;
      void directory;
      void policy;
      void canonicalizeJson;
      void questionVoteLogIdV3;
      void verifyP256SpkiSignature;
      void verifyActiveEligibilityDirectoryRecordV3;
      void verifyDownloadedVoteProof;
    `,
  );
  await writeFile(
    join(consumerDirectory, "tsconfig.json"),
    `${JSON.stringify(
      {
        compilerOptions: {
          lib: ["ES2022", "DOM"],
          module: "ESNext",
          moduleResolution: "Bundler",
          noEmit: true,
          skipLibCheck: false,
          strict: true,
          target: "ES2022",
          types: [],
        },
        include: ["index.ts"],
      },
      null,
      2,
    )}\n`,
  );
  await run(
    [
      join(ROOT, "node_modules/.bin/tsc"),
      "-p",
      join(consumerDirectory, "tsconfig.json"),
    ],
    { cwd: consumerDirectory },
  );
  const help = await run(
    [
      "node",
      join(consumerDirectory, "node_modules/@qualified-opinion/verifier/dist/cli.js"),
      "--help",
    ],
    { captureStdout: true, cwd: consumerDirectory },
  );
  if (!help.includes("qualified-opinion-verify")) {
    throw new Error("Packed verifier CLI smoke test failed");
  }
}

async function checkArchive(archive: NpmPackResult): Promise<void> {
  const expectedNames = new Set([
    "@qualified-opinion/protocol",
    "@qualified-opinion/verifier",
  ]);
  if (
    !expectedNames.has(archive.name) ||
    archive.version !== "3.0.0" ||
    archive.files.length === 0
  ) {
    throw new Error(`Unexpected package metadata for ${archive.filename}`);
  }

  const paths = new Set(archive.files.map((file) => file.path));
  for (const path of paths) {
    if (
      path !== "package.json" &&
      path !== "README.md" &&
      path !== "LICENSE" &&
      path !== "NOTICE" &&
      !path.startsWith("dist/")
    ) {
      throw new Error(`${archive.filename}: unexpected packed file ${path}`);
    }
    if (path.includes(".test.") || path.startsWith("src/")) {
      throw new Error(`${archive.filename}: test or source file was packed`);
    }
  }
  for (const required of ["package.json", "README.md", "LICENSE", "NOTICE"]) {
    if (!paths.has(required)) {
      throw new Error(`${archive.filename}: missing ${required}`);
    }
  }
  if (!paths.has("dist/index.js") || !paths.has("dist/index.d.ts")) {
    throw new Error(`${archive.filename}: missing default ESM entry point`);
  }
  if (
    archive.name === "@qualified-opinion/protocol" &&
    (!paths.has("dist/node.js") || !paths.has("dist/node.d.ts"))
  ) {
    throw new Error(`${archive.filename}: missing Node.js protocol entry point`);
  }
  if (archive.name === "@qualified-opinion/verifier") {
    const cli = archive.files.find((file) => file.path === "dist/cli.js");
    if (!cli || (cli.mode & 0o111) === 0) {
      throw new Error(`${archive.filename}: CLI is missing or not executable`);
    }
  }

  const extractDirectory = join(
    temporaryDirectory,
    `extract-${archive.name.split("/").at(-1)}`,
  );
  await mkdir(extractDirectory);
  await run([
    "tar",
    "-xzf",
    join(temporaryDirectory, archive.filename),
    "-C",
    extractDirectory,
  ]);
  const packageDirectory = join(extractDirectory, "package");
  const manifest = await readJson<PackedManifest>(
    join(packageDirectory, "package.json"),
  );
  if (
    manifest.name !== archive.name ||
    manifest.version !== "3.0.0" ||
    manifest.license !== "Apache-2.0" ||
    manifest.private === true
  ) {
    throw new Error(`${archive.filename}: invalid packed manifest`);
  }

  const productNames = [
    String.fromCodePoint(104, 117, 107, 117, 107, 231, 97),
    String.fromCodePoint(104, 117, 107, 117, 107, 99, 97),
  ];
  const retiredSchema =
    /\b(?:qualified-opinion|qualified-voting)[a-z0-9._-]*[.]v(?:1|2)\b/i;
  for (const path of await listFiles(packageDirectory)) {
    const data = await readFile(path);
    if (data.includes(0)) continue;
    const text = data.toString("utf8");
    const lower = text.toLocaleLowerCase("en");
    if (
      productNames.some((productName) => lower.includes(productName)) ||
      retiredSchema.test(text)
    ) {
      throw new Error(
        `${archive.filename}: non-public application identifier in ${repositoryPath(path)}`,
      );
    }
  }
}
