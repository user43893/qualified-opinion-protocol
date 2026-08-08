import { constants } from "node:fs";
import { access, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { ROOT, run } from "./shared";

const protocolIndex = join(ROOT, "packages/protocol/dist/index.js");
const protocolNode = join(ROOT, "packages/protocol/dist/node.js");
const verifierIndex = join(ROOT, "packages/verifier/dist/index.js");
const verifierCli = join(ROOT, "packages/verifier/dist/cli.js");

for (const path of [protocolIndex, protocolNode, verifierIndex, verifierCli]) {
  await access(path, constants.R_OK);
}

const consumerSmoke = `
  import {
    canonicalizeJson,
    questionVoteLogIdV3,
    validatePublicVoteProofBundleV3
  } from "./packages/protocol/dist/index.js";
  import {
    verifyP256SpkiSignature
  } from "./packages/protocol/dist/node.js";
  import {
    verifyActiveEligibilityDirectoryRecordV3,
    verifyDownloadedVoteProof
  } from "./packages/verifier/dist/index.js";
  if (canonicalizeJson({ b: 2, a: 1 }) !== '{"a":1,"b":2}') {
    throw new Error("canonicalization export failed");
  }
  if (validatePublicVoteProofBundleV3({}).ok) {
    throw new Error("invalid bundle was accepted");
  }
  if ((await questionVoteLogIdV3({
    instanceId: "example-instance",
    questionId: "example-question"
  })).startsWith("qualified-opinion.question-votes.v3:") !== true) {
    throw new Error("question log export failed");
  }
  if (verifyP256SpkiSignature({
    publicKeySpki: new Uint8Array(),
    message: "message",
    signature: new Uint8Array()
  })) {
    throw new Error("invalid signature was accepted");
  }
  if (
    typeof verifyDownloadedVoteProof !== "function" ||
    typeof verifyActiveEligibilityDirectoryRecordV3 !== "function"
  ) {
    throw new Error("verifier export missing");
  }
`;

await run(["node", "--input-type=module", "--eval", consumerSmoke]);
const help = await run(["node", verifierCli, "--help"], {
  captureStdout: true,
});
if (
  !help.includes("qualified-opinion-verify") ||
  !help.includes("--expected-policy-sha256")
) {
  throw new Error("Built CLI help output is incomplete");
}
if (!(await readFile(verifierCli, "utf8")).startsWith("#!/usr/bin/env node")) {
  throw new Error("Built CLI is missing its Node.js shebang");
}
if (((await stat(verifierCli)).mode & 0o111) === 0) {
  throw new Error("Built CLI is not executable");
}

console.log("Built package imports and CLI passed the Node.js smoke test.");
