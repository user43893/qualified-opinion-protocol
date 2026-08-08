import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import { base64UrlDecode, canonicalizeJson } from "@qualified-opinion/protocol";

export const TRANSPARENCY_TREE_HEAD_SCHEMA_V3 =
  "qualified-opinion.transparency-tree-head.v3" as const;
export const TRANSPARENCY_WITNESS_STATUS_SCHEMA_V3 =
  "qualified-opinion.transparency-witness-status.v3" as const;
export const TRANSPARENCY_WITNESS_ENVELOPE_SCHEMA_V3 =
  "qualified-opinion.transparency-witness-envelope.v3" as const;

export type TransparencyLatestEntryV3 = {
  entryId: string;
  entryPayloadHash: string;
  entryType: string;
  leafIndex: number;
};

export type SignedTransparencyCheckpointV3 = {
  payload: {
    schema: typeof TRANSPARENCY_TREE_HEAD_SCHEMA_V3;
    logId: string;
    treeSize: number;
    rootHash: string;
    previousTreeHeadSha256: string | null;
    issuedAt: string;
    issuerKeyId: string;
  };
  payloadSha256: string;
  signature: {
    algorithm: "Ed25519";
    keyId: string;
    value: string;
  };
};

export type TransparencyWitnessStatusV3 = {
  schema: typeof TRANSPARENCY_WITNESS_STATUS_SCHEMA_V3;
  witnessId: string;
  provider: "cloudflare-workers" | "gcp-cloud-run";
  sourceRevision: string;
  trustRootId: string;
  trustRootSha256: string;
  logId: string;
  origin: string;
  status: "verified" | "verification_failure" | "operational_failure";
  lastAttemptAt: string;
  lastSuccessAt: string | null;
  consecutiveFailures: number;
  latestVerified: {
    observedAt: string;
    checkpoint: SignedTransparencyCheckpointV3;
    latestEntryByType: Record<string, TransparencyLatestEntryV3>;
  } | null;
  failure: {
    kind: "input" | "operational" | "verification" | "unknown";
    code: string;
  } | null;
};

export type SignedTransparencyWitnessStatusV3 = {
  schema: typeof TRANSPARENCY_WITNESS_ENVELOPE_SCHEMA_V3;
  statement: TransparencyWitnessStatusV3;
  statementSha256: string;
  signature: {
    algorithm: "Ed25519";
    keyId: string;
    publicKeySpki: string;
    publicKeySpkiSha256: string;
    value: string;
  };
};

export function signWitnessStatus(
  statement: TransparencyWitnessStatusV3,
  privateKeyPkcs8: string,
  expectedPublicKeySpkiSha256?: string,
): SignedTransparencyWitnessStatusV3 {
  const parsed = parseWitnessStatus(statement);
  const privateKey = createPrivateKey({
    key: Buffer.from(decodeBase64Url(privateKeyPkcs8, "witness signing private key")),
    format: "der",
    type: "pkcs8",
  });
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error("witness_signing_key_invalid");
  }
  const publicKeyDer = createPublicKey(privateKey).export({
    format: "der",
    type: "spki",
  });
  const publicKeySpkiSha256 = sha256Hex(publicKeyDer);
  if (
    expectedPublicKeySpkiSha256 !== undefined &&
    publicKeySpkiSha256 !==
      hexadecimalSha256(
        expectedPublicKeySpkiSha256,
        "expected witness public-key fingerprint",
      )
  ) {
    throw new Error("witness_signing_key_pin_mismatch");
  }
  const canonical = canonicalizeJson(parsed);
  return {
    schema: TRANSPARENCY_WITNESS_ENVELOPE_SCHEMA_V3,
    statement: parsed,
    statementSha256: sha256Base64Url(canonical),
    signature: {
      algorithm: "Ed25519",
      keyId: witnessKeyId(publicKeySpkiSha256),
      publicKeySpki: publicKeyDer.toString("base64url"),
      publicKeySpkiSha256,
      value: sign(null, Buffer.from(canonical, "utf8"), privateKey).toString(
        "base64url",
      ),
    },
  };
}

export function verifyWitnessStatusEnvelope(
  value: unknown,
  expectedPublicKeySpkiSha256?: string,
): SignedTransparencyWitnessStatusV3 {
  const envelope = record(value, "envelope");
  exactKeys(
    envelope,
    ["schema", "statement", "statementSha256", "signature"],
    "envelope",
  );
  if (envelope.schema !== TRANSPARENCY_WITNESS_ENVELOPE_SCHEMA_V3) {
    throw new Error("witness_status_invalid");
  }
  const statement = parseWitnessStatus(envelope.statement);
  const canonical = canonicalizeJson(statement);
  const statementSha256 = digest(envelope.statementSha256, "envelope.statementSha256");
  if (sha256Base64Url(canonical) !== statementSha256) {
    throw new Error("witness_status_invalid");
  }
  const signature = record(envelope.signature, "envelope.signature");
  exactKeys(
    signature,
    ["algorithm", "keyId", "publicKeySpki", "publicKeySpkiSha256", "value"],
    "envelope.signature",
  );
  if (signature.algorithm !== "Ed25519") {
    throw new Error("witness_status_invalid");
  }
  const publicKeySpki = identifier(
    signature.publicKeySpki,
    "envelope.signature.publicKeySpki",
    500,
  );
  const publicKeySpkiSha256 = hexadecimalSha256(
    signature.publicKeySpkiSha256,
    "envelope.signature.publicKeySpkiSha256",
  );
  if (
    expectedPublicKeySpkiSha256 !== undefined &&
    publicKeySpkiSha256 !==
      hexadecimalSha256(
        expectedPublicKeySpkiSha256,
        "expected witness public-key fingerprint",
      )
  ) {
    throw new Error("witness_status_invalid");
  }
  if (signature.keyId !== witnessKeyId(publicKeySpkiSha256)) {
    throw new Error("witness_status_invalid");
  }
  try {
    const publicKeyDer = decodeBase64Url(
      publicKeySpki,
      "envelope.signature.publicKeySpki",
    );
    if (sha256Hex(publicKeyDer) !== publicKeySpkiSha256) {
      throw new Error("witness_status_invalid");
    }
    const publicKey = createPublicKey({
      key: Buffer.from(publicKeyDer),
      format: "der",
      type: "spki",
    });
    const signatureValue = identifier(signature.value, "envelope.signature.value", 500);
    const signatureBytes = decodeBase64Url(signatureValue, "envelope.signature.value");
    if (
      publicKey.asymmetricKeyType !== "ed25519" ||
      signatureBytes.length !== 64 ||
      !verify(null, Buffer.from(canonical, "utf8"), publicKey, signatureBytes)
    ) {
      throw new Error("witness_status_invalid");
    }
    return {
      schema: TRANSPARENCY_WITNESS_ENVELOPE_SCHEMA_V3,
      statement,
      statementSha256,
      signature: {
        algorithm: "Ed25519",
        keyId: witnessKeyId(publicKeySpkiSha256),
        publicKeySpki,
        publicKeySpkiSha256,
        value: signatureValue,
      },
    };
  } catch {
    throw new Error("witness_status_invalid");
  }
}

function parseWitnessStatus(value: unknown): TransparencyWitnessStatusV3 {
  const statement = record(value, "statement");
  exactKeys(
    statement,
    [
      "schema",
      "witnessId",
      "provider",
      "sourceRevision",
      "trustRootId",
      "trustRootSha256",
      "logId",
      "origin",
      "status",
      "lastAttemptAt",
      "lastSuccessAt",
      "consecutiveFailures",
      "latestVerified",
      "failure",
    ],
    "statement",
  );
  if (
    statement.schema !== TRANSPARENCY_WITNESS_STATUS_SCHEMA_V3 ||
    (statement.provider !== "cloudflare-workers" &&
      statement.provider !== "gcp-cloud-run") ||
    (statement.status !== "verified" &&
      statement.status !== "verification_failure" &&
      statement.status !== "operational_failure")
  ) {
    throw new Error("witness_status_invalid");
  }
  const latestVerified =
    statement.latestVerified === null
      ? null
      : parseLatestVerified(statement.latestVerified);
  const failure = statement.failure === null ? null : parseFailure(statement.failure);
  const lastSuccessAt =
    statement.lastSuccessAt === null
      ? null
      : timestamp(statement.lastSuccessAt, "statement.lastSuccessAt");
  const consecutiveFailures = nonnegativeInteger(
    statement.consecutiveFailures,
    "statement.consecutiveFailures",
  );
  if (
    (statement.status === "verified" &&
      (failure !== null ||
        latestVerified === null ||
        lastSuccessAt === null ||
        consecutiveFailures !== 0)) ||
    (statement.status !== "verified" && failure === null)
  ) {
    throw new Error("witness_status_invalid");
  }
  return {
    schema: TRANSPARENCY_WITNESS_STATUS_SCHEMA_V3,
    witnessId: identifier(statement.witnessId, "statement.witnessId"),
    provider: statement.provider,
    sourceRevision: identifier(
      statement.sourceRevision,
      "statement.sourceRevision",
      200,
    ),
    trustRootId: identifier(statement.trustRootId, "statement.trustRootId", 500),
    trustRootSha256: hexadecimalSha256(
      statement.trustRootSha256,
      "statement.trustRootSha256",
    ),
    logId: identifier(statement.logId, "statement.logId", 500),
    origin: httpsOrigin(statement.origin),
    status: statement.status,
    lastAttemptAt: timestamp(statement.lastAttemptAt, "statement.lastAttemptAt"),
    lastSuccessAt,
    consecutiveFailures,
    latestVerified,
    failure,
  };
}

function parseLatestVerified(value: unknown) {
  const latest = record(value, "statement.latestVerified");
  exactKeys(
    latest,
    ["observedAt", "checkpoint", "latestEntryByType"],
    "statement.latestVerified",
  );
  return {
    observedAt: timestamp(latest.observedAt, "statement.latestVerified.observedAt"),
    checkpoint: parseCheckpoint(latest.checkpoint),
    latestEntryByType: parseLatestEntryByType(latest.latestEntryByType),
  };
}

function parseCheckpoint(value: unknown): SignedTransparencyCheckpointV3 {
  const checkpoint = record(value, "checkpoint");
  exactKeys(checkpoint, ["payload", "payloadSha256", "signature"], "checkpoint");
  const payload = record(checkpoint.payload, "checkpoint.payload");
  exactKeys(
    payload,
    [
      "schema",
      "logId",
      "treeSize",
      "rootHash",
      "previousTreeHeadSha256",
      "issuedAt",
      "issuerKeyId",
    ],
    "checkpoint.payload",
  );
  if (payload.schema !== TRANSPARENCY_TREE_HEAD_SCHEMA_V3) {
    throw new Error("witness_status_invalid");
  }
  const signature = record(checkpoint.signature, "checkpoint.signature");
  exactKeys(signature, ["algorithm", "keyId", "value"], "checkpoint.signature");
  if (signature.algorithm !== "Ed25519") {
    throw new Error("witness_status_invalid");
  }
  return {
    payload: {
      schema: TRANSPARENCY_TREE_HEAD_SCHEMA_V3,
      logId: identifier(payload.logId, "checkpoint.payload.logId", 500),
      treeSize: nonnegativeInteger(payload.treeSize, "checkpoint.payload.treeSize"),
      rootHash: digest(payload.rootHash, "checkpoint.payload.rootHash"),
      previousTreeHeadSha256:
        payload.previousTreeHeadSha256 === null
          ? null
          : digest(
              payload.previousTreeHeadSha256,
              "checkpoint.payload.previousTreeHeadSha256",
            ),
      issuedAt: timestamp(payload.issuedAt, "checkpoint.payload.issuedAt"),
      issuerKeyId: identifier(payload.issuerKeyId, "checkpoint.payload.issuerKeyId"),
    },
    payloadSha256: digest(checkpoint.payloadSha256, "checkpoint.payloadSha256"),
    signature: {
      algorithm: "Ed25519",
      keyId: identifier(signature.keyId, "checkpoint.signature.keyId"),
      value: identifier(signature.value, "checkpoint.signature.value", 500),
    },
  };
}

function parseLatestEntryByType(
  value: unknown,
): Record<string, TransparencyLatestEntryV3> {
  const entries = Object.entries(record(value, "latestEntryByType"));
  if (entries.length > 1_000) throw new Error("witness_status_invalid");
  return Object.fromEntries(
    entries
      .map(([entryType, candidate]) => {
        if (!/^[a-z][a-z0-9_]{0,99}$/.test(entryType)) {
          throw new Error("witness_status_invalid");
        }
        const entry = record(candidate, `latestEntryByType.${entryType}`);
        exactKeys(
          entry,
          ["entryId", "entryPayloadHash", "entryType", "leafIndex"],
          `latestEntryByType.${entryType}`,
        );
        if (entry.entryType !== entryType) {
          throw new Error("witness_status_invalid");
        }
        return [
          entryType,
          {
            entryId: identifier(entry.entryId, `${entryType}.entryId`),
            entryPayloadHash: digest(
              entry.entryPayloadHash,
              `${entryType}.entryPayloadHash`,
            ),
            entryType,
            leafIndex: nonnegativeInteger(entry.leafIndex, `${entryType}.leafIndex`),
          },
        ] as const;
      })
      .sort(([left], [right]) => left.localeCompare(right)),
  );
}

function parseFailure(
  value: unknown,
): NonNullable<TransparencyWitnessStatusV3["failure"]> {
  const failure = record(value, "statement.failure");
  exactKeys(failure, ["kind", "code"], "statement.failure");
  if (
    failure.kind !== "input" &&
    failure.kind !== "operational" &&
    failure.kind !== "verification" &&
    failure.kind !== "unknown"
  ) {
    throw new Error("witness_status_invalid");
  }
  return {
    kind: failure.kind,
    code: /^[a-z0-9_]{1,100}$/.test(String(failure.code))
      ? String(failure.code)
      : "unexpected_failure",
  };
}

function witnessKeyId(fingerprint: string) {
  return `qualified-opinion-witness-${fingerprint.slice(0, 16)}`;
}

function sha256Base64Url(value: string | Uint8Array) {
  return createHash("sha256").update(value).digest("base64url");
}

function sha256Hex(value: string | Uint8Array) {
  return createHash("sha256").update(value).digest("hex");
}

function decodeBase64Url(value: string, label: string) {
  const bytes = base64UrlDecode(identifier(value, label, 2_000));
  if (Buffer.from(bytes).toString("base64url") !== value) {
    throw new Error(`${label} is not canonical base64url`);
  }
  return bytes;
}

function digest(value: unknown, label: string) {
  const text = identifier(value, label, 100);
  if (decodeBase64Url(text, label).length !== 32) {
    throw new Error("witness_status_invalid");
  }
  return text;
}

function hexadecimalSha256(value: unknown, label: string) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${label} must be a lowercase hexadecimal SHA-256 digest`);
  }
  return value;
}

function timestamp(value: unknown, label: string) {
  const text = identifier(value, label, 100);
  const parsed = new Date(text);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== text) {
    throw new Error("witness_status_invalid");
  }
  return text;
}

function httpsOrigin(value: unknown) {
  const text = identifier(value, "origin", 2_000);
  const parsed = new URL(text);
  if (parsed.protocol !== "https:" || parsed.origin !== text) {
    throw new Error("witness_status_invalid");
  }
  return text;
}

function nonnegativeInteger(value: unknown, label: string) {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new Error(`${label} must be a nonnegative safe integer`);
  }
  return value as number;
}

function identifier(value: unknown, label: string, maximum = 500) {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum) {
    throw new Error(`${label} must be a nonempty string`);
  }
  return value;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: string[], label: string) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    throw new Error(`${label} has unexpected fields`);
  }
}
