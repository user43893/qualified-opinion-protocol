import {
  type BinaryInput,
  base64UrlDecode,
  base64UrlEncode,
  concatBytes,
  equalBytes,
  sha256Bytes,
  toBytes,
} from "./encoding";

const LEAF_PREFIX = new Uint8Array([0x00]);
const NODE_PREFIX = new Uint8Array([0x01]);

export type MerkleInclusionProof = {
  leafIndex: number;
  treeSize: number;
  leafHash: string;
  rootHash: string;
  auditPath: string[];
};

export type MerkleConsistencyProof = {
  firstTreeSize: number;
  secondTreeSize: number;
  firstRootHash: string;
  secondRootHash: string;
  auditPath: string[];
};

/** Coordinates a complete, power-of-two subtree in a persisted RFC 6962 tree. */
export type MerkleNodeCoordinate = {
  level: number;
  nodeIndex: number;
};

export type StoredMerkleNode = MerkleNodeCoordinate & {
  hash: string | Uint8Array;
};

export type MerkleNodeLoader = (
  coordinates: MerkleNodeCoordinate[],
) => Promise<StoredMerkleNode[]>;

/** RFC 6962 MTH({}) = SHA-256 of the empty byte string. */
export async function emptyMerkleRoot(): Promise<Uint8Array> {
  return sha256Bytes(new Uint8Array());
}

/** RFC 6962 leaf hash: SHA-256(0x00 || leaf_data). */
export async function merkleLeafHash(value: BinaryInput): Promise<Uint8Array> {
  return sha256Bytes(concatBytes(LEAF_PREFIX, toBytes(value)));
}

/** RFC 6962 node hash: SHA-256(0x01 || left || right). */
export async function merkleNodeHash(
  left: Uint8Array,
  right: Uint8Array,
): Promise<Uint8Array> {
  assertDigest(left, "left");
  assertDigest(right, "right");
  return sha256Bytes(concatBytes(NODE_PREFIX, left, right));
}

export async function computeMerkleRoot(leaves: BinaryInput[]): Promise<Uint8Array> {
  if (leaves.length === 0) {
    return emptyMerkleRoot();
  }
  const hashes = await Promise.all(leaves.map(merkleLeafHash));
  return subtreeRoot(hashes);
}

/**
 * Computes an RFC 6962 root from an already-hashed, ordered leaf prefix.
 * This is the verifier primitive for a self-contained complete log prefix.
 */
export async function computeMerkleRootFromLeafHashes(
  leafHashes: readonly string[],
): Promise<Uint8Array> {
  if (leafHashes.length === 0) {
    return emptyMerkleRoot();
  }
  const hashes = leafHashes.map((value, index) => {
    let decoded: Uint8Array;
    try {
      decoded = base64UrlDecode(value);
    } catch {
      throw new TypeError(`leafHashes[${index}] must be a SHA-256 digest`);
    }
    assertDigest(decoded, `leafHashes[${index}]`);
    return decoded;
  });
  return subtreeRoot(hashes);
}

export async function createMerkleInclusionProof(
  leaves: BinaryInput[],
  leafIndex: number,
): Promise<MerkleInclusionProof> {
  if (!Number.isSafeInteger(leafIndex) || leafIndex < 0 || leafIndex >= leaves.length) {
    throw new RangeError("leafIndex must identify a leaf in the tree");
  }
  const hashes = await Promise.all(leaves.map(merkleLeafHash));
  const auditPath = await buildAuditPath(hashes, leafIndex);
  const rootHash = await subtreeRoot(hashes);
  return {
    leafIndex,
    treeSize: hashes.length,
    leafHash: base64UrlEncode(hashes[leafIndex]),
    rootHash: base64UrlEncode(rootHash),
    auditPath: auditPath.map(base64UrlEncode),
  };
}

/**
 * Creates the unique minimal RFC 6962 consistency proof showing that the
 * first `firstTreeSize` leaves are an append-only prefix of `leaves`.
 *
 * The RFC defines the recursive proof for 0 < firstTreeSize < leaves.length.
 * This API also handles the two useful boundary cases: an empty tree is a
 * prefix of every tree, and a tree is a prefix of itself. Both have an empty
 * audit path.
 */
export async function createMerkleConsistencyProof(
  leaves: BinaryInput[],
  firstTreeSize: number,
): Promise<MerkleConsistencyProof> {
  if (
    !Number.isSafeInteger(firstTreeSize) ||
    firstTreeSize < 0 ||
    firstTreeSize > leaves.length
  ) {
    throw new RangeError(
      "firstTreeSize must be between zero and the current tree size",
    );
  }

  const hashes = await Promise.all(leaves.map(merkleLeafHash));
  const firstRoot = await subtreeRoot(hashes.slice(0, firstTreeSize));
  const secondRoot = await subtreeRoot(hashes);
  const auditPath =
    firstTreeSize === 0 || firstTreeSize === hashes.length
      ? []
      : await buildConsistencyPath(hashes, firstTreeSize, true);

  return {
    firstTreeSize,
    secondTreeSize: hashes.length,
    firstRootHash: base64UrlEncode(firstRoot),
    secondRootHash: base64UrlEncode(secondRoot),
    auditPath: auditPath.map(base64UrlEncode),
  };
}

/**
 * Computes an RFC 6962 root from a compact index of complete subtrees.
 * The loader is called once and receives O(log(treeSize)) coordinates.
 */
export async function computeStoredMerkleRoot(input: {
  loadNodes: MerkleNodeLoader;
  treeSize: number;
}): Promise<Uint8Array> {
  assertTreeSize(input.treeSize, true);
  if (input.treeSize === 0) return emptyMerkleRoot();
  const plan = planRangeRoot(0, input.treeSize);
  const nodes = await loadPlannedNodes([plan], input.loadNodes);
  return resolveRangePlan(plan, nodes);
}

/**
 * Creates the same minimal inclusion proof as `createMerkleInclusionProof`
 * without loading the full leaf prefix. The loader is called exactly once.
 */
export async function createStoredMerkleInclusionProof(input: {
  leafIndex: number;
  loadNodes: MerkleNodeLoader;
  treeSize: number;
}): Promise<MerkleInclusionProof> {
  assertTreeSize(input.treeSize, false);
  if (
    !Number.isSafeInteger(input.leafIndex) ||
    input.leafIndex < 0 ||
    input.leafIndex >= input.treeSize
  ) {
    throw new RangeError("leafIndex must identify a leaf in the tree");
  }
  const auditPlans = buildStoredAuditPathPlans(0, input.treeSize, input.leafIndex);
  const leafPlan = planRangeRoot(input.leafIndex, 1);
  const rootPlan = planRangeRoot(0, input.treeSize);
  const nodes = await loadPlannedNodes(
    [leafPlan, rootPlan, ...auditPlans],
    input.loadNodes,
  );
  return {
    leafIndex: input.leafIndex,
    treeSize: input.treeSize,
    leafHash: base64UrlEncode(await resolveRangePlan(leafPlan, nodes)),
    rootHash: base64UrlEncode(await resolveRangePlan(rootPlan, nodes)),
    auditPath: await Promise.all(
      auditPlans.map(async (plan) =>
        base64UrlEncode(await resolveRangePlan(plan, nodes)),
      ),
    ),
  };
}

/**
 * Creates the same RFC 6962 consistency proof as
 * `createMerkleConsistencyProof` from a compact complete-subtree index. The
 * loader is called exactly once and receives O(log(secondTreeSize)) nodes.
 */
export async function createStoredMerkleConsistencyProof(input: {
  firstTreeSize: number;
  loadNodes: MerkleNodeLoader;
  secondTreeSize: number;
}): Promise<MerkleConsistencyProof> {
  assertTreeSize(input.firstTreeSize, true);
  assertTreeSize(input.secondTreeSize, true);
  if (input.firstTreeSize > input.secondTreeSize) {
    throw new RangeError(
      "firstTreeSize must be between zero and the current tree size",
    );
  }

  const firstPlan =
    input.firstTreeSize === 0 ? null : planRangeRoot(0, input.firstTreeSize);
  const secondPlan =
    input.secondTreeSize === 0 ? null : planRangeRoot(0, input.secondTreeSize);
  const auditPlans =
    input.firstTreeSize === 0 || input.firstTreeSize === input.secondTreeSize
      ? []
      : buildStoredConsistencyPathPlans(
          0,
          input.secondTreeSize,
          input.firstTreeSize,
          true,
        );
  const plans = [firstPlan, secondPlan, ...auditPlans].filter(
    (plan): plan is MerkleRangePlan => plan !== null,
  );
  const nodes = await loadPlannedNodes(plans, input.loadNodes);
  const emptyRoot = await emptyMerkleRoot();
  return {
    firstTreeSize: input.firstTreeSize,
    secondTreeSize: input.secondTreeSize,
    firstRootHash: base64UrlEncode(
      firstPlan ? await resolveRangePlan(firstPlan, nodes) : emptyRoot,
    ),
    secondRootHash: base64UrlEncode(
      secondPlan ? await resolveRangePlan(secondPlan, nodes) : emptyRoot,
    ),
    auditPath: await Promise.all(
      auditPlans.map(async (plan) =>
        base64UrlEncode(await resolveRangePlan(plan, nodes)),
      ),
    ),
  };
}

export async function verifyMerkleInclusionProof(input: {
  leaf: BinaryInput;
  leafIndex: number;
  treeSize: number;
  auditPath: Array<string | Uint8Array>;
  expectedRootHash: string | Uint8Array;
}): Promise<boolean> {
  return verifyMerkleLeafHashInclusion({
    leafHash: await merkleLeafHash(input.leaf),
    leafIndex: input.leafIndex,
    treeSize: input.treeSize,
    auditPath: input.auditPath,
    expectedRootHash: input.expectedRootHash,
  });
}

export async function verifyMerkleLeafHashInclusion(input: {
  leafHash: string | Uint8Array;
  leafIndex: number;
  treeSize: number;
  auditPath: Array<string | Uint8Array>;
  expectedRootHash: string | Uint8Array;
}): Promise<boolean> {
  if (
    !Number.isSafeInteger(input.treeSize) ||
    input.treeSize < 1 ||
    !Number.isSafeInteger(input.leafIndex) ||
    input.leafIndex < 0 ||
    input.leafIndex >= input.treeSize
  ) {
    return false;
  }

  try {
    const leafHash = digestBytes(input.leafHash);
    const proof = input.auditPath.map(digestBytes);
    const cursor = { value: 0 };
    const root = await reconstructRoot(
      leafHash,
      input.leafIndex,
      input.treeSize,
      proof,
      cursor,
    );
    if (cursor.value !== proof.length) {
      return false;
    }
    return equalBytes(root, digestBytes(input.expectedRootHash));
  } catch {
    return false;
  }
}

/**
 * Verifies an RFC 6962 consistency proof between two Merkle tree roots.
 * Returns false for malformed roots, malformed paths, invalid sizes, truncated
 * proofs, and proofs with unused trailing nodes.
 */
export async function verifyMerkleConsistencyProof(input: {
  firstTreeSize: number;
  secondTreeSize: number;
  firstRootHash: string | Uint8Array;
  secondRootHash: string | Uint8Array;
  auditPath: Array<string | Uint8Array>;
}): Promise<boolean> {
  if (
    !Number.isSafeInteger(input.firstTreeSize) ||
    !Number.isSafeInteger(input.secondTreeSize) ||
    input.firstTreeSize < 0 ||
    input.secondTreeSize < 0 ||
    input.firstTreeSize > input.secondTreeSize
  ) {
    return false;
  }

  try {
    const firstRoot = digestBytes(input.firstRootHash);
    const secondRoot = digestBytes(input.secondRootHash);
    const proof = input.auditPath.map(digestBytes);

    if (input.firstTreeSize === 0) {
      const emptyRoot = await emptyMerkleRoot();
      return (
        proof.length === 0 &&
        equalBytes(firstRoot, emptyRoot) &&
        (input.secondTreeSize !== 0 || equalBytes(secondRoot, emptyRoot))
      );
    }

    if (input.firstTreeSize === input.secondTreeSize) {
      return proof.length === 0 && equalBytes(firstRoot, secondRoot);
    }

    if (proof.length === 0) {
      return false;
    }

    // RFC 9162 section 2.1.4.2 makes the implicit known subtree explicit for
    // exact powers of two by prepending the first tree root.
    const path = isPowerOfTwo(input.firstTreeSize) ? [firstRoot, ...proof] : proof;
    let firstNode = input.firstTreeSize - 1;
    let secondNode = input.secondTreeSize - 1;
    while (isOdd(firstNode)) {
      firstNode = parentIndex(firstNode);
      secondNode = parentIndex(secondNode);
    }

    let firstReconstructed = path[0];
    let secondReconstructed = path[0];
    if (!firstReconstructed || !secondReconstructed) {
      return false;
    }

    for (let index = 1; index < path.length; index += 1) {
      const node = path[index];
      if (!node || secondNode === 0) {
        return false;
      }

      if (isOdd(firstNode) || firstNode === secondNode) {
        firstReconstructed = await merkleNodeHash(node, firstReconstructed);
        secondReconstructed = await merkleNodeHash(node, secondReconstructed);

        if (!isOdd(firstNode)) {
          while (firstNode !== 0 && !isOdd(firstNode)) {
            firstNode = parentIndex(firstNode);
            secondNode = parentIndex(secondNode);
          }
        }
      } else {
        secondReconstructed = await merkleNodeHash(secondReconstructed, node);
      }

      firstNode = parentIndex(firstNode);
      secondNode = parentIndex(secondNode);
    }

    return (
      secondNode === 0 &&
      equalBytes(firstReconstructed, firstRoot) &&
      equalBytes(secondReconstructed, secondRoot)
    );
  } catch {
    return false;
  }
}

async function subtreeRoot(hashes: Uint8Array[]): Promise<Uint8Array> {
  if (hashes.length === 0) {
    return emptyMerkleRoot();
  }
  if (hashes.length === 1) {
    return hashes[0];
  }
  const split = largestPowerOfTwoLessThan(hashes.length);
  return merkleNodeHash(
    await subtreeRoot(hashes.slice(0, split)),
    await subtreeRoot(hashes.slice(split)),
  );
}

async function buildAuditPath(
  hashes: Uint8Array[],
  index: number,
): Promise<Uint8Array[]> {
  if (hashes.length === 1) {
    return [];
  }
  const split = largestPowerOfTwoLessThan(hashes.length);
  if (index < split) {
    return [
      ...(await buildAuditPath(hashes.slice(0, split), index)),
      await subtreeRoot(hashes.slice(split)),
    ];
  }
  return [
    ...(await buildAuditPath(hashes.slice(split), index - split)),
    await subtreeRoot(hashes.slice(0, split)),
  ];
}

async function buildConsistencyPath(
  hashes: Uint8Array[],
  firstTreeSize: number,
  completeSubtree: boolean,
): Promise<Uint8Array[]> {
  if (firstTreeSize === hashes.length) {
    return completeSubtree ? [] : [await subtreeRoot(hashes)];
  }

  const split = largestPowerOfTwoLessThan(hashes.length);
  if (firstTreeSize <= split) {
    return [
      ...(await buildConsistencyPath(
        hashes.slice(0, split),
        firstTreeSize,
        completeSubtree,
      )),
      await subtreeRoot(hashes.slice(split)),
    ];
  }

  return [
    ...(await buildConsistencyPath(hashes.slice(split), firstTreeSize - split, false)),
    await subtreeRoot(hashes.slice(0, split)),
  ];
}

type MerkleRangePlan =
  | {
      coordinate: MerkleNodeCoordinate;
      kind: "node";
    }
  | {
      kind: "branch";
      left: MerkleRangePlan;
      right: MerkleRangePlan;
    };

function planRangeRoot(start: number, size: number): MerkleRangePlan {
  if (
    !Number.isSafeInteger(start) ||
    start < 0 ||
    !Number.isSafeInteger(size) ||
    size < 1 ||
    start + size > Number.MAX_SAFE_INTEGER
  ) {
    throw new RangeError("Merkle range must use safe non-negative integers");
  }
  if (isPowerOfTwo(size) && start % size === 0) {
    return {
      kind: "node",
      coordinate: {
        level: Math.log2(size),
        nodeIndex: start / size,
      },
    };
  }
  const split = largestPowerOfTwoLessThan(size);
  return {
    kind: "branch",
    left: planRangeRoot(start, split),
    right: planRangeRoot(start + split, size - split),
  };
}

function buildStoredAuditPathPlans(
  start: number,
  size: number,
  relativeLeafIndex: number,
): MerkleRangePlan[] {
  if (size === 1) return [];
  const split = largestPowerOfTwoLessThan(size);
  if (relativeLeafIndex < split) {
    return [
      ...buildStoredAuditPathPlans(start, split, relativeLeafIndex),
      planRangeRoot(start + split, size - split),
    ];
  }
  return [
    ...buildStoredAuditPathPlans(
      start + split,
      size - split,
      relativeLeafIndex - split,
    ),
    planRangeRoot(start, split),
  ];
}

function buildStoredConsistencyPathPlans(
  start: number,
  size: number,
  firstTreeSize: number,
  completeSubtree: boolean,
): MerkleRangePlan[] {
  if (firstTreeSize === size) {
    return completeSubtree ? [] : [planRangeRoot(start, size)];
  }
  const split = largestPowerOfTwoLessThan(size);
  if (firstTreeSize <= split) {
    return [
      ...buildStoredConsistencyPathPlans(start, split, firstTreeSize, completeSubtree),
      planRangeRoot(start + split, size - split),
    ];
  }
  return [
    ...buildStoredConsistencyPathPlans(
      start + split,
      size - split,
      firstTreeSize - split,
      false,
    ),
    planRangeRoot(start, split),
  ];
}

async function loadPlannedNodes(plans: MerkleRangePlan[], loader: MerkleNodeLoader) {
  const requested = new Map<string, MerkleNodeCoordinate>();
  for (const plan of plans) collectPlanCoordinates(plan, requested);
  const coordinates = [...requested.values()].sort(
    (left, right) => left.level - right.level || left.nodeIndex - right.nodeIndex,
  );
  const loaded = await loader(coordinates);
  const result = new Map<string, Uint8Array>();
  for (const node of loaded) {
    assertCoordinate(node);
    const key = merkleCoordinateKey(node);
    if (!requested.has(key) || result.has(key)) {
      throw new Error("Merkle node loader returned an unexpected node");
    }
    result.set(key, digestBytes(node.hash));
  }
  if (result.size !== requested.size) {
    throw new Error("Merkle node store is incomplete");
  }
  return result;
}

function collectPlanCoordinates(
  plan: MerkleRangePlan,
  coordinates: Map<string, MerkleNodeCoordinate>,
) {
  if (plan.kind === "node") {
    coordinates.set(merkleCoordinateKey(plan.coordinate), plan.coordinate);
    return;
  }
  collectPlanCoordinates(plan.left, coordinates);
  collectPlanCoordinates(plan.right, coordinates);
}

async function resolveRangePlan(
  plan: MerkleRangePlan,
  nodes: ReadonlyMap<string, Uint8Array>,
): Promise<Uint8Array> {
  if (plan.kind === "node") {
    const node = nodes.get(merkleCoordinateKey(plan.coordinate));
    if (!node) throw new Error("Merkle node store is incomplete");
    return node;
  }
  return merkleNodeHash(
    await resolveRangePlan(plan.left, nodes),
    await resolveRangePlan(plan.right, nodes),
  );
}

function merkleCoordinateKey(coordinate: MerkleNodeCoordinate) {
  return `${coordinate.level}:${coordinate.nodeIndex}`;
}

function assertCoordinate(coordinate: MerkleNodeCoordinate) {
  if (
    !Number.isSafeInteger(coordinate.level) ||
    coordinate.level < 0 ||
    !Number.isSafeInteger(coordinate.nodeIndex) ||
    coordinate.nodeIndex < 0
  ) {
    throw new TypeError("Merkle node coordinate is invalid");
  }
}

function assertTreeSize(treeSize: number, allowEmpty: boolean) {
  if (!Number.isSafeInteger(treeSize) || treeSize < (allowEmpty ? 0 : 1)) {
    throw new RangeError("treeSize is invalid");
  }
}

async function reconstructRoot(
  leafHash: Uint8Array,
  index: number,
  size: number,
  proof: Uint8Array[],
  cursor: { value: number },
): Promise<Uint8Array> {
  if (size === 1) {
    return leafHash;
  }
  const split = largestPowerOfTwoLessThan(size);
  if (index < split) {
    const child = await reconstructRoot(leafHash, index, split, proof, cursor);
    const sibling = nextProofNode(proof, cursor);
    return merkleNodeHash(child, sibling);
  }
  const child = await reconstructRoot(
    leafHash,
    index - split,
    size - split,
    proof,
    cursor,
  );
  const sibling = nextProofNode(proof, cursor);
  return merkleNodeHash(sibling, child);
}

function nextProofNode(proof: Uint8Array[], cursor: { value: number }) {
  const node = proof[cursor.value];
  if (!node) {
    throw new RangeError("Inclusion proof is too short");
  }
  cursor.value += 1;
  return node;
}

function largestPowerOfTwoLessThan(value: number) {
  let power = 1;
  while (power * 2 < value) {
    power *= 2;
  }
  return power;
}

function isPowerOfTwo(value: number) {
  if (!Number.isSafeInteger(value) || value < 1) return false;
  let remainder = value;
  while (!isOdd(remainder)) remainder = parentIndex(remainder);
  return remainder === 1;
}

function isOdd(value: number) {
  return value % 2 === 1;
}

function parentIndex(value: number) {
  return Math.floor(value / 2);
}

function digestBytes(value: string | Uint8Array) {
  const bytes = typeof value === "string" ? base64UrlDecode(value) : value;
  assertDigest(bytes, "digest");
  return bytes;
}

function assertDigest(value: Uint8Array, label: string) {
  if (value.length !== 32) {
    throw new TypeError(`${label} must be a SHA-256 digest`);
  }
}
