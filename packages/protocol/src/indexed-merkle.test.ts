import { describe, expect, test } from "bun:test";
import {
  type MerkleNodeCoordinate,
  type StoredMerkleNode,
  base64UrlEncode,
  computeMerkleRoot,
  computeStoredMerkleRoot,
  createMerkleConsistencyProof,
  createMerkleInclusionProof,
  createStoredMerkleConsistencyProof,
  createStoredMerkleInclusionProof,
  merkleLeafHash,
  merkleNodeHash,
} from "./index";

function key(node: MerkleNodeCoordinate) {
  return `${node.level}:${node.nodeIndex}`;
}

async function buildStore(leaves: string[]) {
  const store = new Map<string, StoredMerkleNode>();
  for (let leafIndex = 0; leafIndex < leaves.length; leafIndex += 1) {
    let level = 0;
    let nodeIndex = leafIndex;
    let hash = await merkleLeafHash(leaves[leafIndex] as string);
    store.set(key({ level, nodeIndex }), { level, nodeIndex, hash });
    while (nodeIndex % 2 === 1) {
      const left = store.get(key({ level, nodeIndex: nodeIndex - 1 }));
      if (!left) throw new Error("test store is incomplete");
      hash = await merkleNodeHash(
        typeof left.hash === "string" ? Buffer.from(left.hash) : left.hash,
        hash,
      );
      level += 1;
      nodeIndex = Math.floor(nodeIndex / 2);
      store.set(key({ level, nodeIndex }), { level, nodeIndex, hash });
    }
  }
  return store;
}

function loader(store: ReadonlyMap<string, StoredMerkleNode>) {
  return async (coordinates: MerkleNodeCoordinate[]) =>
    coordinates.flatMap((coordinate) => {
      const node = store.get(key(coordinate));
      return node ? [node] : [];
    });
}

describe("stored-subtree RFC 6962 proofs", () => {
  test("computes the empty root without consulting storage", async () => {
    let called = false;
    expect(
      base64UrlEncode(
        await computeStoredMerkleRoot({
          loadNodes: async () => {
            called = true;
            return [];
          },
          treeSize: 0,
        }),
      ),
    ).toBe(base64UrlEncode(await computeMerkleRoot([])));
    expect(called).toBe(false);
  });

  test("matches full-prefix roots and proofs byte for byte for irregular trees", async () => {
    const leaves = Array.from({ length: 65 }, (_, index) => `leaf-${index}`);
    const store = await buildStore(leaves);
    const loadNodes = loader(store);
    for (const treeSize of [1, 2, 3, 5, 8, 13, 32, 63, 65]) {
      const currentLeaves = leaves.slice(0, treeSize);
      expect(
        base64UrlEncode(await computeStoredMerkleRoot({ loadNodes, treeSize })),
      ).toBe(base64UrlEncode(await computeMerkleRoot(currentLeaves)));
      for (const leafIndex of [0, Math.floor(treeSize / 2), treeSize - 1]) {
        expect(
          await createStoredMerkleInclusionProof({
            leafIndex,
            loadNodes,
            treeSize,
          }),
        ).toEqual(await createMerkleInclusionProof(currentLeaves, leafIndex));
      }
      for (const firstTreeSize of [0, 1, Math.floor(treeSize / 2), treeSize]) {
        expect(
          await createStoredMerkleConsistencyProof({
            firstTreeSize,
            loadNodes,
            secondTreeSize: treeSize,
          }),
        ).toEqual(await createMerkleConsistencyProof(currentLeaves, firstTreeSize));
      }
      expect(base64UrlEncode(await computeMerkleRoot(currentLeaves))).toBe(
        (
          await createStoredMerkleConsistencyProof({
            firstTreeSize: treeSize,
            loadNodes,
            secondTreeSize: treeSize,
          })
        ).secondRootHash,
      );
    }
  }, 30_000);

  test("matches every proof boundary in small trees", async () => {
    const leaves = Array.from({ length: 17 }, (_, index) => `edge-${index}`);
    const loadNodes = loader(await buildStore(leaves));
    for (let treeSize = 1; treeSize <= leaves.length; treeSize += 1) {
      const prefix = leaves.slice(0, treeSize);
      for (let leafIndex = 0; leafIndex < treeSize; leafIndex += 1) {
        expect(
          await createStoredMerkleInclusionProof({
            leafIndex,
            loadNodes,
            treeSize,
          }),
        ).toEqual(await createMerkleInclusionProof(prefix, leafIndex));
      }
      for (let firstTreeSize = 0; firstTreeSize <= treeSize; firstTreeSize += 1) {
        expect(
          await createStoredMerkleConsistencyProof({
            firstTreeSize,
            loadNodes,
            secondTreeSize: treeSize,
          }),
        ).toEqual(await createMerkleConsistencyProof(prefix, firstTreeSize));
      }
    }
  }, 30_000);

  test("loads a logarithmic number of nodes in one batch", async () => {
    const treeSize = 2 ** 30 - 1;
    const calls: MerkleNodeCoordinate[][] = [];
    const loadNodes = async (coordinates: MerkleNodeCoordinate[]) => {
      calls.push(coordinates);
      return coordinates.map((coordinate) => ({
        ...coordinate,
        hash: new Uint8Array(32).fill((coordinate.level + coordinate.nodeIndex) % 251),
      }));
    };
    await createStoredMerkleInclusionProof({
      leafIndex: Math.floor(treeSize / 3),
      loadNodes,
      treeSize,
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.length).toBeLessThanOrEqual(4 * Math.ceil(Math.log2(treeSize)));

    calls.length = 0;
    await createStoredMerkleConsistencyProof({
      firstTreeSize: Math.floor(treeSize / 3),
      loadNodes,
      secondTreeSize: treeSize,
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.length).toBeLessThanOrEqual(4 * Math.ceil(Math.log2(treeSize)));
  });

  test("fails closed when the node store is incomplete or equivocal", async () => {
    const store = await buildStore(["a", "b", "c"]);
    await expect(
      createStoredMerkleInclusionProof({
        leafIndex: 2,
        loadNodes: async () => [],
        treeSize: 3,
      }),
    ).rejects.toThrow("Merkle node store is incomplete");
    await expect(
      createStoredMerkleInclusionProof({
        leafIndex: 2,
        loadNodes: async (coordinates) => {
          const nodes = await loader(store)(coordinates);
          return nodes[0] ? [...nodes, nodes[0]] : nodes;
        },
        treeSize: 3,
      }),
    ).rejects.toThrow("unexpected node");
  });
});
