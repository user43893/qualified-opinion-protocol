import { describe, expect, test } from "bun:test";
import { base64UrlDecode, base64UrlEncode } from "./encoding";
import {
  computeMerkleRoot,
  createMerkleConsistencyProof,
  createMerkleInclusionProof,
  emptyMerkleRoot,
  verifyMerkleConsistencyProof,
  verifyMerkleInclusionProof,
} from "./merkle";
const leaves = ["a", "b", "c", "d", "e"];
const fiveLeafRoot = "_hSlQm-9cMD6c_UjQq_tDaC9I8SDhmLM9riKMHDq2Xs";

describe("RFC 6962 Merkle tree", () => {
  test("matches fixed empty and five-leaf roots", async () => {
    expect(base64UrlEncode(await computeMerkleRoot([]))).toBe(
      "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
    );
    expect(base64UrlEncode(await computeMerkleRoot(leaves))).toBe(fiveLeafRoot);
  });

  test("creates and verifies an inclusion proof for every leaf", async () => {
    for (let index = 0; index < leaves.length; index += 1) {
      const proof = await createMerkleInclusionProof(leaves, index);
      expect(
        await verifyMerkleInclusionProof({
          leaf: leaves[index],
          leafIndex: proof.leafIndex,
          treeSize: proof.treeSize,
          auditPath: proof.auditPath,
          expectedRootHash: proof.rootHash,
        }),
      ).toBe(true);
    }
  });

  test("rejects tampered leaves, paths, indexes and roots", async () => {
    const proof = await createMerkleInclusionProof(leaves, 2);
    expect(
      await verifyMerkleInclusionProof({
        leaf: "tampered",
        leafIndex: proof.leafIndex,
        treeSize: proof.treeSize,
        auditPath: proof.auditPath,
        expectedRootHash: proof.rootHash,
      }),
    ).toBe(false);
    expect(
      await verifyMerkleInclusionProof({
        leaf: leaves[2],
        leafIndex: 99,
        treeSize: proof.treeSize,
        auditPath: proof.auditPath,
        expectedRootHash: proof.rootHash,
      }),
    ).toBe(false);
    expect(
      await verifyMerkleInclusionProof({
        leaf: leaves[2],
        leafIndex: proof.leafIndex,
        treeSize: proof.treeSize,
        auditPath: [...proof.auditPath, proof.auditPath[0]],
        expectedRootHash: proof.rootHash,
      }),
    ).toBe(false);
  });

  test("creates and verifies consistency proofs for every tree-size pair", async () => {
    const exhaustiveLeaves = Array.from({ length: 32 }, (_, index) => `leaf-${index}`);

    for (
      let secondTreeSize = 0;
      secondTreeSize <= exhaustiveLeaves.length;
      secondTreeSize += 1
    ) {
      const currentLeaves = exhaustiveLeaves.slice(0, secondTreeSize);
      for (let firstTreeSize = 0; firstTreeSize <= secondTreeSize; firstTreeSize += 1) {
        const proof = await createMerkleConsistencyProof(currentLeaves, firstTreeSize);
        expect(proof.firstTreeSize).toBe(firstTreeSize);
        expect(proof.secondTreeSize).toBe(secondTreeSize);
        expect(proof.firstRootHash).toBe(
          base64UrlEncode(
            await computeMerkleRoot(currentLeaves.slice(0, firstTreeSize)),
          ),
        );
        expect(proof.secondRootHash).toBe(
          base64UrlEncode(await computeMerkleRoot(currentLeaves)),
        );
        expect(await verifyMerkleConsistencyProof(proof)).toBe(true);
      }
    }
  }, 60_000);

  test("matches deterministic RFC example proof shapes", async () => {
    const exampleLeaves = Array.from({ length: 7 }, (_, index) => `d${index}`);

    const fromThree = await createMerkleConsistencyProof(exampleLeaves, 3);
    const fromFour = await createMerkleConsistencyProof(exampleLeaves, 4);
    const fromSix = await createMerkleConsistencyProof(exampleLeaves, 6);

    expect(fromThree).toEqual({
      firstTreeSize: 3,
      secondTreeSize: 7,
      firstRootHash: "xkxbkyaVGi24LVRiVlaWKGZZ0cekomqScDVo9jRi97o",
      secondRootHash: "c6WQ-yZrgVVwQLFGudR54qG1hJsSUWdkL1tkhm8dXH0",
      auditPath: [
        "82bfRxjvdQZDF3lP9TAOCWPpbdk_4kIDEYBV-loAvhM",
        "XgxOETDfqE0nQ3ugc-uBfhiWZD1C6hAKCUD4dS1JZ4M",
        "RseHCEE6IxdfUfrxwiYEvMtESC1VO0WUOxiRMOqCIcg",
        "PPBf8W0mwCSCjpOzoUxWVuWry8Xm8Lziz4oWlyBZlnQ",
      ],
    });
    expect(fromFour).toEqual({
      firstTreeSize: 4,
      secondTreeSize: 7,
      firstRootHash: "jfOHCzP65lDoGTiZT5jrRVGxQ7hsldPa5OZETgBxUBY",
      secondRootHash: "c6WQ-yZrgVVwQLFGudR54qG1hJsSUWdkL1tkhm8dXH0",
      auditPath: ["PPBf8W0mwCSCjpOzoUxWVuWry8Xm8Lziz4oWlyBZlnQ"],
    });
    expect(fromSix).toEqual({
      firstTreeSize: 6,
      secondTreeSize: 7,
      firstRootHash: "tlNozR8CRzLCHp24a83ifX3pXcLEDXKN2Xn_z5Q1VuM",
      secondRootHash: "c6WQ-yZrgVVwQLFGudR54qG1hJsSUWdkL1tkhm8dXH0",
      auditPath: [
        "pPKoR8zg3OBRmx1rg-TKFRZhk9uwyPhk5zZmXtveGZQ",
        "11DKki-rxUIu7EadQ3B3m2HVSIGGy4ce7qKZ2BE9ILw",
        "jfOHCzP65lDoGTiZT5jrRVGxQ7hsldPa5OZETgBxUBY",
      ],
    });
  });

  test("rejects every mutated proof node and root", async () => {
    const adversarialLeaves = Array.from(
      { length: 17 },
      (_, index) => `adversarial-${index}`,
    );

    for (
      let firstTreeSize = 1;
      firstTreeSize < adversarialLeaves.length;
      firstTreeSize += 1
    ) {
      const proof = await createMerkleConsistencyProof(
        adversarialLeaves,
        firstTreeSize,
      );
      expect(
        await verifyMerkleConsistencyProof({
          ...proof,
          firstRootHash: tamperDigest(proof.firstRootHash),
        }),
      ).toBe(false);
      expect(
        await verifyMerkleConsistencyProof({
          ...proof,
          secondRootHash: tamperDigest(proof.secondRootHash),
        }),
      ).toBe(false);
      expect(
        await verifyMerkleConsistencyProof({
          ...proof,
          auditPath: proof.auditPath.slice(0, -1),
        }),
      ).toBe(false);
      expect(
        await verifyMerkleConsistencyProof({
          ...proof,
          auditPath: [...proof.auditPath, proof.auditPath[0] as string],
        }),
      ).toBe(false);

      for (let index = 0; index < proof.auditPath.length; index += 1) {
        const auditPath = [...proof.auditPath];
        auditPath[index] = tamperDigest(auditPath[index] as string);
        expect(await verifyMerkleConsistencyProof({ ...proof, auditPath })).toBe(false);
      }
    }
  }, 30_000);

  test("rejects invalid consistency sizes, roots and boundary proofs", async () => {
    const proof = await createMerkleConsistencyProof(leaves, 3);
    const emptyRootHash = base64UrlEncode(await emptyMerkleRoot());
    const currentRootHash = base64UrlEncode(await computeMerkleRoot(leaves));
    const invalidSizes = [
      { firstTreeSize: -1, secondTreeSize: 5 },
      { firstTreeSize: 1.5, secondTreeSize: 5 },
      { firstTreeSize: 6, secondTreeSize: 5 },
      { firstTreeSize: 3, secondTreeSize: Number.MAX_SAFE_INTEGER + 1 },
      { firstTreeSize: Number.NaN, secondTreeSize: 5 },
    ];
    for (const sizes of invalidSizes) {
      expect(await verifyMerkleConsistencyProof({ ...proof, ...sizes })).toBe(false);
    }

    for (const invalidRoot of ["", "AA", "not+a+base64url+digest"] as const) {
      expect(
        await verifyMerkleConsistencyProof({
          ...proof,
          firstRootHash: invalidRoot,
        }),
      ).toBe(false);
      expect(
        await verifyMerkleConsistencyProof({
          ...proof,
          secondRootHash: invalidRoot,
        }),
      ).toBe(false);
    }
    expect(
      await verifyMerkleConsistencyProof({
        ...proof,
        auditPath: ["AA"],
      }),
    ).toBe(false);
    expect(
      await verifyMerkleConsistencyProof({
        ...proof,
        auditPath: [],
      }),
    ).toBe(false);

    expect(
      await verifyMerkleConsistencyProof({
        firstTreeSize: 0,
        secondTreeSize: leaves.length,
        firstRootHash: emptyRootHash,
        secondRootHash: currentRootHash,
        auditPath: [],
      }),
    ).toBe(true);
    expect(
      await verifyMerkleConsistencyProof({
        firstTreeSize: 0,
        secondTreeSize: leaves.length,
        firstRootHash: tamperDigest(emptyRootHash),
        secondRootHash: currentRootHash,
        auditPath: [],
      }),
    ).toBe(false);
    expect(
      await verifyMerkleConsistencyProof({
        firstTreeSize: 0,
        secondTreeSize: leaves.length,
        firstRootHash: emptyRootHash,
        secondRootHash: currentRootHash,
        auditPath: [currentRootHash],
      }),
    ).toBe(false);

    expect(
      await verifyMerkleConsistencyProof({
        firstTreeSize: leaves.length,
        secondTreeSize: leaves.length,
        firstRootHash: currentRootHash,
        secondRootHash: currentRootHash,
        auditPath: [],
      }),
    ).toBe(true);
    expect(
      await verifyMerkleConsistencyProof({
        firstTreeSize: leaves.length,
        secondTreeSize: leaves.length,
        firstRootHash: currentRootHash,
        secondRootHash: tamperDigest(currentRootHash),
        auditPath: [],
      }),
    ).toBe(false);
    expect(
      await verifyMerkleConsistencyProof({
        firstTreeSize: leaves.length,
        secondTreeSize: leaves.length,
        firstRootHash: currentRootHash,
        secondRootHash: currentRootHash,
        auditPath: [currentRootHash],
      }),
    ).toBe(false);
  });

  test("rejects invalid consistency proof creation sizes", async () => {
    await expect(createMerkleConsistencyProof(leaves, -1)).rejects.toThrow(RangeError);
    await expect(createMerkleConsistencyProof(leaves, 1.5)).rejects.toThrow(RangeError);
    await expect(createMerkleConsistencyProof(leaves, 6)).rejects.toThrow(RangeError);
  });
});

function tamperDigest(value: string) {
  const bytes = base64UrlDecode(value);
  bytes[0] = (bytes[0] ?? 0) ^ 0x01;
  return base64UrlEncode(bytes);
}
