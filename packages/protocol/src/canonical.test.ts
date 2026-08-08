import { describe, expect, test } from "bun:test";
import { canonicalizeJson } from "./canonical";
import {
  base64UrlDecode,
  base64UrlEncode,
  canonicalJsonSha256,
  hexEncode,
  sha256Bytes,
  utf8Decode,
  utf8Encode,
} from "./encoding";

describe("RFC 8785 canonical JSON", () => {
  test("sorts object keys recursively and preserves array order", () => {
    expect(canonicalizeJson({ z: 0, a: { y: 2, x: 1 }, list: [3, 2, 1] })).toBe(
      '{"a":{"x":1,"y":2},"list":[3,2,1],"z":0}',
    );
  });

  test("uses ECMAScript number and string serialization", () => {
    expect(
      canonicalizeJson({
        numbers: [Number("333333333.33333329"), 1e30, 4.5, 0.002, 1e-27, -0],
        string: "€\u000f\nA'B\"\\/",
      }),
    ).toBe(
      '{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27,0],"string":"€\\u000f\\nA\'B\\"\\\\/"}',
    );
  });

  test("sorts keys by UTF-16 code units rather than locale", () => {
    expect(canonicalizeJson({ ä: 1, z: 2, A: 3 })).toBe('{"A":3,"z":2,"ä":1}');
  });

  test("rejects lossy and non-I-JSON values", () => {
    expect(() => canonicalizeJson({ bad: undefined })).toThrow();
    const sparse = new Array(2);
    sparse[1] = 1;
    expect(() => canonicalizeJson(sparse)).toThrow();
    expect(() => canonicalizeJson(Number.NaN)).toThrow();
    expect(() => canonicalizeJson({ date: new Date() })).toThrow();
    expect(() => canonicalizeJson("\ud800")).toThrow();
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => canonicalizeJson(cyclic)).toThrow();
  });
});

describe("portable encoding and hashing", () => {
  test("round-trips binary values through strict unpadded base64url", () => {
    const bytes = new Uint8Array([0, 1, 2, 253, 254, 255]);
    const encoded = base64UrlEncode(bytes);
    expect(encoded).toBe("AAEC_f7_");
    expect(base64UrlDecode(encoded)).toEqual(bytes);
    expect(() => base64UrlDecode("a===")).toThrow();
  });

  test("matches the standard SHA-256 vector for abc", async () => {
    const digest = await sha256Bytes("abc");
    expect(hexEncode(digest)).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    expect(base64UrlEncode(digest)).toBe("ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
  });

  test("hashes canonical JSON independent of insertion order", async () => {
    expect(await canonicalJsonSha256({ b: 2, a: 1 })).toBe(
      await canonicalJsonSha256({ a: 1, b: 2 }),
    );
    expect(utf8Decode(utf8Encode("Qualified Opinion"))).toBe("Qualified Opinion");
  });
});
