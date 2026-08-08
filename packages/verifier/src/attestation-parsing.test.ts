import { describe, expect, test } from "bun:test";
import { parseAttestationJwt } from "./attestation";

const threeSegmentToken = [
  Buffer.from(JSON.stringify({ alg: "RS256" })).toString("base64url"),
  Buffer.from(JSON.stringify({ iss: "issuer" })).toString("base64url"),
  Buffer.from("signature").toString("base64url"),
].join(".");

describe("attestation JWT parsing", () => {
  test("accepts exactly three segments", () => {
    expect(() => parseAttestationJwt(threeSegmentToken)).not.toThrow();
  });

  test("rejects an appended segment", () => {
    expect(() => parseAttestationJwt(`${threeSegmentToken}.unexpected`)).toThrow(
      "invalid_attestation_token",
    );
  });
});
