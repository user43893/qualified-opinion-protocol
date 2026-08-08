import { canonicalizeJson } from "./canonical";

const BASE64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export type BinaryInput = string | Uint8Array;

export function utf8Encode(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

export function utf8Decode(value: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(value);
}

export function concatBytes(...values: Uint8Array[]): Uint8Array {
  const length = values.reduce((total, value) => total + value.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.length;
  }
  return output;
}

export function base64UrlEncode(value: Uint8Array): string {
  let output = "";
  for (let index = 0; index < value.length; index += 3) {
    const first = value[index] ?? 0;
    const second = value[index + 1] ?? 0;
    const third = value[index + 2] ?? 0;
    const packed = (first << 16) | (second << 8) | third;
    const remaining = value.length - index;

    output += BASE64_ALPHABET[(packed >>> 18) & 63];
    output += BASE64_ALPHABET[(packed >>> 12) & 63];
    if (remaining > 1) {
      output += BASE64_ALPHABET[(packed >>> 6) & 63];
    }
    if (remaining > 2) {
      output += BASE64_ALPHABET[packed & 63];
    }
  }
  return output.replace(/\+/g, "-").replace(/\//g, "_");
}

export function base64UrlDecode(value: string): Uint8Array {
  if (!isBase64Url(value)) {
    throw new TypeError("Invalid unpadded base64url value");
  }
  const standard = value.replace(/-/g, "+").replace(/_/g, "/");
  const outputLength = Math.floor((standard.length * 6) / 8);
  const output = new Uint8Array(outputLength);
  let buffer = 0;
  let bits = 0;
  let outputIndex = 0;

  for (const character of standard) {
    const digit = BASE64_ALPHABET.indexOf(character);
    buffer = buffer * 64 + digit;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      output[outputIndex] = (buffer >>> bits) & 0xff;
      outputIndex += 1;
      buffer &= (1 << bits) - 1;
    }
  }

  if (bits > 0 && buffer !== 0) {
    throw new TypeError("Invalid base64url trailing bits");
  }
  return output;
}

export function isBase64Url(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^[A-Za-z0-9_-]*$/.test(value) &&
    value.length % 4 !== 1
  );
}

export function hexEncode(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function hexDecode(value: string): Uint8Array {
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(value)) {
    throw new TypeError("Invalid hexadecimal value");
  }
  const output = new Uint8Array(value.length / 2);
  for (let index = 0; index < value.length; index += 2) {
    output[index / 2] = Number.parseInt(value.slice(index, index + 2), 16);
  }
  return output;
}

export function toBytes(value: BinaryInput): Uint8Array {
  return typeof value === "string" ? utf8Encode(value) : value;
}

export async function sha256Bytes(value: BinaryInput): Promise<Uint8Array> {
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    toBytes(value).slice(),
  );
  return new Uint8Array(digest);
}

export async function sha256Base64Url(value: BinaryInput): Promise<string> {
  return base64UrlEncode(await sha256Bytes(value));
}

export async function sha256Hex(value: BinaryInput): Promise<string> {
  return hexEncode(await sha256Bytes(value));
}

export async function canonicalJsonSha256(value: unknown): Promise<string> {
  return sha256Base64Url(canonicalizeJson(value));
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  let difference = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

export function isSha256Base64Url(value: unknown): value is string {
  if (!isBase64Url(value)) {
    return false;
  }
  try {
    return base64UrlDecode(value).length === 32;
  } catch {
    return false;
  }
}
