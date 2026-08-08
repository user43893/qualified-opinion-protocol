/** JSON values accepted by the Qualified Opinion protocol. */
export type JsonPrimitive = null | boolean | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

/**
 * Canonicalizes an I-JSON value using the rules in RFC 8785 (JCS).
 *
 * Protocol payloads deliberately reject JavaScript-only values, sparse arrays,
 * custom prototypes, non-finite numbers and unpaired UTF-16 surrogates instead
 * of silently applying JSON.stringify's lossy conversions.
 */
export function canonicalizeJson(value: unknown): string {
  return serialize(value, new Set<object>(), "$");
}

function serialize(value: unknown, ancestors: Set<object>, path: string): string {
  if (value === null) {
    return "null";
  }

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number": {
      if (!Number.isFinite(value)) {
        throw new TypeError(`${path}: non-finite numbers are not valid I-JSON`);
      }
      return JSON.stringify(value);
    }
    case "string":
      assertWellFormedUnicode(value, path);
      return JSON.stringify(value);
    case "object":
      break;
    default:
      throw new TypeError(`${path}: ${typeof value} is not a JSON value`);
  }

  if (ancestors.has(value)) {
    throw new TypeError(`${path}: cyclic values cannot be canonicalized`);
  }
  ancestors.add(value);

  try {
    if (Array.isArray(value)) {
      const entries: string[] = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(value, index)) {
          throw new TypeError(`${path}[${index}]: sparse arrays are not I-JSON`);
        }
        entries.push(serialize(value[index], ancestors, `${path}[${index}]`));
      }
      return `[${entries.join(",")}]`;
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError(`${path}: only plain JSON objects are supported`);
    }
    if (Object.getOwnPropertySymbols(value).length > 0) {
      throw new TypeError(`${path}: symbol properties are not valid JSON`);
    }

    const object = value as Record<string, unknown>;
    const keys = Object.keys(object).sort(compareUtf16CodeUnits);
    const members = keys.map((key) => {
      assertWellFormedUnicode(key, `${path} property name`);
      return `${JSON.stringify(key)}:${serialize(object[key], ancestors, `${path}.${key}`)}`;
    });
    return `{${members.join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

function compareUtf16CodeUnits(left: string, right: string) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function assertWellFormedUnicode(value: string, path: string) {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new TypeError(`${path}: unpaired high surrogate`);
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw new TypeError(`${path}: unpaired low surrogate`);
    }
  }
}
