# Conformance vectors

`vectors/v3/canonicalization.json` is deterministic, public-only test data. It
contains no private keys, reusable credentials, identity evidence, or live
attestations.

Each case provides:

- an I-JSON input value;
- the exact RFC 8785 canonical JSON text;
- the SHA-256 digest in unpadded base64url; and
- the SHA-256 digest in lowercase hexadecimal.

The vote-event and active-directory checkpoint cases are also passed through
their exact V3 structural validators. The question-log case proves the exact
domain-separated deterministic log identifier.
Run:

```sh
bun run vectors
```

A conforming implementation must produce byte-for-byte identical canonical text
and both digests. It must not Unicode-normalize strings, accept sparse arrays or
non-finite numbers, retain insignificant whitespace, or reorder keys by locale.

Conformance vectors are evidence for deterministic interoperability, not trust
anchors and not production examples. Never add private key material, production
tokens, personal data, or environment-specific secrets.
