# Contributing

Contributions that improve the current V3 implementation, documentation,
interoperability, or security are welcome.

## Set up the workspace

Install Bun 1.3.12 and Node.js 20 or newer, then run:

```sh
bun install --frozen-lockfile
bun run check
```

Use `bun run format` for mechanical formatting. Before opening a pull request,
run the complete local pipeline:

```sh
bun run ci
bun run audit
bun run gitleaks
```

## Change requirements

- Keep public schema objects exact: reject unknown fields instead of ignoring
  them.
- Preserve deterministic RFC 8785 canonicalization and existing signed bytes.
- Treat policy digests and public-key history as independently anchored inputs.
- Add negative tests for malformed encodings and altered trust bindings.
- Add or update a public-only conformance vector when observable canonical bytes
  change.
- Do not commit credentials, private voter data, production certificates, or
  private signing material.
- Keep runtime dependencies minimal and explain any addition in the pull request.

Protocol-incompatible changes need an explicit versioning proposal. Do not
reinterpret an existing schema string.

## Pull requests

Keep a pull request focused and describe its security and compatibility impact.
Document any new trust assumption. Generated `dist/` files and package tarballs
are intentionally excluded from source control.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
