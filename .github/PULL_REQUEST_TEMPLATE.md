## Summary

Describe the change and why it is needed.

## Security and compatibility

- [ ] Signed bytes and schema meanings are unchanged, or the compatibility impact
      is explicitly documented.
- [ ] Trust assumptions and policy changes are documented.
- [ ] No private voter data, credentials, production tokens, or private keys are
      included.
- [ ] Tests cover malformed and adversarial inputs where relevant.
- [ ] Public-only conformance vectors are updated when observable bytes change.

## Validation

- [ ] `bun run ci`
- [ ] `bun run audit`
- [ ] `bun run gitleaks`
