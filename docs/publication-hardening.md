# Post-public repository hardening

The publication repository remains private while release checks are completed.
The final visibility change emits GitHub's `public` event, which starts
`.github/workflows/post-public-hardening.yml` from the exact `main` commit.

Before changing visibility, store the existing owner token as the repository's
only Actions secret, named `PUBLICATION_HARDENING_TOKEN`. The token must be able
to administer this repository, read checks and metadata, inspect every inventory
listed below, delete repository Actions secrets, and disable Actions workflows.
The hardener accepts the owner token GitHub already issued; it does not require a
particular token prefix or token class. The workflow exposes the value only to
its final local apply step; checkout, tool setup, and source validation cannot
read it.

The hardener refuses to mutate the repository unless it proves all of the
following:

- the invocation is the first attempt of the automatic `public` run, or a new
  owner-confirmed manual fallback run;
- actor, owner, numeric owner and repository identities, public visibility,
  `main`, workflow source, and current commit match `PUBLICATION-HARDENING.json`;
- the token belongs to the exact owner and has administrator access to the
  repository;
- the collaborator inventory contains only that owner as administrator, there
  are no pending collaborator invitations, deploy keys, or repository rulesets,
  and the one-time token is the sole repository secret; and
- `CI / Build, test, and inspect packages` and
  `Secret Scan / Gitleaks 8.30.1 exact-tree scan` succeeded for that commit as
  checks created by GitHub Actions App ID `15368`.

It then applies the exact public description, homepage, topics, merge policy,
SHA-pinned selected-Actions policy, read-only workflow token, protected `main`,
required checks, signed commits, dependency alerts and security updates,
private vulnerability reporting, Advanced Security, secret scanning, and push
protection. Dependency-graph activation is checked through the supported
vulnerability-alert endpoint rather than an unsupported repository patch
field.

Mutations run once. Read-only re-audits are bounded to 24 attempts and two
minutes so GitHub settings can converge. Only an exact successful audit allows
the hardener to delete `PUBLICATION_HARDENING_TOKEN`, prove that the repository
secret inventory is empty, disable `.github/workflows/post-public-hardening.yml`,
and read the workflow back with the exact `disabled_manually` state. Retirement
is reported only after both proofs succeed. If the audit fails before
retirement, the secret remains so the underlying condition can be corrected and
a new fallback run can be dispatched:

```sh
gh workflow run post-public-hardening.yml \
  --repo konsensus-platform/qualified-opinion-protocol \
  --ref main \
  -f confirmation=harden-public-repository
```

Do not rerun an existing failed attempt. The source contract requires
`GITHUB_RUN_ATTEMPT=1`; use a fresh dispatch after correcting the reported
state. If a retirement request itself fails, restore the sole secret if GitHub
already deleted it, re-enable the hardening workflow if GitHub already disabled
it, and then use a fresh dispatch.

No local command in this repository publishes the repository or changes its
visibility.
