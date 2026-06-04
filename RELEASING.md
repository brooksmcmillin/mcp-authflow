# Releasing

Merging a PR does **not** publish a release. Changes accumulate under the
`## [Unreleased]` section of [CHANGELOG.md](CHANGELOG.md) and are promoted to a
version number only when we cut a release.

## When to release

- **Security fixes** — release immediately, on their own. Don't let a security
  change wait behind unrelated feature work.
- **Features / enhancements** — batch a few related changes into a minor
  (`0.x.0`) release rather than cutting one per PR.
- **Docs only, internal refactors, CI** — never trigger a release by
  themselves; they ride along with the next real release.

Rule of thumb: if you can't write a one-line changelog entry that gives a user
a reason to upgrade, it isn't a release yet — but if that line contains the
word "security," release it today.

While on `0.x`, breaking changes bump the **minor** version (e.g. `0.5.0` →
`0.6.0`); backwards-compatible changes bump the **patch** version.

## As you work

Every user-facing PR adds an entry under the appropriate subsection of
`## [Unreleased]` in `CHANGELOG.md` (`Added`, `Changed`, `Deprecated`,
`Removed`, `Fixed`, `Security`). Leave empty subsections in place — they are
the template for the next cycle.

## Cutting a release

1. Choose the new version number `X.Y.Z` based on the accumulated
   `[Unreleased]` entries (security/breaking → minor while on `0.x`).
2. In `CHANGELOG.md`, rename `## [Unreleased]` to `## X.Y.Z`, delete any empty
   subsections, and add a fresh `## [Unreleased]` template block above it.
3. Bump the version in `pyproject.toml` (`version = "..."`). This is the single
   source of truth: `mcp_authflow.__version__` reads it from installed
   package metadata at import time, so no other code file needs editing. (The
   `CHANGELOG.md` heading in step 2 is the only other place the number appears.)
4. Commit (`release: X.Y.Z`), tag (`git tag vX.Y.Z`), and push with
   `--follow-tags`.
5. Build and publish:
   ```bash
   uv build
   uv publish
   ```
6. Create the GitHub release from the tag, pasting the version's changelog
   section as the release notes.
