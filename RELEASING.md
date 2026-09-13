# Releasing

The package is pre-1.0, so the only rule is: **never reuse a version number.**
npm will not let you overwrite a published version, and unpublishing is
restricted.

## Prerequisites

```bash
npm login          # you must be logged in; CI has no publish token
npm whoami         # should print your npm username
```

Two-factor auth should be enabled on the npm account; publishing will prompt.

## 1. Pre-flight

```bash
npm run check      # node --test + tsc --noEmit, both must pass
```

`prepublishOnly` runs the same thing, so a broken tree cannot be published — but
run it yourself first so you find out before the tag exists.

Confirm the tarball contents. This is the last cheap moment to notice that you
are about to ship test fixtures, a keyfile, or a stray directory:

```bash
npm pack --dry-run
```

Expected: ~24 files, all under `src/` plus the docs and `package.json`. Nothing
from `test/`, `demo/` or `.github/` should appear. If a `skillnotary.key.json`
appears, stop — `.gitignore` and the `files` allowlist both failed.

## 2. Version and changelog

```bash
# bump version in package.json (and package-lock.json)
npm version 0.2.1 --no-git-tag-version

# move the CHANGELOG's "Unreleased" entries under the new heading
$EDITOR CHANGELOG.md
```

Use [Semantic Versioning](https://semver.org/spec/v2.0.0.html). For this project
specifically:

- **patch** — detection rules, messages, bug fixes;
- **minor** — new commands, new policy rules, new config keys, anything that
  widens the lockfile or attestation format (which must stay backward-readable);
- **major** — a change that stops an existing `skills.lock` or attestation from
  verifying, or that changes default enforcement in a way that breaks CI.

## 3. Publish

```bash
npm publish --access public
```

Then verify what the registry actually has:

```bash
npm view skillnotary version dist.tarball
npx --yes skillnotary@latest --version
```

## 4. Post-publish

1. **Add the npm badge** to the top of `README.md` (it 404s before the first
   publish, which is why it is not there yet):

   ```markdown
   [![npm](https://img.shields.io/npm/v/skillnotary.svg)](https://www.npmjs.com/package/skillnotary)
   ```

2. **Tag and release on GitHub**:

   ```bash
   git add -A && git commit -m "release: v0.2.1"
   git tag -a v0.2.1 -m "v0.2.1"
   git push origin main --follow-tags
   gh release create v0.2.1 --title "v0.2.1" --notes-from-tag
   ```

3. **Pin the action in the README** if a `v0.2.x` tag should be referenced
   instead of `@v0.2.0`.

## What must never be committed

- `skillnotary.key.json` — a generated ed25519 private key. `.gitignore`
  excludes it; keep it that way.
- Any real `skills.lock.attestation.json` you would not want public is fine to
  commit, but check it does not carry an unexpected path or key id.

## If a release goes wrong

- **Wrong contents published** — publish a new patch version. Do not try to
  overwrite; you cannot.
- **A security fix is needed** — ship the patch first, then open a GitHub
  Security Advisory and credit the reporter (see `SECURITY.md`).
- **A detection rule is causing false positives in the wild** — users can
  mitigate immediately with `rules: { "R0xx": "off" }` in
  `skillnotary.config.json`; mention that in the release notes and then ship the
  narrowed rule.
