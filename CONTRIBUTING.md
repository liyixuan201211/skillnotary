# Contributing

Thanks for taking a look. This is a small, opinionated codebase; the notes below
are the things that will get a pull request merged quickly.

## Getting started

No build step and no runtime dependencies.

```bash
git clone https://github.com/skillnotary/skillnotary
cd skillnotary
npm install          # only typescript + @types/node, both dev-only
node --test          # run the suite
npx tsc --noEmit     # typecheck
node src/cli.ts help # run the CLI from source
```

Node **≥ 23.6** is required because the package ships TypeScript and relies on
native type stripping.

## Before you open a PR

```bash
npm run check        # tests + typecheck
```

Both must pass. A pull request that adds behaviour without a test will be asked
for one.

## The rules this project holds itself to

These are load-bearing design constraints, not preferences. A change that
breaks one needs a very good argument.

1. **Zero runtime dependencies.** `dependencies` stays `{}`. The whole point is
   that the supply-chain tool is not its own supply-chain risk.
2. **Never trust the reviewed artefact.** A skill, a manifest and a lockfile are
   all attacker-writable. Anything security-relevant must be re-derived from
   fresh observation, not read out of a file the adversary can edit.
3. **Never follow a symlink** out of a skill directory.
4. **Never let untrusted bytes reach a terminal verbatim** — use
   `sanitizeForTerminal`.
5. **Never cause unbounded work.** Every read, walk and match is capped, and
   truncation is reported rather than silent.
6. **Never default a security-relevant field.** Missing means error.
7. **Suppression is never silent.** If a finding is dropped, say so and say by
   what.
8. **Low false positives.** Security tooling that cries wolf gets switched off.
   Round-tripping `test/fixtures/benign` at zero findings is a hard requirement.

## Adding a detection rule

1. Add the rule to `RULES` in `src/patterns.ts` with a stable id, a severity, a
   `scope` (`code`, `prose` or `any`) and, where applicable, the capability it
   demonstrates.
2. Scope it correctly. A URL in prose is documentation; a URL in a ` ```bash `
   block is network access. Mis-scoping is the usual cause of false positives.
3. If the phrasing is ambiguous in both directions, add a `suppressIf` guard
   (see `R022`, where "do not act without asking" is a *safety* instruction).
4. Add a test in `test/security-fixes.test.ts` or `test/analyze.test.ts`
   asserting both that it fires on the bad case **and** that it stays quiet on
   the benign one.
5. Document it in the README's rule list.

Capability-only signals (things that should enrich the capability set without
raising a finding) use `capabilityOnly: true`.

## Adding a policy rule

Policy rules live in `src/policy.ts` (`Pxxx`) and take plain data, so they are
directly unit-testable — see `test/policy.test.ts`. If the rule needs new
inputs, extend `PolicyInput` rather than reaching for the filesystem.

## Changing the lockfile or attestation format

Both are consumed by other people's CI and by signatures, so:

- treat the on-disk format as a public interface;
- if you change the shape, keep reading the old one (see how `verifyPayload`
  still accepts `skillnotary/attestation@1`);
- `src/lockfile.ts` (`normalizeLockfile`) is the validation boundary — every new
  field must be validated there.

## Commit messages

Conventional-commit style prefixes, and explain *why* in the body:

```
fix(apply): check the installed copy against the source, not the lockfile

--force exists precisely because those two differ, so the post-copy
verification could never pass.
```

## Reporting a security issue

Please do not open a public issue — see [SECURITY.md](SECURITY.md).

## Code style

- Comments explain *why*, not *what*.
- Prefer a small pure function with a test over a clever one without.
- Keep the CLI thin: logic belongs in the modules, and `src/index.ts` exports
  everything the CLI can do.
