# Changelog

All notable changes are recorded here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Rule R031** — a prose *instruction* to read or move credential material.
  `R003` is now code-scoped, because a security skill's own capability table
  necessarily quotes `~/.ssh` and `.env` without touching them; `R031` catches
  the instruction instead, and it is direction-aware, so "do not read the .env
  file" is not an access.
- **Rules R029 / R030** — shell file writes and shell file reads, as
  code-scoped capability signals. A leading `>` in prose is a blockquote and
  `cat` in prose is an animal, so neither implies `fs.write` / `fs.read` any
  more.
- **Rule-scoped ignore entries** — `"R003:reference/*"` drops one rule on one
  path, so a documentation exemption can be narrow instead of blinding a whole
  file.
- **`R001` names the file that exercises the capability**, so a rule-scoped
  ignore on a documentation directory can exempt the capability it documents.

### Fixed

- `--help` and `-h` exited `2`, while `help` exited `0`: a flag leaves no
  positional command, so the explicit-help case fell into the no-command branch
  and the documented `skillnotary --help` smoke test looked like a failure.
  Invoking with no command at all is still a usage error (`2`).
- The critical `R004` (secrets + network) rule had become unreachable from
  prose. With `R003` code-scoped, `R031` was the only prose observer of
  `secrets`, and three of its subject alternatives could never match because a
  leading `\b` cannot hold before `~` or `.`. Its verb list also missed the
  ordinary verbs an instruction uses (`check`, `load`, `echo`, `print`,
  `fetch`, `retrieve`, …), while a fuzzy `\w*` flagged unrelated words such as
  "category" and "copyright".
- A vetoed match no longer grants its capability: "do not read the .env file"
  is not secret access, so it cannot come back as `R001` / `R004`.
- `head -n` / `tail -n` were not recognised as shell reads; only the uncommon
  `head -20` spelling was.

## [0.2.0] — 2026-09-13

The "make it a tool, not just a report" release: skills can now be **installed**,
findings can be **tuned**, and declarations can be **repaired**.

### Added

- **`apply`** — install the locked skills into a harness directory, completing
  the `lock → verify → apply` loop. The source is re-resolved and its digest
  re-checked before anything is written, so the bytes installed are the bytes
  that were reviewed; `--force` overrides, `--dry-run` previews. Never follows
  symlinks, and a skill name may not be a path.
- **`fix`** (and `add --fix`) — derive `allowed-tools` from the capabilities a
  skill actually exercises and write it back into `SKILL.md`. Additive only:
  existing tools are never removed. `--dry-run` shows the change first.
- **`config`** — print the effective configuration, including its locked digest.
- **`skillnotary.config.json`** — per-rule severity overrides (`"off"` to
  silence), file-path ignore globs, `ignoreSkills`, and `apply` targets.
- **Inline suppressions** (`skillnotary-ignore-file` / `-line` / `-next-line`),
  **off by default**: a skill is written by the party being reviewed, so a skill
  that could silence its own findings would be a bypass. When enabled they are
  always reported.
- **Suppression is never silent.** Every dropped finding is counted and
  attributed in the output, and a refused directive is announced.
- **Rules R026 / R027** — executable or unrecognised binary files in a skill
  (by extension and magic bytes), and possible minified/obfuscated content.
- **Rules R023 / R024 / R025** — symlink in a skill, skill too large to review
  fully, scan truncated. Previously these were silent.
- **DSSE attestations.** `sign` now emits a standard DSSE envelope carrying an
  in-toto statement (`subject` digest, `predicateType`, and a predicate listing
  each skill's digest and capabilities plus the config digest).
- **`action.yml`** — a composite GitHub Action, so the gate is one `uses:` line.
- `--target`, `--dry-run` CLI options.

### Changed

- **The config digest is folded into `skills.lock`.** Loosening the suppression
  layer now shows up as drift, and therefore breaks `verify`, `ci` and any
  attestation until it is re-reviewed and re-locked.
- **Policy is evaluated against freshly observed capabilities** and drift is
  itself a violation (`P010`), so a hand-edited lockfile can no longer disarm
  the capability gates.
- `skills.lock` is strictly validated on read; `capabilities` and `declared` are
  required, and an unknown capability is an error.
- Attestations are verified in either DSSE or the legacy
  `skillnotary/attestation@1` format.
- `README.md` and the threat model document the six guarantees the code upholds.

### Fixed

- `apply --force` verified the installed copy against the *lockfile* digest,
  which always failed; it now checks the copy against the resolved source, which
  is the invariant that actually matters.
- `applyConfig` warnings (such as a refused inline suppression) were generated
  but never printed.

### Security

- See [SECURITY-AUDIT.md](SECURITY-AUDIT.md) for the v0.1.0 audit: eight
  findings, all fixed, each with a regression test.

## [0.1.0] — 2026-09-13

Initial release.

- `skills.json` manifest, `skills.lock` lockfile with a deterministic tree
  digest, and capability extraction (declared vs observed).
- Rules R001–R022 covering remote code execution, credential access,
  destructive commands, obfuscated payloads, coercive instructions, hidden
  Unicode, and undeclared capabilities.
- ed25519 attestation over `skills.lock`; policy engine (P001–P009); SBOM;
  harness discovery; `ci` gate.
- Zero runtime dependencies; TypeScript with no build step (Node ≥ 23.6).
