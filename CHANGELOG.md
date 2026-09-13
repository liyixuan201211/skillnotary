# Changelog

All notable changes are recorded here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
