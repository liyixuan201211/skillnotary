# Security policy

## Reporting a vulnerability

Please **do not** open a public issue for a security problem. Use GitHub's
private vulnerability reporting ("Security" → "Report a vulnerability") on this
repository, or email the maintainers listed in `package.json`.

Include:

- what you can do that you should not be able to,
- the smallest input that demonstrates it (a `SKILL.md`, a `skills.json`, or a
  `skills.lock` is usually enough),
- the version or commit you tested.

You can expect an acknowledgement within a few days. Please give us a
reasonable window to ship a fix before public disclosure.

## What counts as a vulnerability here

skillnotary reads untrusted content, so the interesting classes are:

| In scope | Why |
|---|---|
| Code execution, argument injection, path traversal | the tool runs on a machine you care about |
| Reading files outside the skill being reviewed | it is a review tool; it must see only what it is reviewing |
| Denial of service (unbounded work, crashes) | a skill must not be able to wedge a CI job |
| Terminal escape / output injection | a skill must not be able to forge its own report |
| Policy bypass | the whole point is that policy cannot be talked around |
| Signature or digest verification flaws | provenance is the product |

## Explicitly out of scope

- **A skill that passes review and is later found to be malicious.** Detection
  is heuristic; a clean report means "no known signals", not "safe".
- **`path` sources pointing outside the project.** That is a documented,
  manifest-level feature, not an escape (see `SECURITY-AUDIT.md`, accepted risks).
- **Vulnerabilities in `git` itself**, or in the remote you chose to clone.
- **Anything requiring an attacker who can already execute code as your user.**
- **npm supply-chain compromise of dev-only tooling** (`typescript`,
  `@types/node`); there are no runtime dependencies to attack.

## Design commitments

These are the guarantees the code is written to uphold. A report that shows one
of them broken is a valid vulnerability:

1. **Never follow a symlink** out of a skill directory.
2. **Never let manifest content become an option** to `git`.
3. **Never trust the lockfile over fresh observation** when enforcing policy.
4. **Never print untrusted bytes verbatim** to a terminal.
5. **Never let a skill cause unbounded work** — every loop and read is capped,
   and truncation is always reported rather than silent.
6. **Never default a security-relevant field.** Missing means error, not "empty".

## Supported versions

The project is pre-1.0; only the latest release is supported.
