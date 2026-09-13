# Security audit — skillnotary v0.1.0

**Date:** 2026-09-13 · **Scope:** the whole repository at commit `b91a6bc` ·
**Method:** dependency audit, manual source review, threat modelling,
proof-of-concept exploitation, fixes, regression tests, independent re-verification.

Every finding below was **demonstrated with a working proof of concept before
being fixed**, and every fix was **re-verified by re-running the original
exploit** against the patched code. Hypotheses that did not reproduce are
listed too, because knowing what is *not* exploitable is part of the result.

---

## 1. Threat model

skillnotary is a review tool that reads untrusted content. The adversary is
someone who can get code in front of a user of the tool — realistically, by
opening a pull request against a repository the user runs skillnotary in.

Untrusted inputs, in order of importance:

| Input | Reaches | Why it is untrusted |
|---|---|---|
| `SKILL.md` and any file in a skill | the analyser, then the terminal | authored by whoever wrote the skill |
| `skills.json` | `resolveSource` → **`git` argv** | ships inside the reviewed repo |
| a cloned git remote | the analyser, the digest | arbitrary third-party content |
| `skills.lock` | the policy engine | any contributor can edit it |
| `skillnotary.policy.json` | the policy engine | ditto |

Explicitly **out of scope**: the security of `git` itself, supply-chain attacks
on npm (there are no runtime dependencies), and physical/local attackers who
can already run code as the user.

---

## 2. Findings

| ID | Severity | Finding | Status |
|---|---|---|---|
| F1 | Medium | Git `subpath` escapes the clone directory (path traversal) | Fixed |
| F2 | Medium | Symlinks were followed: read files outside the skill; self-referential link re-traversed | Fixed |
| F3 | Medium | Regex stack overflow (DoS) on large repetitive files; no size cap | Fixed |
| F4 | Medium | ANSI escape injection: a skill could rewrite its own audit report | Fixed |
| F5 | Medium | Malformed `skills.lock` crashed with `TypeError`; no schema validation | Fixed |
| F6 | Medium | **Policy bypass**: capability gates trusted self-reported lockfile data | Fixed |
| F7 | Low | `git` argv lacked a `--` separator; no transport allowlist | Hardened |
| F8 | Low | Prototype-pollution-shaped frontmatter assignment | Hardened |
| — | — | `globMatch` `\|` injection (hypothesis) | **Disproved** |

### F1 — Git subpath path traversal

`resolveSource` joined an attacker-controlled `subpath` onto the clone
directory without checking containment, so `..` escaped it.

```ts
// before
const dir = parsed.subpath ? join(cloneDir, parsed.subpath) : cloneDir;
```

**PoC (confirmed):** `git+file://<repo>#../../outside/secret` resolved to a
directory outside the cache and read a `SKILL.md` planted there.

**Impact:** an untrusted `skills.json` could point the analysis at arbitrary
host directories. Because findings print matching lines as evidence, this is an
information-disclosure primitive, not just a sandbox escape.

**Fix:** resolve and require containment.

```ts
dir = resolve(root, parsed.subpath);
if (dir !== root && !dir.startsWith(root + sep)) {
  throw new Error(`subpath escapes the repository: ${parsed.subpath}`);
}
```

**Verified:** exploit now throws `subpath escapes the repository`; absolute
subpaths (`#/etc`) are rejected by the same check.

### F2 — Symlink following

`walkFiles` used `statSync`, which follows symlinks.

**PoC (confirmed):** a skill containing `link -> /outside` yielded
`link/id_rsa` from the walk, i.e. skillnotary read (and digested) a file outside
the skill. A self-referential link (`loop -> .`) was walked 31 times before the
OS path limit stopped it.

**Impact:** read files outside the skill; make the integrity digest cover
content the skill does not own; unbounded work.

**Fix:** walk with `lstatSync` and never traverse a symlink; report them
instead as rule **R023** (`high` when the link target is absolute or contains
`..`, otherwise `medium`).

**Verified:** outside files walked `31 → 0`; the link is reported, not followed.

### F3 — Regex denial of service

Rule **R008** matched long base64 blobs with an open-ended quantifier:

```
[A-Za-z0-9+/]{300,}={0,2}
```

**PoC (confirmed):** 16 MB and 32 MB of repetitive input made V8 exceed the
stack inside `re.exec`, throwing `RangeError: Maximum call stack size exceeded`
and aborting the whole analysis.

**Fix — three layers:**

1. bound the quantifier: `{300,4096}`;
2. only ever **scan the head** of a file — `readHead()` caps reading at
   `LIMITS.maxScanBytesPerFile` (1 MB) and a `maxScanBytesTotal` budget (64 MB);
3. make truncation **visible** rather than silent: rule **R025** fires when any
   file was only partially scanned, and rule **R024** when the walk itself was
   cut off at `maxFiles` (20 000). Silent truncation would be a bypass in
   itself — a payload could simply sit past the limit.

The **digest is still computed over the whole tree**, so integrity is not
weakened by the scan cap.

**Verified:** the 32 MB file now analyses in ~34 ms with no error, and R025 is
raised for oversized files.

### F4 — ANSI escape injection

Finding evidence and skill names were printed verbatim. A skill could embed
`ESC[2K` plus a carriage return to erase the line describing it and print
"✓ clean" in its place.

**PoC (confirmed):** `skillnotary audit` emitted 3 raw `ESC` (0x1b) bytes taken
from skill content.

**Fix:** `sanitizeForTerminal()` replaces C0/C1 control characters, DEL,
zero-width, bidi, Unicode-tag and line-separator characters with `U+FFFD`, and
normalises CR. It is applied at every point where untrusted text is printed
(evidence, titles, details, file paths, skill names, licences, drift and
violation messages). `--json` output was already safe (`JSON.stringify`
escapes control characters).

U+FFFD is used deliberately: the tampering stays **visible** instead of being
silently dropped.

**Verified:** `ESC` bytes in stdout `3 → 0`; the payload renders as
`�[2K` while the finding is still reported.

### F5 — Lockfile schema not validated

`readLockfile` cast `JSON.parse` output straight to `Lockfile`.

**PoC (confirmed):** a lockfile with a skill entry lacking `capabilities` made
`diffLockfiles` throw `TypeError: entry.capabilities is not iterable`.

**Fix:** `normalizeLockfile()` validates and normalises every field, producing
errors such as `skills.lock: skills[0].integrity must be a "sha256-…" digest`.
`capabilities` and `declared` are **required** — a lockfile that merely omits
them is precisely how someone would pretend a skill has no capabilities.

**Verified:** malformed inputs now fail with clear messages; a well-formed
lockfile round-trips unchanged.

### F6 — Policy bypass via a tampered lockfile

Rules **P007** (capability gate) and **P008** (must-be-declared) read
capabilities out of `skills.lock` — a file any contributor can edit.

**PoC (confirmed):** with `capabilities: {secrets: false, network: false}`, the
policy correctly reported 2 × P007. After rewriting `skills.lock` to set
`capabilities: []`, **both P007 violations disappeared** and only the
severity-based P009 checks remained. `verify` caught it via drift, but
`skillnotary policy` — the documented command — was bypassable.

**Fix:** policy is now evaluated against **freshly observed** capabilities, and
drift between the committed lockfile and the working tree is itself a violation
(**P010**). The lockfile is evidence, not an authority.

**Verified:** with the same stripped lockfile, `policy` now fails with
5 violations including `P010` and both P007 gates; exit code 1.

### F7 — `git` argument injection (hardening)

`git clone` received the manifest-controlled URL with no `--` separator and no
transport restrictions.

**Attempted PoCs (all failed to execute):** `ext::` transport, `-u<cmd>`,
`--upload-pack=<cmd>`, `--config=core.sshCommand=<cmd>`. The clone target
directory is always the next positional and does not exist, so `git` aborts
before running anything. **Not exploitable as shipped** — reported as hardening
because it is one refactor away from becoming exploitable.

**Fix:** `assertSafeGitUrl()` allowlists `https/http/ssh/git/file` and scp-like
URLs, rejects anything starting with `-`, and refuses the `ext::` transport
(which executes local commands). `--` now terminates options before the URL, and
a `ref` beginning with `-` is rejected.

**Verified:** all three injection payloads are now rejected before `git` runs.

### F8 — Prototype pollution (hardening)

`parseFrontmatter` assigned parsed keys onto a `{}` literal, so `__proto__` and
`constructor` were attacker-influenced keys.

**PoC (not reproduced):** `Object.prototype.polluted` stayed `undefined` —
the parser only ever produces strings/arrays, and assigning a string to
`__proto__` is a no-op. **Not exploitable.**

**Fix (defence in depth):** the frontmatter map is now `Object.create(null)`.

---

## 3. Hypotheses that were disproved

Recorded so the same ground is not re-tested later:

- **`globMatch` regex injection via `|`** — I initially believed `|` was not
  escaped. It is: the escape class `[.+^${}()|[\]\\]` includes `|`.
  `globMatch("evil|benign", "evil") === false`. Locked in by a regression test.
- **Unbounded file read as its own bug** — superseded by F3; the read is now
  capped and truncation is reported.
- **`git clone` RCE via option injection** — see F7.

---

## 4. Properties verified as sound

- **`npm audit`: 0 vulnerabilities** (prod *and* dev trees).
- **Zero runtime dependencies** — `dependencies: {}`. The only install-time
  packages are `typescript` and `@types/node`, both dev-only.
- **No shell interpretation anywhere** — no `shell: true`, no `execSync`, no
  string command construction; the single subprocess is
  `execFileSync("git", argsArray)`.
- **No `eval`, no `new Function`, no dynamic `import()` of untrusted paths.**
- **ed25519 verification** — a signature is checked against the payload digest
  *and* a modified payload, a foreign public key, and a changed file are all
  rejected. Signature and digest cover the same bytes.
- **Deterministic digests** — content and names only; mtimes, permissions and
  walk order cannot influence the digest.
- **No secrets in the repository** — no key material, no tokens; and
  `.gitignore` now excludes `skillnotary.key.json` so a generated private key
  cannot be committed by accident.
- **Type safety** — `tsc --noEmit` clean under `strict` +
  `noUncheckedIndexedAccess` + `verbatimModuleSyntax`.

---

## 5. Accepted risks

- **`path` sources may point anywhere on disk.** `"source": "/some/dir"` is an
  intended, documented feature (add a skill from elsewhere). Unlike F1 this is
  an explicit, visible choice in your own manifest rather than a hidden escape
  from a clone — so it is accepted rather than blocked. If you run skillnotary
  on an untrusted repository, review `skills.json` first.
- **Static analysis is heuristic.** Rules are context-scoped regexes. Targeted
  obfuscation will evade them; the scan caps of F3 also mean a large enough file
  is only partially inspected (and says so via R025).
- **Signatures cover `skills.lock`, not the skills.** The digests in the lock
  are what bind the signature to content.
- **Not Sigstore.** ed25519 over JSON: no transparency log, no keyless/OIDC.
- **`ref` → `commit` resolution trusts the remote.** A pinned commit is
  recorded, but nothing verifies a tag's signature.
- **No sandboxing.** skillnotary never executes a skill; a skill that passes
  policy can still be harmful when your agent runs it.

---

## 6. Reproducing this audit

```bash
npm audit                 # 0 vulnerabilities
npx tsc --noEmit          # 0 type errors
node --test               # 73 tests, including one per finding above
```

Each finding has a regression test in `test/security-fixes.test.ts` that fails
if the corresponding fix is reverted. The two deliberately hostile fixtures
(`test/fixtures/exfil`, `test/fixtures/benign`) keep the detector's
false-negative and false-positive behaviour pinned.
