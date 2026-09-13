import assert from "node:assert/strict";
import { test } from "node:test";
import { writeFileSync } from "node:fs";
import { join } from "node:path";

import { buildLockfile, diffLockfiles } from "../src/lockfile.ts";
import { parseSource } from "../src/source.ts";
import { makeSkill } from "./helpers.ts";
import type { Lockfile, LockedSkill, Manifest } from "../src/types.ts";

test("github sources parse into url, subpath and ref", () => {
  const parsed = parseSource("github:acme/skills#pdf-tools@v1.2.0");
  assert.equal(parsed.kind, "git");
  assert.equal(parsed.url, "https://github.com/acme/skills.git");
  assert.equal(parsed.subpath, "pdf-tools");
  assert.equal(parsed.ref, "v1.2.0");
});

test("a github source without a fragment has neither subpath nor ref", () => {
  const parsed = parseSource("github:acme/skills");
  assert.equal(parsed.url, "https://github.com/acme/skills.git");
  assert.equal(parsed.subpath, undefined);
  assert.equal(parsed.ref, undefined);
});

test("a leading @ in the fragment means ref only", () => {
  const parsed = parseSource("github:acme/skills#@main");
  assert.equal(parsed.subpath, undefined);
  assert.equal(parsed.ref, "main");
});

test("git+ and bare https remotes parse", () => {
  const plus = parseSource("git+https://git.example.com/x.git#sub/skill@abc123");
  assert.equal(plus.url, "https://git.example.com/x.git");
  assert.equal(plus.subpath, "sub/skill");
  assert.equal(plus.ref, "abc123");

  const bare = parseSource("https://github.com/a/b.git");
  assert.equal(bare.kind, "git");
  assert.equal(bare.url, "https://github.com/a/b.git");
});

test("local paths parse as paths, including file: and absolute", () => {
  for (const spec of ["./vendor/skill", "vendor/skill", "file:./x", "/abs/path"]) {
    const parsed = parseSource(spec);
    assert.equal(parsed.kind, "path", `${spec} should be a path source`);
  }
  assert.equal(parseSource("file:./x").path, "./x");
});

test("an empty source is rejected", () => {
  assert.throws(() => parseSource("   "), /empty source spec/);
});

test("buildLockfile resolves a local skill and pins its digest", () => {
  const cwd = makeSkill({
    "skill/SKILL.md": "---\nname: demo\nallowed-tools: Bash\n---\n\n```bash\ngit status\n```\n",
  });
  const manifest: Manifest = { version: 1, skills: [{ name: "demo", source: "./skill" }] };

  const { lockfile, analyses } = buildLockfile({ cwd, manifest });
  assert.equal(lockfile.skills.length, 1);

  const entry = lockfile.skills[0];
  assert.ok(entry);
  assert.equal(entry.name, "demo");
  assert.match(entry.integrity, /^sha256-/);
  assert.deepEqual(entry.capabilities, ["exec"]);
  assert.ok(analyses.has("demo"));
});

function locked(overrides: Partial<LockedSkill> = {}): LockedSkill {
  return {
    name: "s",
    source: "./s",
    resolved: { type: "path", spec: "./s", dir: "/tmp/s" },
    integrity: "sha256-AAAA",
    files: 1,
    bytes: 10,
    capabilities: ["exec"],
    declared: ["exec"],
    declaredTools: ["Bash"],
    license: "MIT",
    description: null,
    ...overrides,
  };
}

function lockfile(...skills: LockedSkill[]): Lockfile {
  return { lockfileVersion: 1, generator: "test", skills };
}

test("identical lockfiles have no drift", () => {
  assert.deepEqual(diffLockfiles(lockfile(locked()), lockfile(locked())), []);
});

test("a changed digest is reported as integrity drift", () => {
  const drifts = diffLockfiles(lockfile(locked()), lockfile(locked({ integrity: "sha256-BBBB" })));
  assert.equal(drifts.length, 1);
  assert.equal(drifts[0]?.kind, "integrity-changed");
});

test("capability escalation is reported even when only capabilities change", () => {
  const drifts = diffLockfiles(
    lockfile(locked({ capabilities: ["exec"] })),
    lockfile(locked({ capabilities: ["exec", "secrets"] })),
  );
  assert.equal(drifts.length, 1);
  assert.equal(drifts[0]?.kind, "capabilities-changed");
  assert.match(drifts[0]?.detail ?? "", /secrets/);
});

test("a moved git commit is reported", () => {
  const before = locked({
    resolved: { type: "git", spec: "github:a/b", dir: "/tmp/a", url: "u", commit: "1111111111" },
  });
  const after = locked({
    resolved: { type: "git", spec: "github:a/b", dir: "/tmp/a", url: "u", commit: "2222222222" },
  });
  const drifts = diffLockfiles(lockfile(before), lockfile(after));
  assert.ok(drifts.some((d) => d.kind === "resolved-changed"));
});

test("missing and extra skills are both reported", () => {
  const drifts = diffLockfiles(
    lockfile(locked({ name: "gone" })),
    lockfile(locked({ name: "new" })),
  );
  const kinds = drifts.map((d) => d.kind).sort();
  assert.deepEqual(kinds, ["extra", "missing"]);
});

test("a changed source spec is reported", () => {
  const drifts = diffLockfiles(
    lockfile(locked({ source: "./a" })),
    lockfile(locked({ source: "./b" })),
  );
  assert.ok(drifts.some((d) => d.kind === "source-changed"));
});

test("editing a file changes the resolved digest", () => {
  const cwd = makeSkill({ "skill/SKILL.md": "---\nname: demo\n---\n\nversion one\n" });
  const manifest: Manifest = { version: 1, skills: [{ name: "demo", source: "./skill" }] };
  const first = buildLockfile({ cwd, manifest }).lockfile;

  writeFileSync(join(cwd, "skill/SKILL.md"), "---\nname: demo\n---\n\nversion two\n", "utf8");
  const second = buildLockfile({ cwd, manifest }).lockfile;

  const drifts = diffLockfiles(first, second);
  assert.ok(drifts.some((d) => d.kind === "integrity-changed"));
});
