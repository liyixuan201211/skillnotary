/**
 * Tests for the v0.2 additions: the config/suppression layer, `apply`, and `fix`.
 */
import assert from "node:assert/strict";
import { existsSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { analyzeSkill } from "../src/analyze.ts";
import { applySkills, assertSafeSkillDirName } from "../src/apply.ts";
import {
  applyConfig,
  configDigest,
  defaultConfig,
  ignoreMatches,
  readConfig,
  resolveTarget,
  writeConfig,
} from "../src/config.ts";
import { planAllowedTools, toolsForCapabilities, writeFix } from "../src/fix.ts";
import { buildLockfile } from "../src/lockfile.ts";
import { makeSkill, tempDir } from "./helpers.ts";
import type { CapabilityId, Finding, Lockfile } from "../src/types.ts";

function finding(rule: string, file = "SKILL.md", line?: number): Finding {
  return {
    rule,
    severity: "high",
    title: "t",
    detail: "d",
    file,
    ...(line !== undefined ? { line } : {}),
  };
}

// ------------------------------------------------------------------- config

test("config: a rule set to off is suppressed, with the reason recorded", () => {
  const config = { ...defaultConfig(), rules: { R002: "off" as const } };
  const result = applyConfig([finding("R002"), finding("R003")], "s", config);
  assert.deepEqual(result.findings.map((f) => f.rule), ["R003"]);
  assert.equal(result.suppressed.length, 1);
  assert.match(result.suppressed[0]?.by ?? "", /R002=off/);
});

test("config: a rule can be raised as well as lowered", () => {
  const config = { ...defaultConfig(), rules: { R017: "critical" as const } };
  const result = applyConfig([finding("R017")], "s", config);
  assert.equal(result.findings[0]?.severity, "critical");
});

test("config: ignore globs drop findings by file", () => {
  const config = { ...defaultConfig(), ignore: ["vendor/*", "*.min.js"] };
  const result = applyConfig(
    [finding("R002", "vendor/lib.js"), finding("R002", "a.min.js"), finding("R002", "SKILL.md")],
    "s",
    config,
  );
  assert.deepEqual(result.findings.map((f) => f.file), ["SKILL.md"]);
  assert.equal(result.suppressed.length, 2);
});

test("config: an ignore entry can be scoped to one rule and one path", () => {
  // Documentation legitimately contains detector strings, so the exemption has
  // to be narrow: this rule, these files.
  const config = { ...defaultConfig(), ignore: ["R003:reference/*"] };
  const result = applyConfig(
    [
      finding("R003", "reference/capabilities.md"),
      finding("R003", "SKILL.md"),
      finding("R009", "reference/capabilities.md"),
    ],
    "s",
    config,
  );
  assert.deepEqual(result.findings.map((f) => `${f.rule}:${f.file}`), [
    "R003:SKILL.md",
    "R009:reference/capabilities.md",
  ]);
  assert.equal(result.suppressed.length, 1);
  assert.match(result.suppressed[0]?.by ?? "", /R003:reference/);
});

test("config: a rule-scoped ignore does not leak to other rules or paths", () => {
  assert.equal(ignoreMatches("R003:reference/*", "R003", "reference/x.md"), true);
  assert.equal(ignoreMatches("R003:reference/*", "R004", "reference/x.md"), false);
  assert.equal(ignoreMatches("R003:reference/*", "R003", "SKILL.md"), false);
  assert.equal(ignoreMatches("vendor/*", "R003", "vendor/x.js"), true);
  assert.equal(ignoreMatches("R003", "R003", "SKILL.md"), false, "a bare id is a path glob");
});

test("config: ignoreSkills drops the whole skill", () => {
  const config = { ...defaultConfig(), ignoreSkills: ["legacy-*"] };
  const result = applyConfig([finding("R002")], "legacy-thing", config);
  assert.equal(result.ignoredSkill, true);
  assert.deepEqual(result.findings, []);
});

test("config: an invalid rule setting is reported, not silently ignored", () => {
  const config = { ...defaultConfig(), rules: { R002: "nonsense" as never } };
  const result = applyConfig([finding("R002")], "s", config);
  assert.ok(result.warnings.some((w) => w.includes("R002")));
});

test("config: an inline directive is refused by default and announced", () => {
  const config = defaultConfig();
  const withDirective: Finding = {
    ...finding("R002"),
    suppression: { rule: "R002", file: "SKILL.md", line: 4, scope: "file", reason: "" },
  };
  const result = applyConfig([withDirective], "s", config);
  assert.equal(result.findings.length, 1, "the finding must survive");
  assert.ok(
    result.warnings.some((w) => w.includes("allowInlineSuppressions is false")),
    "the refusal must be announced",
  );
});

test("config: an inline directive is honoured only when explicitly enabled", () => {
  const config = { ...defaultConfig(), allowInlineSuppressions: true };
  const withDirective: Finding = {
    ...finding("R002"),
    suppression: { rule: "R002", file: "SKILL.md", line: 4, scope: "file", reason: "reviewed" },
  };
  const result = applyConfig([withDirective], "s", config);
  assert.deepEqual(result.findings, []);
  assert.equal(result.suppressed.length, 1);
});

test("config: requireSuppressionReason rejects a bare directive", () => {
  const config = { ...defaultConfig(), allowInlineSuppressions: true, requireSuppressionReason: true };
  const withDirective: Finding = {
    ...finding("R002"),
    suppression: { rule: "R002", file: "SKILL.md", line: 4, scope: "file", reason: "" },
  };
  const result = applyConfig([withDirective], "s", config);
  assert.equal(result.findings.length, 1);
  assert.ok(result.warnings.some((w) => w.includes("no reason")));
});

test("config: a partial file merges over the defaults", () => {
  const cwd = tempDir("sn-cfg-");
  writeFileSync(join(cwd, "skillnotary.config.json"), JSON.stringify({ rules: { R017: "off" } }));
  const config = readConfig(cwd);
  assert.ok(config);
  assert.equal(config.rules?.["R017"], "off");
  assert.equal(config.allowInlineSuppressions, false, "defaults must still apply");
  assert.ok(config.targets?.["claude-code"]);
});

test("config: a malformed config file is a clear error", () => {
  const cwd = tempDir("sn-cfg-bad-");
  writeFileSync(join(cwd, "skillnotary.config.json"), "{ not json");
  assert.throws(() => readConfig(cwd), /not valid JSON/);
});

test("config: the digest is null when absent and stable when present", () => {
  const cwd = tempDir("sn-cfg-digest-");
  assert.equal(configDigest(cwd), null);
  writeConfig(cwd, defaultConfig());
  const first = configDigest(cwd);
  assert.match(first ?? "", /^sha256-/);
  assert.equal(configDigest(cwd), first, "the same bytes must produce the same digest");
});

test("config: resolveTarget handles names, unknown names and raw paths", () => {
  const config = defaultConfig();
  assert.equal(resolveTarget(config, "claude-code").dir, ".claude/skills");
  assert.equal(resolveTarget(config, undefined).name, config.defaultTarget);
  assert.equal(resolveTarget(config, "./custom/dir").dir, "./custom/dir");
  assert.throws(() => resolveTarget(config, "nope"), /unknown apply target/);
});

// -------------------------------------------------------------------- apply

test("apply: a skill name cannot be a path", () => {
  assert.throws(() => assertSafeSkillDirName("../../etc/x"), /path separator/);
  assert.throws(() => assertSafeSkillDirName("a/b"), /path separator/);
  assert.throws(() => assertSafeSkillDirName(".."), /unsafe/);
  assert.throws(() => assertSafeSkillDirName(".hidden"), /start with a dot/);
  assert.throws(() => assertSafeSkillDirName(""), /empty/);
  assert.doesNotThrow(() => assertSafeSkillDirName("pdf-tools"));
});

function projectWithOneSkill(): { cwd: string; lockfile: Lockfile } {
  const cwd = makeSkill({
    "pdf-tools/SKILL.md": "---\nname: pdf-tools\nallowed-tools: Bash\n---\n\n```bash\ngit status\n```\n",
    "pdf-tools/LICENSE": "MIT License\n",
  });
  const manifest = { version: 1 as const, skills: [{ name: "pdf-tools", source: "./pdf-tools" }] };
  const { lockfile } = buildLockfile({ cwd, manifest });
  writeFileSync(join(cwd, "skills.json"), JSON.stringify(manifest));
  return { cwd, lockfile };
}

test("apply: installs the locked content into the target", () => {
  const { cwd, lockfile } = projectWithOneSkill();
  const result = applySkills({ cwd, lockfile, targetDir: ".claude/skills" });

  assert.equal(result.applied.length, 1);
  assert.equal(result.applied[0]?.action, "installed");
  assert.ok(existsSync(join(result.targetDir, "pdf-tools", "SKILL.md")));
});

test("apply: is idempotent", () => {
  const { cwd, lockfile } = projectWithOneSkill();
  applySkills({ cwd, lockfile, targetDir: ".claude/skills" });
  const second = applySkills({ cwd, lockfile, targetDir: ".claude/skills" });
  assert.equal(second.applied[0]?.action, "unchanged");
});

test("apply: a dry run writes nothing", () => {
  const { cwd, lockfile } = projectWithOneSkill();
  const result = applySkills({ cwd, lockfile, targetDir: ".claude/skills", dryRun: true });
  assert.equal(result.applied.length, 1);
  assert.equal(existsSync(join(cwd, ".claude")), false);
});

test("apply: refuses content that no longer matches the lockfile", () => {
  const { cwd, lockfile } = projectWithOneSkill();
  // Change the skill after locking.
  writeFileSync(
    join(cwd, "pdf-tools", "SKILL.md"),
    "---\nname: pdf-tools\nallowed-tools: Bash\n---\n\ntampered\n",
  );

  const result = applySkills({ cwd, lockfile, targetDir: ".claude/skills" });
  assert.equal(result.applied.length, 0);
  assert.equal(result.skipped.length, 1);
  assert.match(result.skipped[0]?.reason ?? "", /changed since it was locked/);
  assert.equal(existsSync(join(cwd, ".claude")), false, "nothing must be written");
});

test("apply: --force installs despite the mismatch", () => {
  const { cwd, lockfile } = projectWithOneSkill();
  writeFileSync(
    join(cwd, "pdf-tools", "SKILL.md"),
    "---\nname: pdf-tools\nallowed-tools: Bash\n---\n\ntampered\n",
  );
  const result = applySkills({ cwd, lockfile, targetDir: ".claude/skills", force: true });
  assert.equal(result.applied.length, 1);
});

test("apply: does not copy symlinked content from the source", () => {
  const { cwd, lockfile } = projectWithOneSkill();
  writeFileSync(join(cwd, "outside-secret.txt"), "SECRET");
  // A symlink inside the skill must not be followed into the target.
  symlinkSync(join(cwd, "outside-secret.txt"), join(cwd, "pdf-tools", "leak.txt"));

  applySkills({ cwd, lockfile, targetDir: ".claude/skills", force: true });
  assert.equal(existsSync(join(cwd, ".claude", "skills", "pdf-tools", "leak.txt")), false);
});

// ---------------------------------------------------------------------- fix

test("fix: capabilities map back to tools, with shell refinements folding into Bash", () => {
  const caps: CapabilityId[] = ["exec", "network", "fs.read", "fs.write", "secrets", "install"];
  assert.deepEqual(toolsForCapabilities(caps), ["Bash", "Read", "WebFetch", "Write"]);
});

test("fix: adds missing tools to an inline allowed-tools list, keeping existing ones", () => {
  const dir = makeSkill({
    "SKILL.md":
      "---\nname: s\nallowed-tools: Read, CustomTool\n---\n\n```bash\ncurl https://x.test\n```\n",
    LICENSE: "MIT License\n",
  });
  const analysis = analyzeSkill(dir);
  const plan = planAllowedTools(dir, analysis);

  assert.equal(plan.changed, true);
  assert.deepEqual(plan.keptTools, ["Read", "CustomTool"]);
  assert.ok(plan.addedTools.includes("Bash"));
  assert.ok(plan.addedTools.includes("WebFetch"));
  assert.match(plan.newContent, /^---\nname: s\n/);
  assert.ok(plan.newContent.includes("CustomTool"), "existing tools must survive");

  writeFix(plan);
  const written = readFileSync(join(dir, "SKILL.md"), "utf8");
  assert.equal(written, plan.newContent);
  assert.deepEqual(analyzeSkill(dir).declared.tools.sort(), ["Bash", "CustomTool", "Read", "WebFetch"]);
});

test("fix: rewrites a YAML block list form", () => {
  const dir = makeSkill({
    "SKILL.md": "---\nname: s\nallowed-tools:\n  - Read\n  - Write\n---\n\n```bash\nls\n```\n",
    LICENSE: "MIT License\n",
  });
  const plan = planAllowedTools(dir, analyzeSkill(dir));
  assert.ok(plan.changed);
  assert.ok(!/^\s+- Read$/m.test(plan.newContent), "the old block list must be gone");
  assert.ok(plan.newContent.includes("allowed-tools: Bash, Read, Write"));
});

test("fix: creates frontmatter when there is none", () => {
  const dir = makeSkill({ "SKILL.md": "Just prose.\n\n```bash\nls\n```\n", LICENSE: "MIT License\n" });
  const plan = planAllowedTools(dir, analyzeSkill(dir));
  assert.ok(plan.changed);
  assert.match(plan.newContent, /^---\nname: /);
  assert.ok(plan.newContent.includes("allowed-tools: Bash"));
});

test("fix: is a no-op when the declaration already covers the behaviour", () => {
  const dir = makeSkill({
    "SKILL.md": "---\nname: s\nallowed-tools: Bash\n---\n\n```bash\nls\n```\n",
    LICENSE: "MIT License\n",
  });
  const plan = planAllowedTools(dir, analyzeSkill(dir));
  assert.equal(plan.changed, false);
  assert.match(plan.reason ?? "", /already covers/);
});

test("fix: is additive and never removes a declared tool", () => {
  const dir = makeSkill({
    "SKILL.md": "---\nname: s\nallowed-tools: Read\n---\n\nno capabilities here\n",
    LICENSE: "MIT License\n",
  });
  const plan = planAllowedTools(dir, analyzeSkill(dir));
  if (plan.changed) {
    assert.ok(plan.newContent.includes("Read"), "Read must not be dropped");
  }
});
