import assert from "node:assert/strict";
import { test } from "node:test";

import { atLeast, defaultPolicy, evaluatePolicy, severityRank } from "../src/policy.ts";
import type { Finding, LockedSkill, Lockfile, Severity } from "../src/types.ts";

function skill(overrides: Partial<LockedSkill> = {}): LockedSkill {
  return {
    name: "s",
    source: "./s",
    resolved: { type: "path", spec: "./s", dir: "/tmp/s" },
    integrity: "sha256-AAAA",
    files: 1,
    bytes: 10,
    capabilities: [],
    declared: [],
    declaredTools: [],
    license: "MIT",
    description: null,
    ...overrides,
  };
}

function lock(...skills: LockedSkill[]): Lockfile {
  return { lockfileVersion: 1, generator: "test", skills };
}

function finding(severity: Severity, rule = "R002"): Finding {
  return { rule, severity, title: "t", detail: "d", file: "SKILL.md" };
}

const absent = { present: false, valid: false };
const valid = { present: true, valid: true };

test("severity ordering helpers behave", () => {
  assert.ok(atLeast("critical", "high"));
  assert.ok(atLeast("high", "high"));
  assert.ok(!atLeast("medium", "high"));
  assert.ok(severityRank("critical") > severityRank("info"));
});

test("a missing lockfile is a violation by default", () => {
  const outcome = evaluatePolicy({
    policy: defaultPolicy(),
    lockfile: null,
    findingsBySkill: new Map(),
    attestation: absent,
  });
  assert.deepEqual(
    outcome.violations.map((v) => v.rule),
    ["P001"],
  );
});

test("requireLock:false tolerates a missing lockfile", () => {
  const outcome = evaluatePolicy({
    policy: { version: 1, requireLock: false },
    lockfile: null,
    findingsBySkill: new Map(),
    attestation: absent,
  });
  assert.deepEqual(outcome.violations, []);
});

test("forbidden capabilities are reported per skill", () => {
  const outcome = evaluatePolicy({
    policy: { version: 1, capabilities: { network: false, secrets: false } },
    lockfile: lock(skill({ name: "web", capabilities: ["network"] })),
    findingsBySkill: new Map(),
    attestation: absent,
  });
  assert.equal(outcome.violations.length, 1);
  assert.equal(outcome.violations[0]?.rule, "P007");
  assert.match(outcome.violations[0]?.message ?? "", /network/);
});

test("denySkills matches globs", () => {
  const outcome = evaluatePolicy({
    policy: { version: 1, denySkills: ["crypto-*"] },
    lockfile: lock(skill({ name: "crypto-miner" }), skill({ name: "pdf-tools" })),
    findingsBySkill: new Map(),
    attestation: absent,
  });
  assert.equal(outcome.violations.length, 1);
  assert.equal(outcome.violations[0]?.rule, "P006");
  assert.equal(outcome.violations[0]?.skill, "crypto-miner");
});

test("allowSkills restricts what may be installed", () => {
  const outcome = evaluatePolicy({
    policy: { version: 1, allowSkills: ["approved-*"] },
    lockfile: lock(skill({ name: "approved-a" }), skill({ name: "other" })),
    findingsBySkill: new Map(),
    attestation: absent,
  });
  assert.equal(outcome.violations.length, 1);
  assert.equal(outcome.violations[0]?.rule, "P005");
  assert.equal(outcome.violations[0]?.skill, "other");
});

test("requireSignature without an attestation is a violation", () => {
  const outcome = evaluatePolicy({
    policy: { version: 1, requireSignature: true },
    lockfile: lock(skill()),
    findingsBySkill: new Map(),
    attestation: absent,
  });
  assert.ok(outcome.violations.some((v) => v.rule === "P002"));
});

test("an invalid attestation is a violation", () => {
  const outcome = evaluatePolicy({
    policy: { version: 1, requireSignature: true },
    lockfile: lock(skill()),
    findingsBySkill: new Map(),
    attestation: { present: true, valid: false, reason: "digest mismatch" },
  });
  const violation = outcome.violations.find((v) => v.rule === "P003");
  assert.ok(violation);
  assert.match(violation.message, /digest mismatch/);
});

test("a valid attestation satisfies requireSignature", () => {
  const outcome = evaluatePolicy({
    policy: { version: 1, requireSignature: true },
    lockfile: lock(skill()),
    findingsBySkill: new Map(),
    attestation: valid,
  });
  assert.deepEqual(outcome.violations, []);
});

test("requireDeclared flags capabilities used but not declared", () => {
  const outcome = evaluatePolicy({
    policy: { version: 1, requireDeclared: ["exec"] },
    lockfile: lock(skill({ capabilities: ["exec"], declared: [] })),
    findingsBySkill: new Map(),
    attestation: absent,
  });
  assert.ok(outcome.violations.some((v) => v.rule === "P008"));
});

test("maxSeverity gates findings", () => {
  const findings = new Map<string, Finding[]>([["s", [finding("medium"), finding("critical", "R003")]]]);

  const strict = evaluatePolicy({
    policy: { version: 1, maxSeverity: "high" },
    lockfile: lock(skill()),
    findingsBySkill: findings,
    attestation: absent,
  });
  assert.equal(strict.violations.length, 1, "only the critical finding should fail");

  const loose = evaluatePolicy({
    policy: { version: 1, maxSeverity: "medium" },
    lockfile: lock(skill()),
    findingsBySkill: findings,
    attestation: absent,
  });
  assert.equal(loose.violations.length, 2, "both findings should fail");
});

test("a clean project yields no violations", () => {
  const outcome = evaluatePolicy({
    policy: defaultPolicy(),
    lockfile: lock(skill({ capabilities: ["exec"], declared: ["exec"] })),
    findingsBySkill: new Map(),
    attestation: absent,
  });
  assert.deepEqual(outcome.violations, []);
});

test("an unopinionated policy produces a network note", () => {
  const outcome = evaluatePolicy({
    policy: { version: 1 },
    lockfile: lock(skill({ capabilities: ["network"] })),
    findingsBySkill: new Map(),
    attestation: absent,
  });
  assert.ok(outcome.notes.some((n) => n.includes("network")));
});

test("an explicit network decision produces no note", () => {
  const outcome = evaluatePolicy({
    policy: { version: 1, capabilities: { network: false } },
    lockfile: lock(skill({ capabilities: ["network"] })),
    findingsBySkill: new Map(),
    attestation: absent,
  });
  assert.deepEqual(outcome.notes, []);
});
