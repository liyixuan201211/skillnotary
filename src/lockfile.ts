import { existsSync } from "node:fs";
import { analyzeSkill } from "./analyze.ts";
import { resolveSpec, CACHE_DIRNAME } from "./source.ts";
import { GENERATOR } from "./version.ts";
import { canonicalJson, readTextFileSafe, writeTextFile } from "./util.ts";
import { join } from "node:path";
import type { Lockfile, LockedSkill, Manifest, SkillAnalysis, CapabilityId } from "./types.ts";
import { ALL_CAPABILITIES } from "./types.ts";
import { configDigest } from "./config.ts";

export const LOCKFILE_FILENAME = "skills.lock";

export function readLockfile(path: string): Lockfile | null {
  const raw = readTextFileSafe(path);
  if (raw === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`${LOCKFILE_FILENAME} is not valid JSON`);
  }
  return normalizeLockfile(parsed);
}

function fail(message: string): never {
  throw new Error(`${LOCKFILE_FILENAME}: ${message}`);
}

function asCapabilityArray(value: unknown, where: string): CapabilityId[] {
  // Required, not defaulted: a lockfile that simply omits `capabilities` is the
  // cheapest way to pretend a skill has none, so absence is an error.
  if (value === undefined) fail(`${where} is missing`);
  if (!Array.isArray(value)) fail(`${where} must be an array`);
  return value.map((entry, index) => {
    if (typeof entry !== "string" || !(ALL_CAPABILITIES as readonly string[]).includes(entry)) {
      fail(`${where}[${index}] is not a known capability`);
    }
    return entry as CapabilityId;
  });
}

function asStringArray(value: unknown, where: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) fail(`${where} must be an array`);
  return value.map((entry, index) => {
    if (typeof entry !== "string") fail(`${where}[${index}] must be a string`);
    return entry;
  });
}

/**
 * Validate and normalise a lockfile.
 *
 * The lockfile is untrusted input: any contributor can edit it, and `policy`
 * reads capability claims straight out of it. A malformed or hand-edited file
 * must therefore produce a clear error — never a crash, and never a silently
 * empty capability list.
 */
export function normalizeLockfile(parsed: unknown): Lockfile {
  if (typeof parsed !== "object" || parsed === null) fail("must be a JSON object");
  const record = parsed as Record<string, unknown>;

  const rawSkills = record["skills"];
  if (!Array.isArray(rawSkills)) fail('is missing a "skills" array');

  const skills: LockedSkill[] = rawSkills.map((entry, index) => {
    const where = `skills[${index}]`;
    if (typeof entry !== "object" || entry === null) fail(`${where} must be an object`);
    const skill = entry as Record<string, unknown>;

    const name = skill["name"];
    const source = skill["source"];
    const integrity = skill["integrity"];
    if (typeof name !== "string" || name === "") fail(`${where}.name must be a non-empty string`);
    if (typeof source !== "string") fail(`${where}.source must be a string`);
    if (typeof integrity !== "string" || !integrity.startsWith("sha256-")) {
      fail(`${where}.integrity must be a "sha256-…" digest`);
    }

    const resolved = skill["resolved"];
    if (typeof resolved !== "object" || resolved === null) fail(`${where}.resolved must be an object`);
    const r = resolved as Record<string, unknown>;
    if (r["type"] !== "path" && r["type"] !== "git") {
      fail(`${where}.resolved.type must be "path" or "git"`);
    }
    if (typeof r["dir"] !== "string") fail(`${where}.resolved.dir must be a string`);

    const str = (key: string): string | undefined =>
      typeof r[key] === "string" ? (r[key] as string) : undefined;
    const url = str("url");
    const ref = str("ref");
    const commit = str("commit");
    const subpath = str("subpath");

    return {
      name,
      source,
      resolved: {
        type: r["type"],
        spec: str("spec") ?? source,
        dir: r["dir"],
        ...(url !== undefined ? { url } : {}),
        ...(ref !== undefined ? { ref } : {}),
        ...(commit !== undefined ? { commit } : {}),
        ...(subpath !== undefined ? { subpath } : {}),
      },
      integrity,
      files: typeof skill["files"] === "number" ? skill["files"] : 0,
      bytes: typeof skill["bytes"] === "number" ? skill["bytes"] : 0,
      capabilities: asCapabilityArray(skill["capabilities"], `${where}.capabilities`),
      declared: asCapabilityArray(skill["declared"], `${where}.declared`),
      declaredTools: asStringArray(skill["declaredTools"], `${where}.declaredTools`),
      license: typeof skill["license"] === "string" ? skill["license"] : null,
      description: typeof skill["description"] === "string" ? skill["description"] : null,
    };
  });

  const rawConfig = record["config"];
  let config: { digest: string | null } | undefined;
  if (typeof rawConfig === "object" && rawConfig !== null) {
    const c = rawConfig as Record<string, unknown>;
    config = { digest: typeof c["digest"] === "string" ? c["digest"] : null };
  }

  return {
    lockfileVersion: 1,
    generator: typeof record["generator"] === "string" ? record["generator"] : "unknown",
    ...(config !== undefined ? { config } : {}),
    skills,
  };
}

export function writeLockfile(path: string, lockfile: Lockfile): void {
  writeTextFile(path, `${canonicalJson(lockfile)}\n`);
}

export interface BuildOptions {
  cwd: string;
  manifest: Manifest;
  /** Re-clone git sources instead of using the cache. */
  refresh?: boolean;
  /** Skip tree hashing (used when only capabilities are needed). */
  skipDigest?: boolean;
}

export interface BuildResult {
  lockfile: Lockfile;
  analyses: Map<string, SkillAnalysis>;
  warnings: string[];
}

/** Resolve every manifest entry, analyse it, and produce a lockfile. */
export function buildLockfile(options: BuildOptions): BuildResult {
  const cacheDir = join(options.cwd, CACHE_DIRNAME);
  const skills: LockedSkill[] = [];
  const analyses = new Map<string, SkillAnalysis>();
  const warnings: string[] = [];

  for (const entry of options.manifest.skills) {
    const resolved = resolveSpec(entry.source, {
      cwd: options.cwd,
      cacheDir,
      ...(options.refresh !== undefined ? { refresh: options.refresh } : {}),
    });

    const analysis = analyzeSkill(resolved.dir, {
      fallbackName: entry.name,
      ...(options.skipDigest !== undefined ? { skipDigest: options.skipDigest } : {}),
    });
    analyses.set(entry.name, analysis);

    if (analysis.name !== entry.name) {
      warnings.push(
        `skill "${entry.name}" declares name "${analysis.name}" in SKILL.md; the manifest name is used in the lockfile`,
      );
    }

    skills.push({
      name: entry.name,
      source: entry.source,
      resolved,
      integrity: analysis.integrity,
      files: analysis.files,
      bytes: analysis.bytes,
      capabilities: analysis.observed,
      declared: analysis.declared.capabilities,
      declaredTools: analysis.declared.tools,
      license: analysis.license,
      description: analysis.description,
    });
  }

  skills.sort((a, b) => a.name.localeCompare(b.name));
  return {
    lockfile: {
      lockfileVersion: 1,
      generator: GENERATOR,
      config: { digest: configDigest(options.cwd) },
      skills,
    },
    analyses,
    warnings,
  };
}

export type DriftKind =
  | "missing"
  | "extra"
  | "source-changed"
  | "integrity-changed"
  | "capabilities-changed"
  | "resolved-changed"
  | "config-changed";

export interface Drift {
  name: string;
  kind: DriftKind;
  detail: string;
}

/**
 * Compare a committed lockfile against a freshly resolved one.
 *
 * `integrity-changed` is the important one: it means the bytes on disk (or on
 * the remote) no longer match what was reviewed and locked.
 */
export function diffLockfiles(committed: Lockfile, fresh: Lockfile): Drift[] {
  const drifts: Drift[] = [];

  // A changed config means the suppression layer moved, which is exactly the
  // kind of change an attacker would smuggle in alongside a malicious skill.
  const beforeConfig = committed.config?.digest ?? null;
  const afterConfig = fresh.config?.digest ?? null;
  if (beforeConfig !== afterConfig) {
    drifts.push({
      name: "(config)",
      kind: "config-changed",
      detail: `skillnotary.config.json changed since it was locked (${shortHash(beforeConfig)} -> ${shortHash(afterConfig)}); review the suppression layer`,
    });
  }

  const locked = new Map(committed.skills.map((s) => [s.name, s]));
  const current = new Map(fresh.skills.map((s) => [s.name, s]));

  for (const [name, entry] of locked) {
    const now = current.get(name);
    if (!now) {
      drifts.push({ name, kind: "missing", detail: "in lockfile but no longer in the manifest" });
      continue;
    }
    if (entry.source !== now.source) {
      drifts.push({
        name,
        kind: "source-changed",
        detail: `source changed: ${entry.source} -> ${now.source}`,
      });
    }
    if (entry.resolved.commit && now.resolved.commit && entry.resolved.commit !== now.resolved.commit) {
      drifts.push({
        name,
        kind: "resolved-changed",
        detail: `commit moved: ${entry.resolved.commit.slice(0, 10)} -> ${now.resolved.commit.slice(0, 10)}`,
      });
    }
    if (entry.integrity !== now.integrity) {
      drifts.push({
        name,
        kind: "integrity-changed",
        detail: `content digest changed: ${short(entry.integrity)} -> ${short(now.integrity)}`,
      });
    }
    const before = [...entry.capabilities].sort().join(",");
    const after = [...now.capabilities].sort().join(",");
    if (before !== after) {
      drifts.push({
        name,
        kind: "capabilities-changed",
        detail: `capabilities changed: [${before || "none"}] -> [${after || "none"}]`,
      });
    }
  }

  for (const name of current.keys()) {
    if (!locked.has(name)) {
      drifts.push({ name, kind: "extra", detail: "in the manifest but not in the lockfile" });
    }
  }

  return drifts;
}

function short(integrity: string): string {
  return integrity.replace(/^sha256-/, "").slice(0, 12);
}

function shortHash(digest: string | null): string {
  return digest === null ? "none" : digest.slice(0, 15);
}

export function lockfilePath(cwd: string): string {
  return join(cwd, LOCKFILE_FILENAME);
}

export function lockfileExists(cwd: string): boolean {
  return existsSync(lockfilePath(cwd));
}

/** Find one entry by name, tolerating a glob selector. */
export function findLocked(lockfile: Lockfile, name: string): LockedSkill | undefined {
  return lockfile.skills.find((s) => s.name === name);
}
