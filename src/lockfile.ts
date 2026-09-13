import { existsSync } from "node:fs";
import { analyzeSkill } from "./analyze.ts";
import { resolveSpec, CACHE_DIRNAME } from "./source.ts";
import { GENERATOR } from "./version.ts";
import { canonicalJson, readTextFileSafe, writeTextFile } from "./util.ts";
import { join } from "node:path";
import type { Lockfile, LockedSkill, Manifest, SkillAnalysis } from "./types.ts";

export const LOCKFILE_FILENAME = "skills.lock";

export function readLockfile(path: string): Lockfile | null {
  const raw = readTextFileSafe(path);
  if (raw === null) return null;
  const parsed = JSON.parse(raw) as Partial<Lockfile>;
  return {
    lockfileVersion: 1,
    generator: parsed.generator ?? "unknown",
    skills: Array.isArray(parsed.skills) ? parsed.skills : [],
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
    lockfile: { lockfileVersion: 1, generator: GENERATOR, skills },
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
  | "resolved-changed";

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
