import { copyFileSync, existsSync, mkdirSync, rmSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { digestTree } from "./hash.ts";
import { CACHE_DIRNAME, resolveSpec } from "./source.ts";
import { walkTree } from "./util.ts";
import type { Lockfile, LockedSkill } from "./types.ts";

export interface ApplyOptions {
  cwd: string;
  lockfile: Lockfile;
  /** Absolute destination directory. */
  targetDir: string;
  /** Report what would happen without touching the filesystem. */
  dryRun?: boolean;
  /** Only apply these skill names. */
  only?: string[];
  /**
   * Install even though the working tree no longer matches the lockfile.
   * Off by default: applying content that differs from what was reviewed and
   * signed defeats the point of a notary.
   */
  force?: boolean;
}

export interface AppliedSkill {
  name: string;
  dir: string;
  files: number;
  bytes: number;
  action: "installed" | "replaced" | "unchanged";
}

export interface ApplyResult {
  targetDir: string;
  applied: AppliedSkill[];
  skipped: Array<{ name: string; reason: string }>;
  warnings: string[];
}

/**
 * A skill name becomes a directory name under the target, so it must be a
 * single safe path segment. It comes from the manifest, which is untrusted —
 * `"../../../etc/cron.d/x"` must not be able to escape the target.
 */
export function assertSafeSkillDirName(name: string): void {
  if (name === "") throw new Error("skill name is empty");
  if (name === "." || name === "..") throw new Error(`unsafe skill name: ${name}`);
  if (name.includes("/") || name.includes("\\")) {
    throw new Error(`skill name must not contain a path separator: ${name}`);
  }
  if (name.startsWith(".")) throw new Error(`skill name must not start with a dot: ${name}`);
  // Defence in depth: resolve and confirm the result is still one segment.
  if (resolve("/base", name) !== `/base/${name}`) {
    throw new Error(`unsafe skill name: ${name}`);
  }
}

function copyTree(from: string, to: string): { files: number; bytes: number } {
  // walkTree never follows symlinks, so a link cannot pull content in from
  // outside the skill, and `files` are regular files by construction.
  const { files } = walkTree(from);
  let bytes = 0;
  for (const rel of files) {
    const src = join(from, rel);
    const dst = join(to, rel);
    mkdirSync(dirname(dst), { recursive: true });
    copyFileSync(src, dst);
    try {
      bytes += statSync(src).size;
    } catch {
      /* size is informational */
    }
  }
  return { files: files.length, bytes };
}

function existingTreeDigest(dir: string): string | null {
  if (!existsSync(dir)) return null;
  try {
    if (!statSync(dir).isDirectory()) return null;
    return digestTree(dir).integrity;
  } catch {
    return null;
  }
}

/**
 * Materialise the locked skills into a harness directory.
 *
 * Two properties matter and are enforced here:
 *
 *  1. **The bytes installed are the bytes that were locked.** The source is
 *     re-resolved from the manifest and its digest re-computed; a mismatch
 *     aborts unless `force` is set. We never copy from the `dir` recorded in
 *     the lockfile, because that path is attacker-writable.
 *  2. **Nothing escapes the target directory.** The name is validated as a
 *     single safe segment and the copy uses a symlink-free walk.
 */
export function applySkills(options: ApplyOptions): ApplyResult {
  const targetDir = resolve(options.cwd, options.targetDir);
  const applied: AppliedSkill[] = [];
  const skipped: Array<{ name: string; reason: string }> = [];
  const warnings: string[] = [];

  const wanted = options.only && options.only.length > 0 ? new Set(options.only) : null;
  const cacheDir = join(options.cwd, CACHE_DIRNAME);

  for (const entry of options.lockfile.skills) {
    if (wanted !== null && !wanted.has(entry.name)) continue;

    let dest: string;
    try {
      assertSafeSkillDirName(entry.name);
      dest = join(targetDir, entry.name);
      if (!dest.startsWith(`${targetDir}/`)) {
        throw new Error(`destination escapes the target directory: ${entry.name}`);
      }
    } catch (error) {
      skipped.push({ name: entry.name, reason: (error as Error).message });
      continue;
    }

    // Re-resolve from the manifest spec, then confirm it is still the reviewed
    // content. This is what makes `apply` trustworthy rather than a file copy.
    let sourceDir: string;
    let integrity: string;
    try {
      sourceDir = resolveSpec(entry.source, { cwd: options.cwd, cacheDir }).dir;
      integrity = digestTree(sourceDir).integrity;
    } catch (error) {
      skipped.push({ name: entry.name, reason: `could not resolve source: ${(error as Error).message}` });
      continue;
    }

    if (integrity !== entry.integrity && !options.force) {
      skipped.push({
        name: entry.name,
        reason: `content changed since it was locked (${entry.integrity.slice(0, 22)} -> ${integrity.slice(0, 22)}); run \`skillnotary lock\` to review the change, or pass --force`,
      });
      continue;
    }

    const previous = existingTreeDigest(dest);
    const action: AppliedSkill["action"] =
      previous === null ? "installed" : previous === integrity ? "unchanged" : "replaced";

    if (action === "replaced" && previous !== null) {
      warnings.push(
        `${entry.name}: replacing a different version already at ${dest} (its digest ${previous.slice(0, 22)} differs from the locked ${integrity.slice(0, 22)})`,
      );
    }

    if (action === "unchanged") {
      applied.push({ name: entry.name, dir: dest, files: entry.files, bytes: entry.bytes, action });
      continue;
    }

    if (options.dryRun) {
      applied.push({ name: entry.name, dir: dest, files: entry.files, bytes: entry.bytes, action });
      continue;
    }

    try {
      if (existsSync(dest)) rmSync(dest, { recursive: true, force: true });
      mkdirSync(dest, { recursive: true });
      const copied = copyTree(sourceDir, dest);

      // Verify what actually landed on disk. The invariant is "the copy is
      // faithful to the source we read", not "it matches the lockfile" — under
      // --force those differ by design, and the lockfile gate already ran.
      const written = digestTree(dest).integrity;
      if (written !== integrity) {
        skipped.push({
          name: entry.name,
          reason: `installed content does not match the source (${written.slice(0, 22)}); target may be on an unusual filesystem`,
        });
        continue;
      }
      applied.push({ name: entry.name, dir: dest, files: copied.files, bytes: copied.bytes, action });
    } catch (error) {
      skipped.push({ name: entry.name, reason: `copy failed: ${(error as Error).message}` });
    }
  }

  return { targetDir, applied, skipped, warnings };
}

/** Locked skills that are not present in the target directory. */
export function findMissing(lockfile: Lockfile, targetDir: string): LockedSkill[] {
  return lockfile.skills.filter((skill) => {
    try {
      assertSafeSkillDirName(skill.name);
    } catch {
      return false;
    }
    return !existsSync(join(targetDir, skill.name));
  });
}
