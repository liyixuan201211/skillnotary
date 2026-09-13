import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";

/** Directories that never contribute to a skill digest. */
export const IGNORED_DIRS = new Set([".git", "node_modules", ".skillnotary", ".DS_Store"]);

export function sha256Hex(input: string | Uint8Array): string {
  return createHash("sha256").update(input).digest("hex");
}

export function sha256Base64(input: string | Uint8Array): string {
  return createHash("sha256").update(input).digest("base64");
}

/** Subresource-Integrity style string, e.g. `sha256-KL0...`. */
export function sri(input: string | Uint8Array): string {
  return `sha256-${sha256Base64(input)}`;
}

export function readTextFile(path: string): string {
  return readFileSync(path, "utf8");
}

export function readTextFileSafe(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

export function writeTextFile(path: string, contents: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents, "utf8");
}

export function pathExists(path: string): boolean {
  return existsSync(path);
}

export function isDirectory(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

/** Recursively list files under `root`, relative and POSIX-separated, sorted. */
export function walkFiles(root: string): string[] {
  const out: string[] = [];
  const visit = (dir: string): void => {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      if (IGNORED_DIRS.has(entry)) continue;
      const full = join(dir, entry);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) visit(full);
      else if (st.isFile()) out.push(relative(root, full).split(sep).join("/"));
    }
  };
  visit(root);
  return out.sort();
}

/**
 * Stable JSON stringification: object keys sorted, so the same logical value
 * always produces the same bytes (needed for signatures over manifests).
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortDeep(value), null, 2);
}

function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value && typeof value === "object") {
    const src = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(src).sort()) out[key] = sortDeep(src[key]);
    return out;
  }
  return value;
}

/** Minimal glob matcher supporting `*` and `?`, anchored to the whole string. */
export function globMatch(pattern: string, value: string): boolean {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  const rx = new RegExp(`^${escaped.replace(/\*/g, ".*").replace(/\?/g, ".")}$`);
  return rx.test(value);
}

export function matchesAny(patterns: string[] | undefined, value: string): boolean {
  if (!patterns || patterns.length === 0) return false;
  return patterns.some((p) => globMatch(p, value));
}

export function resolveFrom(cwd: string, maybeRelative: string): string {
  return resolve(cwd, maybeRelative);
}

/** Human-readable byte count. */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}
