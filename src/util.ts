import { createHash } from "node:crypto";
import {
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  lstatSync,
  statSync,
} from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";

/** Directories that never contribute to a skill digest. */
export const IGNORED_DIRS = new Set([".git", "node_modules", ".skillnotary", ".DS_Store"]);

/**
 * Hard limits so a hostile skill cannot exhaust memory or CPU.
 * A skill is untrusted input; everything it can make us do has to be bounded.
 */
export const LIMITS = {
  /** Refuse to analyse a skill with more entries than this. */
  maxFiles: 20_000,
  /** Only the first N bytes of a file are pattern-scanned. */
  maxScanBytesPerFile: 1024 * 1024,
  /** Total bytes pattern-scanned across one skill. */
  maxScanBytesTotal: 64 * 1024 * 1024,
  /** Total bytes hashed for one skill digest. */
  maxDigestBytes: 512 * 1024 * 1024,
} as const;

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

export interface WalkResult {
  /** Regular files, relative + POSIX-separated, sorted. */
  files: string[];
  /** Symlinks, relative + POSIX-separated, sorted. Never followed. */
  symlinks: string[];
  /** True when the walk stopped early because `maxFiles` was reached. */
  truncated: boolean;
}

/**
 * Walk a directory tree, never following a symlink.
 *
 * Symlinks are *reported* rather than traversed. Following them would let a
 * skill read (and digest) files outside its own directory — a `link -> ~/.ssh`
 * entry is enough — and a self-referential link would recurse until the OS
 * path limit stopped it.
 */
export function walkTree(root: string, maxFiles: number = LIMITS.maxFiles): WalkResult {
  const files: string[] = [];
  const symlinks: string[] = [];
  let truncated = false;

  const visit = (dir: string): void => {
    if (truncated) return;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      if (IGNORED_DIRS.has(entry)) continue;
      if (files.length + symlinks.length >= maxFiles) {
        truncated = true;
        return;
      }
      const full = join(dir, entry);
      let st;
      try {
        st = lstatSync(full); // lstat, not stat: never follow
      } catch {
        continue;
      }
      const rel = relative(root, full).split(sep).join("/");
      if (st.isSymbolicLink()) {
        symlinks.push(rel);
        continue;
      }
      if (st.isDirectory()) visit(full);
      else if (st.isFile()) files.push(rel);
    }
  };

  visit(root);
  return { files: files.sort(), symlinks: symlinks.sort(), truncated };
}

/** Recursively list regular files under `root`, following no symlinks. */
export function walkFiles(root: string): string[] {
  return walkTree(root).files;
}

/**
 * Make untrusted text safe to print to a terminal.
 *
 * A skill is untrusted content and its text lands in our report. Without this,
 * a skill can embed ANSI escapes to erase or rewrite the very lines that
 * describe it (`ESC[2K` plus a carriage return), i.e. forge its own audit
 * result. Control characters are replaced with U+FFFD so the tampering stays
 * visible instead of being silently dropped.
 */
export function sanitizeForTerminal(input: string): string {
  return input
    .replace(/\r\n?/g, "\n")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g, "\uFFFD")
    .replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u206A-\u206F\uFEFF\u2028\u2029]/g, "\uFFFD")
    .replace(/[\u{E0000}-\u{E007F}]/gu, "\uFFFD");
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
