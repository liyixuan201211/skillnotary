import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { sri, sha256Hex, walkFiles } from "./util.ts";

export interface TreeDigest {
  integrity: string;
  files: number;
  bytes: number;
  /** Map of relative path -> per-file sha256 hex. Used for drift reporting. */
  entries: Record<string, string>;
}

/**
 * Deterministic digest of a directory tree.
 *
 * Determinism rules (so two machines agree):
 *  - files are walked and sorted by POSIX relative path
 *  - each file contributes `path\0<sha256(content)>\n` to the digest input
 *  - `.git`, `node_modules`, `.DS_Store` and `.skillnotary` are skipped
 *  - path separators are normalised to `/`
 *
 * This means the digest depends on file *contents* and *names*, not on
 * mtimes, permissions or walk order.
 */
export function digestTree(root: string): TreeDigest {
  const files = walkFiles(root);
  const entries: Record<string, string> = {};
  const lines: string[] = [];
  let bytes = 0;

  for (const rel of files) {
    let buf: Buffer;
    try {
      buf = readFileSync(join(root, rel));
    } catch {
      continue;
    }
    const hex = sha256Hex(buf);
    entries[rel] = hex;
    bytes += buf.byteLength;
    lines.push(`${rel}\u0000${hex}\n`);
  }

  return {
    integrity: sri(lines.join("")),
    files: files.length,
    bytes,
    entries,
  };
}

export function dirSize(root: string): number {
  let total = 0;
  for (const rel of walkFiles(root)) {
    try {
      total += statSync(join(root, rel)).size;
    } catch {
      /* ignore */
    }
  }
  return total;
}
