import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** A throwaway directory under the OS temp dir. */
export function tempDir(prefix = "skillnotary-test-"): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

/** Materialise a skill directory from a {relativePath: contents} map. */
export function makeSkill(files: Record<string, string>, prefix?: string): string {
  const dir = tempDir(prefix);
  for (const [rel, content] of Object.entries(files)) {
    const full = join(dir, rel);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content, "utf8");
  }
  return dir;
}

/** Absolute path to a checked-in fixture. */
export function fixture(name: string): string {
  return fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));
}
