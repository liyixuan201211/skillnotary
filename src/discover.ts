import { existsSync, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { readTextFileSafe } from "./util.ts";

/**
 * Known places agent harnesses keep skills, so `skillnotary discover` can find
 * what is already installed before you start locking things.
 *
 * `project` paths are relative to the working directory, `user` paths to $HOME.
 */
export interface HarnessLayout {
  harness: string;
  project: string[];
  user: string[];
}

export const HARNESS_LAYOUTS: HarnessLayout[] = [
  { harness: "claude-code", project: [".claude/skills"], user: [".claude/skills"] },
  { harness: "agents", project: [".agents/skills"], user: [".agents/skills"] },
  { harness: "opencode", project: [".opencode/skills"], user: [".config/opencode/skills"] },
  { harness: "deepseek-harness", project: [".dsh/skills"], user: [".dsh/skills"] },
  { harness: "codex", project: [".codex/skills"], user: [".codex/skills"] },
  { harness: "cursor", project: [".cursor/skills"], user: [".cursor/skills"] },
  { harness: "generic", project: ["skills"], user: [] },
];

export interface DiscoveredSkill {
  name: string;
  dir: string;
  harness: string;
  scope: "project" | "user";
  /** True when the directory looks like a skill (has SKILL.md). */
  looksLikeSkill: boolean;
}

export interface DiscoverOptions {
  cwd: string;
  home?: string;
  /** Include directories that have no SKILL.md. Default false. */
  includeBareDirectories?: boolean;
}

export function discoverSkills(options: DiscoverOptions): DiscoveredSkill[] {
  const home = options.home ?? homedir();
  const found: DiscoveredSkill[] = [];
  const seen = new Set<string>();

  const scan = (base: string, harness: string, scope: "project" | "user"): void => {
    if (!existsSync(base)) return;
    let entries: string[];
    try {
      entries = readdirSync(base);
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.startsWith(".")) continue;
      const dir = join(base, entry);
      try {
        if (!statSync(dir).isDirectory()) continue;
      } catch {
        continue;
      }
      const looksLikeSkill =
        existsSync(join(dir, "SKILL.md")) ||
        existsSync(join(dir, "skill.md")) ||
        existsSync(join(dir, "README.md"));
      if (!looksLikeSkill && !options.includeBareDirectories) continue;
      const key = `${harness}:${dir}`;
      if (seen.has(key)) continue;
      seen.add(key);
      found.push({ name: entry, dir, harness, scope, looksLikeSkill });
    }
  };

  for (const layout of HARNESS_LAYOUTS) {
    for (const rel of layout.project) scan(join(options.cwd, rel), layout.harness, "project");
    for (const rel of layout.user) scan(join(home, rel), layout.harness, "user");
  }

  found.sort((a, b) => a.name.localeCompare(b.name));
  return found;
}

/** Read the `name:` field from a SKILL.md, if present. */
export function readSkillName(dir: string): string | null {
  const raw = readTextFileSafe(join(dir, "SKILL.md")) ?? readTextFileSafe(join(dir, "skill.md"));
  if (raw === null) return null;
  const match = /^---\r?\n([\s\S]*?)\r?\n---/.exec(raw);
  const scope = match?.[1] ?? raw;
  const name = /^\s*name\s*:\s*(.+)$/m.exec(scope);
  return name?.[1] ? name[1].trim().replace(/^["']|["']$/g, "") : null;
}
