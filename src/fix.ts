import { join } from "node:path";
import { readTextFileSafe, writeTextFile } from "./util.ts";
import { parseFrontmatter, toolsFromFrontmatter } from "./analyze.ts";
import type { CapabilityId, SkillAnalysis } from "./types.ts";

/**
 * Reverse of the tool→capability map: which `allowed-tools` entry grants a
 * capability.
 *
 * `secrets`, `destructive`, `install` and `privilege` are refinements of
 * running shell commands, not separately declarable tools, so they map to
 * `null` — declaring `Bash` is all a skill can honestly say about them.
 */
const CAPABILITY_TOOL: Record<CapabilityId, string | null> = {
  exec: "Bash",
  network: "WebFetch",
  "fs.read": "Read",
  "fs.write": "Write",
  "agent.spawn": "Task",
  mcp: "mcp",
  secrets: null,
  destructive: null,
  install: null,
  privilege: null,
};

export function toolsForCapabilities(capabilities: CapabilityId[]): string[] {
  const out: string[] = [];
  for (const capability of capabilities) {
    const tool = CAPABILITY_TOOL[capability];
    if (tool !== null && !out.includes(tool)) out.push(tool);
  }
  return out.sort();
}

export interface FixPlan {
  skillName: string;
  /** Absolute path of the file that would change. */
  file: string;
  changed: boolean;
  /** Why nothing would change, when `changed` is false. */
  reason?: string;
  /** The merged declaration that would be written. */
  tools: string[];
  addedTools: string[];
  keptTools: string[];
  removed: string[];
  added: string[];
  before: string;
  after: string;
  newContent: string;
}

const KEY_RE = /^([A-Za-z0-9_.-]+)\s*:/;
const TOOL_KEYS = new Set(["allowed-tools", "allowed_tools", "tools"]);

interface FrontmatterRange {
  /** Index of the opening `---`. */
  open: number;
  /** Index of the closing `---`. */
  close: number;
}

function locateFrontmatter(lines: string[]): FrontmatterRange | null {
  if ((lines[0] ?? "").trim() !== "---") return null;
  for (let i = 1; i < lines.length; i++) {
    if ((lines[i] ?? "").trim() === "---") return { open: 0, close: i };
  }
  return null;
}

/**
 * Work out how to make a skill's `allowed-tools` match what it actually does.
 *
 * Deliberately additive: tools are only ever *added*, never removed, so the fix
 * cannot silently take away a permission the skill genuinely needs (which would
 * break it). The result is a plan; nothing is written until `writeFix` is called.
 */
export function planAllowedTools(dir: string, analysis: SkillAnalysis): FixPlan {
  const file = join(dir, "SKILL.md");
  const raw = readTextFileSafe(file);
  const desired = toolsForCapabilities(analysis.observed);

  const base: FixPlan = {
    skillName: analysis.name,
    file,
    changed: false,
    tools: desired,
    addedTools: [],
    keptTools: [],
    removed: [],
    added: [],
    before: "",
    after: "",
    newContent: raw ?? "",
  };

  if (raw === null) {
    return { ...base, reason: "no SKILL.md to fix" };
  }

  const lines = raw.split("\n");
  const range = locateFrontmatter(lines);

  // Existing declarations, for the merge and for reporting.
  const existing = toolsFromFrontmatter(parseFrontmatter(raw).data);
  const merged = [...existing];
  for (const tool of desired) if (!merged.includes(tool)) merged.push(tool);
  merged.sort();
  const addedTools = merged.filter((t) => !existing.includes(t));

  if (desired.length === 0) {
    return { ...base, keptTools: existing, reason: "no capabilities observed; nothing to declare" };
  }
  if (addedTools.length === 0 && existing.length > 0) {
    return { ...base, tools: merged, keptTools: existing, reason: "allowed-tools already covers what the skill does" };
  }

  const insertLine = `allowed-tools: ${merged.join(", ")}`;

  if (range === null) {
    // No frontmatter at all: create a minimal one.
    const created = ["---", `name: ${analysis.name}`, insertLine, "---", ""];
    const newContent = [...created, ...lines].join("\n");
    const after = created.slice(0, 4).join("\n");
    return {
      ...base,
      changed: true,
      tools: merged,
      addedTools,
      keptTools: existing,
      added: [insertLine],
      before: "",
      after,
      newContent,
    };
  }

  // Find the existing tool key (inline or list form) inside the frontmatter.
  let keyLine = -1;
  let lastLine = -1;
  for (let i = range.open + 1; i < range.close; i++) {
    const match = KEY_RE.exec(lines[i] ?? "");
    if (match === null) continue;
    if (!TOOL_KEYS.has((match[1] ?? "").toLowerCase())) continue;
    keyLine = i;
    lastLine = i;
    const value = (lines[i] ?? "").slice(match[0].length).trim();
    if (value === "") {
      // Block list form: consume the following "- item" lines.
      let j = i + 1;
      while (j < range.close && /^\s*-\s+/.test(lines[j] ?? "")) j++;
      lastLine = j - 1;
    }
    break;
  }

  const removed: string[] = [];
  const next = [...lines];

  if (keyLine === -1) {
    next.splice(range.close, 0, insertLine);
    while (next.length <= range.close) next.push("");
  } else {
    removed.push(...next.slice(keyLine, lastLine + 1));
    next.splice(keyLine, lastLine - keyLine + 1, insertLine);
  }

  const before = lines.slice(range.open, range.close + 1).join("\n");
  const newClose = range.close + (keyLine === -1 ? 1 : 0);
  const after = next.slice(range.open, newClose + 1).join("\n");

  return {
    ...base,
    changed: true,
    tools: merged,
    addedTools,
    keptTools: existing,
    removed,
    added: [insertLine],
    before,
    after,
    newContent: next.join("\n"),
  };
}

export function writeFix(plan: FixPlan): void {
  if (!plan.changed) return;
  writeTextFile(plan.file, plan.newContent);
}
