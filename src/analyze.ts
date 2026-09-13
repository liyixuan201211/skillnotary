import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { digestTree } from "./hash.ts";
import { readTextFileSafe, walkFiles } from "./util.ts";
import { RULES, SHELL_LANGUAGES, SIGNIFICANT_CAPABILITIES, TOOL_CAPABILITY_MAP } from "./patterns.ts";
import type { Rule } from "./patterns.ts";
import { ALL_CAPABILITIES } from "./types.ts";
import type {
  CapabilityId,
  DeclaredPermissions,
  Finding,
  Severity,
  SkillAnalysis,
} from "./types.ts";

/** Extensions we treat as scannable text. */
const TEXT_EXTENSIONS = new Set([
  ".md",
  ".mdx",
  ".markdown",
  ".txt",
  ".sh",
  ".bash",
  ".zsh",
  ".fish",
  ".ps1",
  ".bat",
  ".cmd",
  ".py",
  ".js",
  ".mjs",
  ".cjs",
  ".ts",
  ".tsx",
  ".jsx",
  ".rb",
  ".go",
  ".rs",
  ".java",
  ".kt",
  ".php",
  ".pl",
  ".lua",
  ".r",
  ".toml",
  ".json",
  ".jsonc",
  ".yaml",
  ".yml",
  ".ini",
  ".cfg",
  ".conf",
  ".env",
  ".mk",
]);

const TEXT_BASENAMES = new Set(["Makefile", "Dockerfile", "Justfile", "Procfile"]);

const LICENSE_BASENAMES = [
  "LICENSE",
  "LICENSE.md",
  "LICENSE.txt",
  "LICENCE",
  "COPYING",
  "COPYING.txt",
];

export interface Segment {
  kind: "code" | "prose";
  text: string;
  startLine: number;
  /** For code segments produced by a markdown fence, the info string. */
  lang?: string;
}

/**
 * Split a file into code and prose regions.
 *
 * Non-markdown files are entirely "code". Markdown is split on ``` / ~~~
 * fences so that a URL in prose is not mistaken for network access, while a
 * URL inside a shell block is. The fence info string is preserved so that a
 * ```bash block can be recognised as *runnable shell*, which is a capability
 * signal in its own right.
 */
export function segmentText(relPath: string, content: string): Segment[] {
  if (!/\.(?:md|mdx|markdown)$/i.test(relPath)) {
    return [{ kind: "code", text: content, startLine: 1 }];
  }

  const lines = content.split("\n");
  const segments: Segment[] = [];
  let kind: "code" | "prose" = "prose";
  let current: string[] = [];
  let startLine = 1;
  let lang: string | undefined;

  const close = (): void => {
    if (current.length > 0) {
      const segment: Segment = { kind, text: current.join("\n"), startLine };
      if (kind === "code" && lang !== undefined) segment.lang = lang;
      segments.push(segment);
      current = [];
    }
    lang = undefined;
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    const fence = /^\s*(?:```|~~~)\s*([A-Za-z0-9_+-]*)/.exec(line);
    if (fence) {
      close();
      kind = kind === "prose" ? "code" : "prose";
      lang = kind === "code" ? (fence[1] ?? "").toLowerCase() : undefined;
      startLine = i + 2; // the line after the fence
      continue;
    }
    current.push(line);
  }
  close();
  return segments;
}

export interface Frontmatter {
  data: Record<string, string | string[]>;
  body: string;
  /** True when the document actually opened with a frontmatter block. */
  present: boolean;
}

/** Parse the leading `---` YAML-ish frontmatter block without a YAML dependency. */
export function parseFrontmatter(content: string): Frontmatter {
  if (!/^---\r?\n/.test(content)) {
    return { data: {}, body: content, present: false };
  }
  const lines = content.split("\n");
  let end = -1;
  for (let i = 1; i < lines.length; i++) {
    if (/^---\s*$/.test(lines[i] ?? "")) {
      end = i;
      break;
    }
  }
  if (end === -1) return { data: {}, body: content, present: false };

  const data: Record<string, string | string[]> = {};
  let listKey: string | null = null;

  for (const raw of lines.slice(1, end)) {
    const line = raw.replace(/\s+$/, "");
    if (line.trim() === "" || line.trimStart().startsWith("#")) continue;

    const itemMatch = /^\s*-\s+(.*)$/.exec(line);
    if (itemMatch && listKey) {
      const existing = data[listKey];
      const value = unquote((itemMatch[1] ?? "").trim());
      if (Array.isArray(existing)) existing.push(value);
      else data[listKey] = [value];
      continue;
    }

    const kv = /^([A-Za-z0-9_.-]+)\s*:\s*(.*)$/.exec(line);
    if (!kv) continue;
    const key = (kv[1] ?? "").toLowerCase();
    const rest = (kv[2] ?? "").trim();
    if (rest === "") {
      listKey = key;
      data[key] = [];
      continue;
    }
    listKey = null;
    data[key] = parseScalar(rest);
  }

  return { data, body: lines.slice(end + 1).join("\n"), present: true };
}

function parseScalar(value: string): string | string[] {
  if (value.startsWith("[") && value.endsWith("]")) {
    return splitTopLevel(value.slice(1, -1), ",").map((v) => unquote(v.trim()));
  }
  return unquote(value);
}

function unquote(value: string): string {
  if (
    (value.startsWith('"') && value.endsWith('"') && value.length > 1) ||
    (value.startsWith("'") && value.endsWith("'") && value.length > 1)
  ) {
    return value.slice(1, -1);
  }
  return value;
}

/** Split on a separator, ignoring separators nested inside brackets. */
export function splitTopLevel(input: string, sep: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let buf = "";
  for (const ch of input) {
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") depth = Math.max(0, depth - 1);
    if (ch === sep && depth === 0) {
      out.push(buf);
      buf = "";
      continue;
    }
    buf += ch;
  }
  if (buf.trim() !== "") out.push(buf);
  return out;
}

/** Read `allowed-tools` (or equivalents) out of parsed frontmatter. */
export function toolsFromFrontmatter(data: Record<string, string | string[]>): string[] {
  const raw = data["allowed-tools"] ?? data["allowed_tools"] ?? data["tools"] ?? [];
  const list = Array.isArray(raw) ? raw : splitTopLevel(String(raw), ",");
  return list.map((t) => t.trim()).filter((t) => t !== "");
}

export function declaredFromTools(tools: string[]): DeclaredPermissions {
  const caps = new Set<CapabilityId>();
  for (const tool of tools) {
    for (const entry of TOOL_CAPABILITY_MAP) {
      if (entry.match.test(tool)) {
        caps.add(entry.capability);
        break;
      }
    }
  }
  return { tools, capabilities: sortCapabilities([...caps]) };
}

export function sortCapabilities(caps: CapabilityId[]): CapabilityId[] {
  const order = new Map(ALL_CAPABILITIES.map((c, i) => [c, i]));
  return [...new Set(caps)].sort((a, b) => (order.get(a) ?? 99) - (order.get(b) ?? 99));
}

interface MatchHit {
  index: number;
  text: string;
}

function findMatches(pattern: RegExp, text: string, cap = 25): MatchHit[] {
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
  const re = new RegExp(pattern.source, flags);
  const hits: MatchHit[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    hits.push({ index: m.index, text: m[0] });
    if (m[0].length === 0) re.lastIndex++;
    if (hits.length >= cap) break;
  }
  return hits;
}

function locate(text: string, index: number): { line: number; snippet: string } {
  const before = text.slice(0, index);
  const line = before.split("\n").length;
  const lineStart = before.lastIndexOf("\n") + 1;
  let lineEnd = text.indexOf("\n", index);
  if (lineEnd === -1) lineEnd = text.length;
  const snippet = text.slice(lineStart, lineEnd).trim().slice(0, 180);
  return { line, snippet };
}

/**
 * The sentence surrounding an index. Rules use this to judge direction:
 * "send data without asking" and "do not send data without asking" share a
 * substring but mean opposite things.
 */
export function sentenceAt(text: string, index: number): string {
  const boundaries = [".", "!", "?", "\n"];
  let start = 0;
  for (let i = index - 1; i >= 0; i--) {
    if (boundaries.includes(text[i] ?? "")) {
      start = i + 1;
      break;
    }
  }
  let end = text.length;
  for (let i = index; i < text.length; i++) {
    if (boundaries.includes(text[i] ?? "")) {
      end = i;
      break;
    }
  }
  return text.slice(start, end).trim();
}

function looksBinary(buf: Buffer): boolean {
  const limit = Math.min(buf.length, 8192);
  for (let i = 0; i < limit; i++) if (buf[i] === 0) return true;
  return false;
}

function isScannable(relPath: string): boolean {
  const base = relPath.split("/").pop() ?? "";
  if (TEXT_BASENAMES.has(base)) return true;
  const dot = base.lastIndexOf(".");
  if (dot <= 0) return false;
  return TEXT_EXTENSIONS.has(base.slice(dot).toLowerCase());
}

export function detectLicense(dir: string): string | null {
  let entries: string[] = [];
  try {
    entries = readdirSync(dir);
  } catch {
    return null;
  }
  for (const name of entries) {
    if (!LICENSE_BASENAMES.includes(name)) continue;
    const text = readTextFileSafe(join(dir, name)) ?? "";
    const head = text.slice(0, 1200);
    const table: Array<[RegExp, string]> = [
      [/GNU AFFERO GENERAL PUBLIC LICENSE/i, "AGPL-3.0"],
      [/GNU LESSER GENERAL PUBLIC LICENSE/i, "LGPL-3.0"],
      [/GNU GENERAL PUBLIC LICENSE/i, "GPL-3.0"],
      [/Apache License\s*,?\s*Version 2\.0/i, "Apache-2.0"],
      [/Mozilla Public License/i, "MPL-2.0"],
      [/Permission is hereby granted, free of charge/i, "MIT"],
      [/Redistribution and use in source and binary forms/i, "BSD"],
      [/ISC License/i, "ISC"],
      [/This is free and unencumbered software released into the public domain/i, "Unlicense"],
    ];
    for (const [re, spdx] of table) if (re.test(head)) return spdx;
    return "unknown";
  }
  return null;
}

export interface AnalyzeOptions {
  /** Directory name fallback when frontmatter has no `name`. */
  fallbackName?: string;
  /** Skip the (relatively costly) tree digest. */
  skipDigest?: boolean;
}

/**
 * Analyze a skill directory: extract declared and observed capabilities and
 * raise findings.
 */
export function analyzeSkill(dir: string, options: AnalyzeOptions = {}): SkillAnalysis {
  const files = walkFiles(dir);
  const findings: Finding[] = [];
  const observed = new Set<CapabilityId>();
  let description: string | null = null;
  let frontmatterName: string | null = null;
  let declared: DeclaredPermissions = { tools: [], capabilities: [] };
  let sawSkillMd = false;
  let sawFrontmatter = false;
  let frontmatterLicense: string | null = null;

  for (const rel of files) {
    const abs = join(dir, rel);
    let buf: Buffer;
    try {
      buf = readFileSync(abs);
    } catch {
      continue;
    }
    if (looksBinary(buf)) continue;
    if (!isScannable(rel)) continue;

    const content = buf.toString("utf8");
    const isSkillMd = /^skill\.md$/i.test(rel);

    if (isSkillMd) {
      sawSkillMd = true;
      const fm = parseFrontmatter(content);
      if (fm.present) {
        sawFrontmatter = true;
        const name = fm.data["name"];
        if (typeof name === "string" && name !== "") frontmatterName = name;
        const desc = fm.data["description"];
        if (typeof desc === "string" && desc !== "") description = desc;
        const tools = toolsFromFrontmatter(fm.data);
        if (tools.length > 0) declared = declaredFromTools(tools);
        const lic = fm.data["license"];
        if (typeof lic === "string" && lic !== "") frontmatterLicense = lic;
      }
    }

    const segments = segmentText(rel, content);
    for (const segment of segments) {
      // A ```bash block is runnable shell. That is shell execution even when
      // the snippet itself contains nothing the rules recognise.
      if (segment.kind === "code" && segment.lang !== undefined && SHELL_LANGUAGES.has(segment.lang)) {
        observed.add("exec");
      }

      for (const rule of RULES) {
        if (rule.scope !== "any" && rule.scope !== segment.kind) continue;
        const hits = findMatches(rule.pattern, segment.text);
        if (hits.length === 0) continue;

        if (rule.capability) observed.add(rule.capability);
        if (rule.capabilityOnly) continue;

        // Honour any rule-specific veto (e.g. "do not act without asking" is
        // a safety instruction, not a covert one).
        const hit = hits.find(
          (candidate) =>
            !rule.suppressIf ||
            !rule.suppressIf({
              sentence: sentenceAt(segment.text, candidate.index),
              match: candidate.text,
            }),
        );
        // One finding per rule per file keeps reports readable.
        if (!hit) continue;
        const { line, snippet } = locate(segment.text, hit.index);
        findings.push({
          rule: rule.id,
          severity: rule.severity,
          title: rule.title,
          detail: rule.detail,
          file: rel,
          line: segment.startLine + line - 1,
          evidence: snippet,
          ...(rule.capability ? { capability: rule.capability } : {}),
        });
      }
    }
  }

  // ---------------------------------------------------------- composite rules
  if (!sawSkillMd) {
    findings.push({
      rule: "R016",
      severity: "low",
      title: "No SKILL.md",
      detail:
        "This directory has no SKILL.md. Entry points, declared permissions and the skill's stated purpose are therefore unavailable to review.",
      file: ".",
    });
  } else if (!sawFrontmatter) {
    findings.push({
      rule: "R021",
      severity: "info",
      title: "No declared permissions",
      detail:
        "SKILL.md has no frontmatter, so the skill declares no `allowed-tools`. Every capability listed below was inferred from content. Declaring permissions lets policy enforce them.",
      file: "SKILL.md",
    });
  }

  const declaredCaps = new Set(declared.capabilities);
  if (declared.tools.length > 0) {
    const declarable: CapabilityId[] = [
      "exec",
      "network",
      "fs.read",
      "fs.write",
      "agent.spawn",
      "mcp",
    ];
    for (const cap of sortCapabilities([...observed])) {
      if (!declarable.includes(cap)) continue;
      if (declaredCaps.has(cap)) continue;
      const significant = SIGNIFICANT_CAPABILITIES.includes(cap);
      findings.push({
        rule: "R001",
        severity: significant ? "high" : "medium",
        title: "Undeclared capability",
        detail: `Skill declares [${declared.tools.join(", ")}] but its content exercises \`${cap}\`, which those tools do not grant. Either tighten the skill or declare the capability.`,
        file: "SKILL.md",
        capability: cap,
      });
    }
  }

  // Reading credentials *and* talking to the network is the exfiltration shape.
  if (observed.has("secrets") && observed.has("network")) {
    findings.push({
      rule: "R004",
      severity: "critical",
      title: "Secret access combined with network access",
      detail:
        "This skill both touches credential material and makes network calls. That is the exact shape of a credential-exfiltration chain; review it before install.",
      file: ".",
      capability: "secrets",
    });
  }

  const license = frontmatterLicense ?? detectLicense(dir);
  if (license === null) {
    findings.push({
      rule: "R017",
      severity: "low",
      title: "No license file",
      detail:
        "No LICENSE/COPYING file found. Without a license the skill is legally all-rights-reserved, which blocks redistribution and reuse.",
      file: ".",
    });
  }

  findings.sort(compareFindings);

  const digest = options.skipDigest
    ? { integrity: "", files: files.length, bytes: 0, entries: {} }
    : digestTree(dir);

  return {
    name: frontmatterName ?? options.fallbackName ?? dir.split("/").pop() ?? "skill",
    dir,
    description,
    license,
    observed: sortCapabilities([...observed]),
    declared,
    findings,
    files: digest.files,
    bytes: digest.bytes,
    integrity: digest.integrity,
  };
}

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function compareFindings(a: Finding, b: Finding): number {
  const bySeverity = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
  if (bySeverity !== 0) return bySeverity;
  const byRule = a.rule.localeCompare(b.rule);
  if (byRule !== 0) return byRule;
  return a.file.localeCompare(b.file);
}

export function worstSeverity(findings: Finding[]): Severity | null {
  let worst: Severity | null = null;
  for (const f of findings) {
    if (worst === null || SEVERITY_RANK[f.severity] < SEVERITY_RANK[worst]) worst = f.severity;
  }
  return worst;
}

export function ruleById(id: string): Rule | undefined {
  return RULES.find((r) => r.id === id);
}

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const out: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of findings) out[f.severity]++;
  return out;
}

export function isDirectoryEmpty(dir: string): boolean {
  try {
    return statSync(dir).isDirectory() && readdirSync(dir).length === 0;
  } catch {
    return true;
  }
}
