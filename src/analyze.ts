import {
  closeSync,
  fstatSync,
  openSync,
  readdirSync,
  readlinkSync,
  readSync,
  statSync,
} from "node:fs";
import { join } from "node:path";
import { digestTree } from "./hash.ts";
import { LIMITS, readTextFileSafe, walkTree } from "./util.ts";
import { RULES, SHELL_LANGUAGES, SIGNIFICANT_CAPABILITIES, TOOL_CAPABILITY_MAP } from "./patterns.ts";
import type { Rule } from "./patterns.ts";
import { ALL_CAPABILITIES } from "./types.ts";
import type {
  CapabilityId,
  DeclaredPermissions,
  Finding,
  Severity,
  SkillAnalysis,
  SuppressionDirective,
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

  // Null-prototype map: frontmatter keys come from an untrusted file, so it
  // must not be possible for `__proto__` / `constructor` to reach Object.prototype.
  const data: Record<string, string | string[]> = Object.create(null) as Record<
    string,
    string | string[]
  >;
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

/**
 * Read at most `maxBytes` from the head of a file.
 *
 * Only the head is ever pattern-scanned. A skill must not be able to make us
 * slurp an arbitrarily large file into memory just to run regexes over it.
 */
function readHead(path: string, maxBytes: number): Buffer {
  const fd = openSync(path, "r");
  try {
    const size = Math.min(Number(fstatSync(fd).size), maxBytes);
    const buf = Buffer.alloc(size);
    let read = 0;
    while (read < size) {
      const n = readSync(fd, buf, read, size - read, read);
      if (n <= 0) break;
      read += n;
    }
    return read === size ? buf : buf.subarray(0, read);
  } finally {
    closeSync(fd);
  }
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

/** How much of a file is read purely to classify it. */
const INSPECT_HEAD_BYTES = 4096;

/** A line longer than this suggests minified, packed or generated content. */
const OBFUSCATION_LINE_LENGTH = 5000;

/**
 * Compiled or executable formats. A skill has no reason to ship one, and a
 * binary cannot be reviewed by reading it, so their presence is a finding in
 * itself rather than something to silently skip.
 */
const EXECUTABLE_EXTENSIONS = new Set([
  ".exe", ".dll", ".so", ".dylib", ".node", ".bin", ".wasm", ".class", ".jar",
  ".war", ".pyc", ".pyo", ".o", ".obj", ".a", ".lib", ".dmg", ".pkg", ".deb",
  ".rpm", ".msi", ".app", ".com", ".scr", ".apk", ".ipa",
]);

/** Binary types that are legitimate skill assets, so they are not flagged. */
const SAFE_BINARY_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".bmp", ".ico", ".svg",
  ".pdf", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".m4a",
  ".wav", ".ogg", ".webm", ".mov", ".zip", ".tar", ".gz", ".tgz", ".bz2",
  ".xz", ".7z", ".rar", ".db", ".sqlite", ".sqlite3",
]);

function extensionOf(rel: string): string {
  const base = rel.split("/").pop() ?? "";
  const dot = base.lastIndexOf(".");
  return dot <= 0 ? "" : base.slice(dot).toLowerCase();
}

/** Classify an executable/compiled format from its magic bytes. */
function detectExecutableMagic(buf: Buffer): string | null {
  const b = buf;
  if (b.length >= 4 && b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) {
    return "an ELF binary";
  }
  if (b.length >= 4 && b[0] === 0xfe && b[1] === 0xed && b[2] === 0xfa) return "a Mach-O binary";
  if (b.length >= 4 && b[0] === 0xcf && b[1] === 0xfa && b[2] === 0xed && b[3] === 0xfe) {
    return "a Mach-O binary";
  }
  if (b.length >= 2 && b[0] === 0x4d && b[1] === 0x5a) return "a PE/Windows executable";
  if (b.length >= 4 && b[0] === 0x00 && b[1] === 0x61 && b[2] === 0x73 && b[3] === 0x6d) {
    return "a WebAssembly module";
  }
  if (b.length >= 4 && b[0] === 0xca && b[1] === 0xfe && b[2] === 0xba && b[3] === 0xbe) {
    return "a Java class file";
  }
  return null;
}

/** Length of the longest line, computed without splitting the whole string. */
function longestLineLength(text: string): number {
  let max = 0;
  let current = 0;
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10) {
      if (current > max) max = current;
      current = 0;
    } else {
      current++;
    }
  }
  return current > max ? current : max;
}

/**
 * Directives look like:
 *
 *   skillnotary-ignore-file R003 R004: reason
 *   skillnotary-ignore-next-line R002
 *   skillnotary-ignore-line R017
 *   skillnotary-ignore R021            (bare form == whole file)
 *
 * They are parsed here but never applied here — see `config.applyConfig`.
 */
export function parseSuppressions(rel: string, content: string): SuppressionDirective[] {
  const out: SuppressionDirective[] = [];
  const re = /skillnotary-ignore(?:-(file|next-line|line))?[ \t]+((?:R\d{3}[,\s]*)+)(?::[ \t]*(.*))?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    if (m[0].length === 0) {
      re.lastIndex++;
      continue;
    }
    const scope = (m[1] ?? "file") as SuppressionDirective["scope"];
    const rules = (m[2] ?? "").match(/R\d{3}/g) ?? [];
    const reason = (m[3] ?? "").trim();
    const line = content.slice(0, m.index).split("\n").length;
    for (const rule of rules) out.push({ rule, file: rel, line, scope, reason });
    if (out.length >= 200) break;
  }
  return out;
}

/**
 * Analyze a skill directory: extract declared and observed capabilities and
 * raise findings.
 */
export function analyzeSkill(dir: string, options: AnalyzeOptions = {}): SkillAnalysis {
  const tree = walkTree(dir);
  const files = tree.files;
  const scanTruncated: string[] = [];
  let scannedBytes = 0;
  const findings: Finding[] = [];
  const suppressions: SuppressionDirective[] = [];
  const observed = new Set<CapabilityId>();
  let description: string | null = null;
  let frontmatterName: string | null = null;
  let declared: DeclaredPermissions = { tools: [], capabilities: [] };
  let sawSkillMd = false;
  let sawFrontmatter = false;
  let frontmatterLicense: string | null = null;

  for (const rel of files) {
    const abs = join(dir, rel);
    const ext = extensionOf(rel);

    // Inspect the head before deciding anything: binaries and executables are
    // reported even though they are never text-scanned, because "compiled code
    // you cannot read" is precisely what a reviewer needs to be told about.
    let head: Buffer;
    try {
      head = readHead(abs, INSPECT_HEAD_BYTES);
    } catch {
      continue;
    }
    if (head.byteLength === 0) continue;

    const magic = detectExecutableMagic(head);
    if (magic !== null || EXECUTABLE_EXTENSIONS.has(ext)) {
      findings.push({
        rule: "R026",
        severity: "high",
        title: "Executable or compiled file in skill",
        detail: `Contains ${magic ?? "an executable file type"} (${rel}). Compiled payloads cannot be reviewed by reading them, and a skill has no reason to ship one.`,
        file: rel,
        capability: "exec",
      });
      observed.add("exec");
      continue;
    }

    if (looksBinary(head)) {
      if (!SAFE_BINARY_EXTENSIONS.has(ext)) {
        findings.push({
          rule: "R026",
          severity: "medium",
          title: "Unrecognised binary file in skill",
          detail: `Contains a binary file that is not a known document, image or archive type (${rel}). It was not scanned, so its contents are unreviewed.`,
          file: rel,
        });
      }
      continue;
    }

    if (!isScannable(rel)) continue;

    if (scannedBytes >= LIMITS.maxScanBytesTotal) {
      scanTruncated.push(rel);
      continue;
    }

    let fileSize = 0;
    try {
      fileSize = statSync(abs).size;
    } catch {
      continue;
    }
    if (fileSize > LIMITS.maxScanBytesPerFile) scanTruncated.push(rel);

    let buf = head;
    if (fileSize > INSPECT_HEAD_BYTES) {
      try {
        buf = readHead(abs, LIMITS.maxScanBytesPerFile);
      } catch {
        continue;
      }
    }
    scannedBytes += buf.byteLength;

    const content = buf.toString("utf8");

    // A single enormous line is what minified or packed payloads look like.
    const longest = longestLineLength(content);
    if (longest >= OBFUSCATION_LINE_LENGTH) {
      findings.push({
        rule: "R027",
        severity: "medium",
        title: "Possible minified or obfuscated content",
        detail: `${rel} has a line of ${longest} characters (threshold ${OBFUSCATION_LINE_LENGTH}). Packed or minified payloads hide their behaviour from review; ask for the source instead.`,
        file: rel,
      });
    }

    suppressions.push(...parseSuppressions(rel, content));

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

  // -------------------------------------------------------- structural rules
  // Symlinks are reported but never followed: a link pointing outside the skill
  // is a way to make review tooling read files it has no business reading.
  for (const rel of tree.symlinks) {
    let target = "";
    try {
      target = readlinkSync(join(dir, rel));
    } catch {
      /* unreadable link */
    }
    const escapes = target.startsWith("/") || target.split(/[/\\]/).includes("..");
    findings.push({
      rule: "R023",
      severity: escapes ? "high" : "medium",
      title: "Symlink in skill",
      detail: `Found a symlink (${rel} -> ${target === "" ? "?" : target}). skillnotary does not follow symlinks, so the target was neither read nor hashed. A link that points outside the skill is a way to make tooling read files it should not.`,
      file: rel,
    });
  }

  if (tree.truncated) {
    findings.push({
      rule: "R024",
      severity: "high",
      title: "Skill too large to review fully",
      detail: `The skill has at least ${LIMITS.maxFiles} entries, so the walk stopped early. The findings below are incomplete and a payload could sit beyond the limit.`,
      file: ".",
    });
  }

  if (scanTruncated.length > 0) {
    findings.push({
      rule: "R025",
      severity: "medium",
      title: "Scan truncated",
      detail: `${scanTruncated.length} file(s) exceeded the scan budget and were only read in part (${Math.round(LIMITS.maxScanBytesPerFile / 1048576)} MB per file, ${Math.round(LIMITS.maxScanBytesTotal / 1048576)} MB total). Findings for those files may be incomplete.`,
      file: scanTruncated[0] ?? ".",
    });
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

  // Attach the directive that covers each finding, if any. Nothing is dropped
  // here: whether a directive is *honoured* is a policy decision that belongs
  // to the user's config, not to the skill being reviewed.
  for (const finding of findings) {
    const directive = suppressions.find(
      (candidate) =>
        candidate.rule === finding.rule &&
        candidate.file === finding.file &&
        (candidate.scope === "file" ||
          (candidate.scope === "line" && candidate.line === finding.line) ||
          (candidate.scope === "next-line" && candidate.line + 1 === finding.line)),
    );
    if (directive !== undefined) finding.suppression = directive;
  }

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
    suppressions,
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
