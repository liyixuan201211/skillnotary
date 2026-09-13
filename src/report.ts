import type { CapabilityId, Finding, Severity, SkillAnalysis } from "./types.ts";
import { formatBytes, sanitizeForTerminal, sri } from "./util.ts";
import type { Drift } from "./lockfile.ts";
import type { PolicyViolation } from "./types.ts";

export interface RenderOptions {
  color: boolean;
  /** Show info-level findings. Default false. */
  showInfo?: boolean;
}

const ANSI = {
  reset: "\u001b[0m",
  bold: "\u001b[1m",
  dim: "\u001b[2m",
  red: "\u001b[31m",
  green: "\u001b[32m",
  yellow: "\u001b[33m",
  blue: "\u001b[34m",
  magenta: "\u001b[35m",
  cyan: "\u001b[36m",
  gray: "\u001b[90m",
} as const;

export function colorEnabled(explicit?: boolean): boolean {
  if (explicit !== undefined) return explicit;
  if (process.env["NO_COLOR"] !== undefined && process.env["NO_COLOR"] !== "") return false;
  return process.stdout.isTTY === true;
}

function paint(text: string, code: string, enabled: boolean): string {
  return enabled ? `${code}${text}${ANSI.reset}` : text;
}

const SEVERITY_STYLE: Record<Severity, keyof typeof ANSI> = {
  critical: "magenta",
  high: "red",
  medium: "yellow",
  low: "blue",
  info: "gray",
};

export function severityTag(severity: Severity, color: boolean): string {
  return paint(severity.toUpperCase().padEnd(8), ANSI[SEVERITY_STYLE[severity]], color);
}

export function ok(text: string, color: boolean): string {
  return paint(text, ANSI.green, color);
}

export function bad(text: string, color: boolean): string {
  return paint(text, ANSI.red, color);
}

export function dim(text: string, color: boolean): string {
  return paint(text, ANSI.dim, color);
}

export function bold(text: string, color: boolean): string {
  return paint(text, ANSI.bold, color);
}

export function shortIntegrity(integrity: string): string {
  if (integrity === "") return "-";
  return integrity.replace(/^sha256-/, "sha256:").slice(0, 22);
}

/** Render capabilities, highlighting the dangerous ones. */
export function renderCapabilities(caps: CapabilityId[], color: boolean): string {
  if (caps.length === 0) return dim("(none)", color);
  const risky: CapabilityId[] = ["secrets", "destructive", "privilege", "install", "exec"];
  return caps
    .map((c) => (risky.includes(c) ? paint(c, ANSI.yellow, color) : c))
    .join(", ");
}

/**
 * Everything a skill can influence goes through here before it is printed.
 *
 * `bold`/`dim`/`paint` only add *our* escapes; they do nothing about escapes
 * that arrived inside a skill. Without sanitising, a skill could embed ANSI
 * control sequences and rewrite the lines that report on it.
 */
const safe = sanitizeForTerminal;

export function formatFindings(
  findings: Finding[],
  skillName: string,
  options: RenderOptions,
): string {
  const { color, showInfo = false } = options;
  const visible = findings.filter((f) => showInfo || f.severity !== "info");
  if (visible.length === 0) return "";
  const lines: string[] = [];
  for (const f of visible) {
    const location = safe(`${f.file}${f.line !== undefined ? `:${f.line}` : ""}`);
    lines.push(
      `  ${severityTag(f.severity, color)} ${bold(f.rule, color)} ${safe(f.title)} ${dim(`(${safe(skillName)} ${location})`, color)}`,
    );
    lines.push(`           ${dim(safe(f.detail), color)}`);
    if (f.evidence) lines.push(`           ${paint(`> ${safe(f.evidence)}`, ANSI.gray, color)}`);
  }
  return lines.join("\n");
}

export function formatAnalysisSummary(
  analysis: SkillAnalysis,
  options: RenderOptions,
  displayName?: string,
): string {
  const { color } = options;
  const name = displayName ?? analysis.name;
  const lines: string[] = [];
  lines.push(
    `${bold(safe(name), color)} ${dim(`(${analysis.files} ${pluralize(analysis.files, "file")}, ${formatBytes(analysis.bytes)})`, color)}`,
  );
  lines.push(`  integrity   ${shortIntegrity(analysis.integrity)}`);
  lines.push(`  license     ${analysis.license === null ? dim("none", color) : safe(analysis.license)}`);
  lines.push(`  declared    ${renderCapabilities(analysis.declared.capabilities, color)}`);
  lines.push(`  observed    ${renderCapabilities(analysis.observed, color)}`);
  return lines.join("\n");
}

export function formatDrifts(drifts: Drift[], color: boolean): string {
  if (drifts.length === 0) return "";
  return drifts
    .map(
      (d) =>
        `  ${bad("✗", color)} ${bold(safe(d.name), color)} ${dim(`[${d.kind}]`, color)} ${safe(d.detail)}`,
    )
    .join("\n");
}

export function formatViolations(violations: PolicyViolation[], color: boolean): string {
  if (violations.length === 0) return "";
  return violations
    .map((v) => `  ${bad("✗", color)} ${bold(v.rule, color)} ${safe(v.message)}`)
    .join("\n");
}

/** Simple two-column-ish table for lockfile listings. */
export function formatLockTable(
  rows: Array<{ name: string; integrity: string; capabilities: CapabilityId[]; source: string }>,
  color: boolean,
): string {
  if (rows.length === 0) return dim("  (no skills)", color);
  const nameWidth = Math.max(4, ...rows.map((r) => r.name.length));
  const integWidth = 22;
  const lines = [
    dim(
      `  ${"SKILL".padEnd(nameWidth)}  ${"INTEGRITY".padEnd(integWidth)}  CAPABILITIES`,
      color,
    ),
  ];
  for (const row of rows) {
    lines.push(
      `  ${safe(row.name).padEnd(nameWidth)}  ${shortIntegrity(row.integrity).padEnd(integWidth)}  ${renderCapabilities(row.capabilities, color)}`,
    );
  }
  return lines.join("\n");
}

export function pluralize(count: number, singular: string, plural?: string): string {
  return count === 1 ? singular : (plural ?? `${singular}s`);
}

/** A stable digest of a string, handy for logging without dumping content. */
export function digestForLog(text: string): string {
  return sri(text).slice(0, 16);
}
