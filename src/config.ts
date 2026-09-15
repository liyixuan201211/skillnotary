import { globMatch, matchesAny, readTextFileSafe, writeTextFile, sri } from "./util.ts";
import { canonicalJson } from "./util.ts";
import { SEVERITY_ORDER } from "./types.ts";
import type { Finding, Severity, SuppressionDirective } from "./types.ts";

export const CONFIG_FILENAME = "skillnotary.config.json";

/** A rule can be forced to a severity, or turned off entirely. */
export type RuleSetting = Severity | "off";

export interface Config {
  version: 1;
  /** Per-rule severity override, or "off" to silence the rule. */
  rules?: Record<string, RuleSetting>;
  /**
   * Findings to drop. Two forms:
   *
   *   "vendor/*"            any finding whose path matches
   *   "R003:reference/*"    only rule R003, only on matching paths
   *
   * The rule-scoped form exists because a security skill's own documentation
   * necessarily contains the strings its rules look for — the capability table
   * in a reference doc lists `~/.ssh` without touching it. Scoping the exception
   * to a rule and a path keeps the exemption honest instead of blinding the
   * whole file.
   * `*` crosses `/`.
   */
  ignore?: string[];
  /** Skill names to skip entirely (still locked and verified). */
  ignoreSkills?: string[];
  /** Harness name -> install directory, used by `apply`. */
  targets?: Record<string, string>;
  /** Target used by `apply` when `--target` is not given. */
  defaultTarget?: string;
  /**
   * Honour `skillnotary-ignore` comments found inside skill files.
   *
   * **Default false, deliberately.** A skill is written by the party being
   * reviewed; if it could silence its own findings, the tool would be
   * bypassable by the very thing it is checking. Enable this only for skills
   * you author yourself, and note that honouring one is always reported.
   */
  allowInlineSuppressions?: boolean;
  /** Refuse an inline suppression that carries no `: reason`. */
  requireSuppressionReason?: boolean;
}

export function defaultConfig(): Config {
  return {
    version: 1,
    rules: {},
    ignore: [],
    ignoreSkills: [],
    targets: {
      "claude-code": ".claude/skills",
      agents: ".agents/skills",
      opencode: ".opencode/skills",
      "deepseek-harness": ".dsh/skills",
      codex: ".codex/skills",
      cursor: ".cursor/skills",
    },
    defaultTarget: "claude-code",
    allowInlineSuppressions: false,
    requireSuppressionReason: false,
  };
}

export function readConfig(cwd: string): Config | null {
  const raw = readTextFileSafe(`${cwd}/${CONFIG_FILENAME}`);
  if (raw === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`${CONFIG_FILENAME} is not valid JSON`);
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error(`${CONFIG_FILENAME} must be a JSON object`);
  }
  // Merge over defaults so a partial file is valid.
  return { ...defaultConfig(), ...(parsed as Partial<Config>), version: 1 };
}

export function writeConfig(cwd: string, config: Config): void {
  writeTextFile(`${cwd}/${CONFIG_FILENAME}`, `${canonicalJson(config)}\n`);
}

/**
 * Digest of the config file as written, or `null` when there is none.
 * Stored in the lockfile so that changing the suppression layer is drift.
 */
export function configDigest(cwd: string): string | null {
  const raw = readTextFileSafe(`${cwd}/${CONFIG_FILENAME}`);
  return raw === null ? null : sri(raw);
}

function isSeverity(value: string): value is Severity {
  return (SEVERITY_ORDER as readonly string[]).includes(value);
}

export interface ConfigApplication {
  findings: Finding[];
  /** Findings removed by config, with the reason. */
  suppressed: Array<{ finding: Finding; by: string }>;
  /** True when the whole skill was ignored by config. */
  ignoredSkill: boolean;
  warnings: string[];
}

/**
 * Apply the user's configuration to a skill's findings.
 *
 * This is the *only* place suppression happens, and it is driven by config the
 * user owns. Inline suppressions (which live in the skill, i.e. in attacker
 * controlled content) are ignored unless explicitly enabled.
 */
export function applyConfig(
  findings: Finding[],
  skillName: string,
  config: Config,
): ConfigApplication {
  const warnings: string[] = [];
  const suppressed: Array<{ finding: Finding; by: string }> = [];

  if (matchesAny(config.ignoreSkills, skillName) || config.ignoreSkills?.includes(skillName)) {
    return {
      findings: [],
      suppressed: findings.map((finding) => ({ finding, by: "config.ignoreSkills" })),
      ignoredSkill: true,
      warnings,
    };
  }

  // Validate configured rule ids so a typo cannot silently do nothing.
  for (const [rule, setting] of Object.entries(config.rules ?? {})) {
    if (setting !== "off" && !isSeverity(setting)) {
      warnings.push(`config.rules["${rule}"] is not a severity or "off"; ignored`);
    }
  }

  const kept: Finding[] = [];
  for (const finding of findings) {
    const setting = config.rules?.[finding.rule];

    if (setting === "off") {
      suppressed.push({ finding, by: `config.rules.${finding.rule}=off` });
      continue;
    }
    const ignoreHit = (config.ignore ?? []).find((entry) =>
      ignoreMatches(entry, finding.rule, finding.file),
    );
    if (ignoreHit !== undefined) {
      suppressed.push({ finding, by: `config.ignore matched ${ignoreHit}` });
      continue;
    }
    if (finding.suppression !== undefined) {
      // A directive written inside the skill itself.
      if (!config.allowInlineSuppressions) {
        warnings.push(
          `skill "${skillName}" contains an inline suppression for ${finding.rule} at ${finding.file}${finding.line !== undefined ? `:${finding.line}` : ""}; ignored because config.allowInlineSuppressions is false`,
        );
        kept.push(finding);
        continue;
      }
      if (config.requireSuppressionReason && finding.suppression.reason === "") {
        warnings.push(
          `inline suppression for ${finding.rule} in ${finding.file} has no reason and config.requireSuppressionReason is true; not honoured`,
        );
        kept.push(finding);
        continue;
      }
      suppressed.push({
        finding,
        by: `inline (${finding.file}${finding.suppression.line !== undefined ? `:${finding.suppression.line}` : ""}${finding.suppression.reason !== "" ? `: ${finding.suppression.reason}` : ""})`,
      });
      continue;
    }

    kept.push(setting !== undefined && isSeverity(setting) ? { ...finding, severity: setting } : finding);
  }

  return { findings: kept, suppressed, ignoredSkill: false, warnings };
}

/**
 * Match one ignore entry against a finding.
 *
 *   "vendor/*"          -> path glob only
 *   "R003:reference/*"  -> rule AND path
 */
export function ignoreMatches(entry: string, rule: string, file: string): boolean {
  const colon = entry.indexOf(":");
  if (colon > 0 && /^R\d{3}$/i.test(entry.slice(0, colon))) {
    return (
      entry.slice(0, colon).toUpperCase() === rule.toUpperCase() &&
      globMatch(entry.slice(colon + 1), file)
    );
  }
  return globMatch(entry, file);
}

export function effectiveRules(config: Config): Array<{ rule: string; setting: RuleSetting }> {
  return Object.entries(config.rules ?? {}).map(([rule, setting]) => ({ rule, setting }));
}

/** Resolve an `apply` destination from `--target`, falling back to config. */
export function resolveTarget(config: Config, target: string | undefined): { name: string; dir: string } {
  const name = target ?? config.defaultTarget ?? "claude-code";
  const dir = config.targets?.[name];
  if (dir !== undefined) return { name, dir };
  // Allow a raw path as the target.
  if (name.includes("/") || name.startsWith(".")) return { name, dir: name };
  throw new Error(
    `unknown apply target "${name}"; known targets: ${Object.keys(config.targets ?? {}).join(", ") || "none"}`,
  );
}

/** True when `config` mentions the rule at all. */
export function ruleMentioned(config: Config, rule: string): boolean {
  return config.rules?.[rule] !== undefined || (config.ignore ?? []).some((p) => globMatch(p, rule));
}

export type { SuppressionDirective };
