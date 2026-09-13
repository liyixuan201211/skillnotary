#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join, resolve } from "node:path";
import { parseArgs } from "node:util";

import { analyzeSkill, countBySeverity, worstSeverity } from "./analyze.ts";
import {
  buildLockfile,
  diffLockfiles,
  LOCKFILE_FILENAME,
  lockfilePath,
  readLockfile,
  writeLockfile,
} from "./lockfile.ts";
import {
  emptyManifest,
  MANIFEST_FILENAME,
  readManifest,
  upsertSkill,
  writeManifest,
} from "./manifest.ts";
import {
  atLeast,
  defaultPolicy,
  evaluatePolicy,
  POLICY_FILENAME,
  readPolicy,
  writePolicy,
} from "./policy.ts";
import { buildSbom } from "./sbom.ts";
import {
  ATTEST_FILENAME,
  attestationPath,
  generateKeyPair,
  KEYFILE_FILENAME,
  keyId,
  readAttestation,
  readKeyFile,
  signPayload,
  verifyPayload,
  writeKeyFile,
} from "./attest.ts";
import { discoverSkills, readSkillName } from "./discover.ts";
import { CACHE_DIRNAME, resolveSpec } from "./source.ts";
import { sanitizeForTerminal, sha256Hex } from "./util.ts";
import { GENERATOR, VERSION } from "./version.ts";
import * as R from "./report.ts";
import {
  applyConfig,
  CONFIG_FILENAME,
  configDigest,
  defaultConfig,
  readConfig,
  resolveTarget,
  writeConfig,
} from "./config.ts";
import type { Config } from "./config.ts";
import { applySkills } from "./apply.ts";
import { planAllowedTools, toolsForCapabilities, writeFix } from "./fix.ts";
import type {
  CapabilityId,
  Finding,
  ManifestSkill,
  Severity,
  SkillAnalysis,
} from "./types.ts";

const HELP = `skillnotary ${VERSION} — lockfile, provenance and capability policy for AI agent skills

USAGE
  skillnotary <command> [options]

COMMANDS
  init                    Create skills.json, a default policy and a config
  add <source>            Add a skill to the manifest (path, github:owner/repo#sub/path@ref)
  lock                    Resolve the manifest and write skills.lock
  verify                  Check the working tree against skills.lock (drift + attestation)
  audit                   Static capability and risk report
  fix                     Declare the capabilities a skill actually uses (--dry-run)
  policy                  Evaluate the policy against the locked skills
  apply                   Install the locked skills into a harness directory
  keygen                  Generate an ed25519 signing keypair
  sign                    Attest skills.lock with your key
  sbom                    Emit an SBOM for the locked skills
  discover                Find skills installed in known harness locations
  config                  Show the effective configuration
  ci                      verify + policy + audit, for CI pipelines
  help                    Show this help

OPTIONS
  --json                  Machine-readable output
  --out <path>            Write output to a file
  --key <path>            Signing keyfile (default $KEYFILE_FILENAME)
  --name <name>           Name to record for an added skill
  --refresh               Re-clone git sources instead of using the cache
  --check                 Do not write; fail if the lockfile would change
  --min-severity <s>      info|low|medium|high|critical (default: high)
  --skill <name>          Limit to a skill (repeatable)
  --target <name|path>    Install target for "apply" (default: config.defaultTarget)
  --dry-run               Show what would happen without writing anything
  --fix                   With "add", also declare allowed-tools in SKILL.md
  --force                 Apply even if content differs from the lockfile
  --[no-]color            Force or disable colour
  -h, --help              Show this help
  -v, --version           Print the version

EXAMPLES
  skillnotary init
  skillnotary add github:acme/skills#pdf-tools@v1.2.0 --fix
  skillnotary lock && skillnotary audit
  skillnotary keygen && skillnotary sign && skillnotary verify
  skillnotary apply --target claude-code --dry-run
  skillnotary ci
`;

const OPTIONS = {
  json: { type: "boolean" as const },
  out: { type: "string" as const },
  key: { type: "string" as const },
  name: { type: "string" as const },
  refresh: { type: "boolean" as const },
  check: { type: "boolean" as const },
  force: { type: "boolean" as const },
  "min-severity": { type: "string" as const },
  skill: { type: "string" as const, multiple: true },
  target: { type: "string" as const },
  "dry-run": { type: "boolean" as const },
  fix: { type: "boolean" as const },
  color: { type: "boolean" as const },
  "no-color": { type: "boolean" as const },
  "include-bare": { type: "boolean" as const },
  help: { type: "boolean" as const, short: "h" },
  version: { type: "boolean" as const, short: "v" },
};

interface Parsed {
  values: Record<string, unknown>;
  positionals: string[];
}

function parse(argv: string[]): Parsed {
  const { values, positionals } = parseArgs({
    args: argv,
    options: OPTIONS,
    allowPositionals: true,
    strict: false,
  });
  return { values: values as Record<string, unknown>, positionals };
}

function str(values: Record<string, unknown>, key: string): string | undefined {
  const v = values[key];
  return typeof v === "string" ? v : undefined;
}

function bool(values: Record<string, unknown>, key: string): boolean {
  return values[key] === true;
}

function strList(values: Record<string, unknown>, key: string): string[] {
  const v = values[key];
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === "string");
  if (typeof v === "string") return [v];
  return [];
}

function asSeverity(input: string | undefined, fallback: Severity): Severity {
  const valid: Severity[] = ["info", "low", "medium", "high", "critical"];
  if (input && (valid as string[]).includes(input)) return input as Severity;
  return fallback;
}

interface Context {
  cwd: string;
  color: boolean;
  values: Record<string, unknown>;
  positionals: string[];
}

// --------------------------------------------------------------------- helpers

function manifestPath(cwd: string): string {
  return join(cwd, MANIFEST_FILENAME);
}

function policyPath(cwd: string): string {
  return join(cwd, POLICY_FILENAME);
}

interface AttestationStatus {
  present: boolean;
  valid: boolean;
  reason?: string;
  keyId?: string;
  format?: "legacy" | "dsse";
}

function checkAttestation(cwd: string): AttestationStatus {
  const att = readAttestation(attestationPath(cwd));
  const lock = lockfilePath(cwd);
  if (!att) return { present: false, valid: false };
  if (!existsSync(lock)) {
    return { present: true, valid: false, reason: "skills.lock is missing" };
  }
  const result = verifyPayload(att, readFileSync(lock));
  return {
    present: true,
    valid: result.valid,
    ...(result.reason !== undefined ? { reason: result.reason } : {}),
    ...(result.keyId !== undefined ? { keyId: result.keyId } : {}),
    ...(result.format !== undefined ? { format: result.format } : {}),
  };
}

function loadConfig(cwd: string): Config {
  return readConfig(cwd) ?? defaultConfig();
}

interface Prepared {
  name: string;
  dir: string;
  analysis: SkillAnalysis;
  /** Findings after the config layer has been applied. */
  effective: Finding[];
  suppressed: Array<{ finding: Finding; by: string }>;
  /** Things the config layer wanted to say but could not act on. */
  warnings: string[];
  ignoredSkill: boolean;
}

/** Resolve, analyse, then apply the config layer. */
function prepareSkill(
  cwd: string,
  entry: ManifestSkill,
  config: Config,
  refresh: boolean,
): Prepared {
  const resolved = resolveSpec(entry.source, {
    cwd,
    cacheDir: join(cwd, CACHE_DIRNAME),
    refresh,
  });
  const analysis = analyzeSkill(resolved.dir, { fallbackName: entry.name });
  const application = applyConfig(analysis.findings, entry.name, config);
  return {
    name: entry.name,
    dir: resolved.dir,
    analysis,
    effective: application.findings,
    suppressed: application.suppressed,
    warnings: application.warnings,
    ignoredSkill: application.ignoredSkill,
  };
}

/**
 * Report what the config layer did. Suppression is never silent: if a finding
 * was dropped, the user is told how many and by what — and if a directive was
 * refused, that is said out loud too.
 */
function reportSuppressed(prepared: Prepared, color: boolean): void {
  for (const warning of prepared.warnings) {
    console.log(R.bad(`  ! ${sanitizeForTerminal(warning)}`, color));
  }
  if (prepared.ignoredSkill) {
    console.log(R.dim(`  · ${prepared.name}: ignored by config.ignoreSkills`, color));
    return;
  }
  if (prepared.suppressed.length === 0) return;
  const by = [...new Set(prepared.suppressed.map((s) => s.by))];
  console.log(
    R.dim(`  · ${prepared.suppressed.length} finding(s) suppressed (${by.join("; ")})`, color),
  );
}

// -------------------------------------------------------------------- commands

function cmdConfig(ctx: Context): number {
  const { cwd, color, values } = ctx;
  const config = loadConfig(cwd);
  const digest = configDigest(cwd);

  if (bool(values, "json")) {
    console.log(JSON.stringify({ config, digest }, null, 2));
    return 0;
  }

  console.log(
    R.bold(CONFIG_FILENAME, color) +
      R.dim(digest === null ? "  (absent — using defaults)" : `  ${digest.slice(0, 22)}`, color),
  );
  console.log(`  locked digest  ${digest ?? "none"}`);

  const entries = Object.entries(config.rules ?? {});
  console.log("");
  console.log(R.bold("rule overrides", color));
  if (entries.length === 0) console.log(R.dim("  (none)", color));
  for (const [rule, setting] of entries) console.log(`  ${rule.padEnd(6)} -> ${setting}`);

  console.log("");
  console.log(R.bold("ignore (file globs)", color));
  console.log(config.ignore && config.ignore.length > 0 ? `  ${config.ignore.join(", ")}` : R.dim("  (none)", color));
  console.log(R.bold("ignoreSkills", color));
  console.log(
    config.ignoreSkills && config.ignoreSkills.length > 0
      ? `  ${config.ignoreSkills.join(", ")}`
      : R.dim("  (none)", color),
  );

  console.log("");
  console.log(R.bold("inline suppressions", color));
  console.log(
    config.allowInlineSuppressions
      ? `  ${R.bad("honoured", color)} ${R.dim("— skills can silence their own findings", color)}`
      : `  ${R.ok("ignored", color)} ${R.dim("(default; skills cannot silence themselves)", color)}`,
  );

  console.log("");
  console.log(R.bold("apply targets", color));
  for (const [name, dir] of Object.entries(config.targets ?? {})) {
    const marker = name === config.defaultTarget ? R.dim("  (default)", color) : "";
    console.log(`  ${name.padEnd(18)} ${dir}${marker}`);
  }
  return 0;
}

function cmdApply(ctx: Context): number {
  const { cwd, color, values } = ctx;
  const config = loadConfig(cwd);
  const lockfile = readLockfile(lockfilePath(cwd));
  if (!lockfile) {
    console.error(`error: no ${LOCKFILE_FILENAME}; run \`skillnotary lock\` first`);
    return 2;
  }

  let target: { name: string; dir: string };
  try {
    target = resolveTarget(config, str(values, "target"));
  } catch (error) {
    console.error(`error: ${(error as Error).message}`);
    return 2;
  }

  // Installing content that no longer matches the lockfile defeats the point,
  // so treat drift as fatal unless --force is given.
  const manifest = readManifest(manifestPath(cwd)) ?? emptyManifest();
  const { lockfile: fresh } = buildLockfile({ cwd, manifest, refresh: bool(values, "refresh") });
  const drifts = diffLockfiles(lockfile, fresh);
  if (drifts.length > 0 && !bool(values, "force")) {
    console.log(R.bad(`✗ ${LOCKFILE_FILENAME} is out of date — run \`skillnotary lock\` first (or pass --force)`, color));
    console.log(R.formatDrifts(drifts, color));
    return 1;
  }

  const dryRun = bool(values, "dry-run");
  const result = applySkills({
    cwd,
    lockfile,
    targetDir: target.dir,
    dryRun,
    only: strList(values, "skill"),
    force: bool(values, "force"),
  });

  console.log(
    R.bold(dryRun ? "apply (dry run)" : "apply", color) + R.dim(`  target=${target.name} -> ${result.targetDir}`, color),
  );
  for (const warning of result.warnings) {
    console.log(R.dim(`  ! ${sanitizeForTerminal(warning)}`, color));
  }
  for (const item of result.applied) {
    const label =
      item.action === "unchanged" ? R.dim("unchanged", color) : R.ok(item.action.padEnd(9), color);
    console.log(
      `  ${label} ${R.bold(sanitizeForTerminal(item.name), color)} ${R.dim(`(${item.files} files, ${item.bytes} B)`, color)}`,
    );
  }
  for (const item of result.skipped) {
    console.log(
      `  ${R.bad("skipped  ", color)} ${R.bold(sanitizeForTerminal(item.name), color)} ${R.dim(sanitizeForTerminal(item.reason), color)}`,
    );
  }
  if (result.applied.length === 0 && result.skipped.length === 0) {
    console.log(R.dim("  no skills selected", color));
  }

  return result.skipped.length > 0 ? 1 : 0;
}

function cmdFix(ctx: Context): number {
  const { cwd, color, values } = ctx;
  const config = loadConfig(cwd);
  const manifest = readManifest(manifestPath(cwd));
  if (!manifest) {
    console.error(`error: no ${MANIFEST_FILENAME}; run \`skillnotary init\` first`);
    return 2;
  }

  const selected = strList(values, "skill");
  const entries =
    selected.length > 0 ? manifest.skills.filter((s) => selected.includes(s.name)) : manifest.skills;
  if (entries.length === 0) {
    console.error("error: no matching skills in the manifest");
    return 2;
  }

  const dryRun = bool(values, "dry-run");
  let changed = 0;

  for (const entry of entries) {
    let prepared: Prepared;
    try {
      prepared = prepareSkill(cwd, entry, config, bool(values, "refresh"));
    } catch (error) {
      console.error(`error: could not resolve ${entry.source}: ${(error as Error).message}`);
      return 2;
    }

    const plan = planAllowedTools(prepared.dir, prepared.analysis);
    console.log(R.bold(sanitizeForTerminal(entry.name), color));

    if (!plan.changed) {
      console.log(R.dim(`  · ${plan.reason ?? "nothing to do"}`, color));
      continue;
    }

    console.log(`  capabilities  ${plan.tools.join(", ")}`);
    if (plan.keptTools.length > 0) console.log(R.dim(`  = kept        ${plan.keptTools.join(", ")}`, color));
    if (plan.addedTools.length > 0) console.log(R.ok(`  + added       ${plan.addedTools.join(", ")}`, color));
    for (const line of plan.removed) console.log(R.bad(`  - ${sanitizeForTerminal(line)}`, color));
    for (const line of plan.added) console.log(R.ok(`  + ${sanitizeForTerminal(line)}`, color));

    if (!dryRun && writeFixSafe(plan)) {
      console.log(R.dim(`  wrote ${plan.file}`, color));
    }
    changed++;
  }

  console.log("");
  if (changed === 0) {
    console.log(R.ok("✓ nothing to fix", color));
    return 0;
  }
  console.log(
    dryRun
      ? R.dim(`${changed} skill(s) would change; re-run without --dry-run to write`, color)
      : R.ok(`${changed} skill(s) updated — run \`skillnotary lock\` to record the new declarations`, color),
  );
  return 0;
}

/** Write a fix, refusing to touch anything that is not a skill's SKILL.md. */
function writeFixSafe(plan: { changed: boolean; file: string; newContent: string }): boolean {
  if (!plan.changed) return false;
  if (!/[/\\]SKILL\.md$/i.test(plan.file)) {
    console.error(`error: refusing to write outside a SKILL.md: ${plan.file}`);
    return false;
  }
  writeFix(plan as Parameters<typeof writeFix>[0]);
  return true;
}


function cmdInit(ctx: Context): number {
  const { cwd, color } = ctx;
  const mPath = manifestPath(cwd);
  const pPath = policyPath(cwd);

  if (!existsSync(mPath)) {
    writeManifest(mPath, emptyManifest());
    console.log(`${R.ok("created", color)} ${MANIFEST_FILENAME}`);
  } else {
    console.log(`${R.dim("exists ", color)} ${MANIFEST_FILENAME}`);
  }

  if (!existsSync(pPath)) {
    writePolicy(pPath, defaultPolicy());
    console.log(`${R.ok("created", color)} ${POLICY_FILENAME}`);
  } else {
    console.log(`${R.dim("exists ", color)} ${POLICY_FILENAME}`);
  }

  const cPath = join(cwd, CONFIG_FILENAME);
  if (!existsSync(cPath)) {
    writeConfig(cwd, defaultConfig());
    console.log(`${R.ok("created", color)} ${CONFIG_FILENAME}`);
  } else {
    console.log(`${R.dim("exists ", color)} ${CONFIG_FILENAME}`);
  }

  console.log("");
  console.log("Next:");
  console.log(`  1. skillnotary add ./path/to/skill        # or github:owner/repo#sub/path@ref`);
  console.log("  2. skillnotary lock                       # pin what you reviewed");
  console.log("  3. skillnotary audit                      # see what it can do");
  console.log("  4. skillnotary apply --dry-run            # install into your harness");
  return 0;
}

function cmdAdd(ctx: Context): number {
  const { cwd, color } = ctx;
  const source = ctx.positionals[0];
  if (!source) {
    console.error("error: `add` needs a source, e.g. skillnotary add ./my-skill");
    return 2;
  }

  const mPath = manifestPath(cwd);
  const manifest = readManifest(mPath) ?? emptyManifest();

  let resolved;
  try {
    resolved = resolveSpec(source, { cwd, cacheDir: join(cwd, CACHE_DIRNAME) });
  } catch (error) {
    console.error(`error: could not resolve ${source}: ${String(error)}`);
    return 2;
  }

  const analysis = analyzeSkill(resolved.dir, {
    fallbackName: basename(resolved.dir),
  });
  const name = str(ctx.values, "name") ?? readSkillName(resolved.dir) ?? analysis.name;
  const config = loadConfig(cwd);
  const application = applyConfig(analysis.findings, name, config);

  writeManifest(mPath, upsertSkill(manifest, { name, source }));

  console.log(
    `${R.ok("added", color)} ${R.bold(sanitizeForTerminal(name), color)} ${R.dim(`from ${sanitizeForTerminal(source)}`, color)}`,
  );
  console.log(R.formatAnalysisSummary(analysis, { color }, name));

  if (application.suppressed.length > 0) {
    console.log(
      R.dim(
        `  · ${application.suppressed.length} finding(s) suppressed by config (${application.suppressed.map((s) => s.by).join("; ")})`,
        color,
      ),
    );
  }
  for (const warning of application.warnings) {
    console.log(R.bad(`  ! ${sanitizeForTerminal(warning)}`, color));
  }

  const counts = countBySeverity(application.findings);
  if (counts.critical + counts.high > 0) {
    console.log("");
    console.log(R.formatFindings(application.findings, name, { color }));
    console.log("");
    console.log(
      R.bad(
        `warning: ${counts.critical + counts.high} finding(s) at high or above — review before locking`,
        color,
      ),
    );
  }

  if (bool(ctx.values, "fix")) {
    const plan = planAllowedTools(resolved.dir, analysis);
    console.log("");
    if (!plan.changed) {
      console.log(R.dim(`· ${plan.reason ?? "nothing to fix"}`, color));
    } else if (writeFixSafe(plan)) {
      console.log(
        `${R.ok("fixed", color)} declared ${R.bold(plan.tools.join(", "), color)} ${R.dim(`in ${plan.file}`, color)}`,
      );
    }
  }

  return 0;
}

function cmdLock(ctx: Context): number {
  const { cwd, color, values } = ctx;
  const mPath = manifestPath(cwd);
  const manifest = readManifest(mPath);
  if (!manifest) {
    console.error(`error: no ${MANIFEST_FILENAME} found. Run \`skillnotary init\` first.`);
    return 2;
  }
  if (manifest.skills.length === 0) {
    console.error(`error: ${MANIFEST_FILENAME} has no skills. Add one with \`skillnotary add\`.`);
    return 2;
  }

  const { lockfile, warnings } = buildLockfile({
    cwd,
    manifest,
    refresh: bool(values, "refresh"),
  });

  for (const warning of warnings) console.log(R.dim(`note: ${sanitizeForTerminal(warning)}`, color));

  const lPath = lockfilePath(cwd);
  const committed = readLockfile(lPath);

  if (bool(values, "check")) {
    if (!committed) {
      console.log(R.bad(`✗ ${LOCKFILE_FILENAME} does not exist`, color));
      return 1;
    }
    const drifts = diffLockfiles(committed, lockfile);
    if (drifts.length > 0) {
      console.log(R.bad(`✗ ${drifts.length} drift(s) between ${LOCKFILE_FILENAME} and the working tree:`, color));
      console.log(R.formatDrifts(drifts, color));
      return 1;
    }
    console.log(R.ok(`✓ ${LOCKFILE_FILENAME} is up to date`, color));
    return 0;
  }

  writeLockfile(lPath, lockfile);
  console.log(`${R.ok("wrote", color)} ${LOCKFILE_FILENAME} ${R.dim(`(${lockfile.skills.length} skills)`, color)}`);
  console.log("");
  console.log(
    R.formatLockTable(
      lockfile.skills.map((s) => ({
        name: s.name,
        integrity: s.integrity,
        capabilities: s.capabilities,
        source: s.source,
      })),
      color,
    ),
  );
  return 0;
}

function cmdVerify(ctx: Context): number {
  const { cwd, color, values } = ctx;
  const mPath = manifestPath(cwd);
  const manifest = readManifest(mPath) ?? emptyManifest();
  const committed = readLockfile(lockfilePath(cwd));

  if (!committed) {
    console.log(R.bad(`✗ no ${LOCKFILE_FILENAME} found; run \`skillnotary lock\``, color));
    return 1;
  }

  const { lockfile: fresh } = buildLockfile({
    cwd,
    manifest,
    refresh: bool(values, "refresh"),
  });
  const drifts = diffLockfiles(committed, fresh);
  const att = checkAttestation(cwd);

  let failed = false;
  if (drifts.length === 0) {
    console.log(R.ok(`✓ ${committed.skills.length} skill(s) match ${LOCKFILE_FILENAME}`, color));
  } else {
    failed = true;
    console.log(R.bad(`✗ ${drifts.length} drift(s) detected:`, color));
    console.log(R.formatDrifts(drifts, color));
  }

  if (att.present) {
    if (att.valid) {
      console.log(
        R.ok(`✓ ${LOCKFILE_FILENAME} attestation is valid`, color) +
          R.dim(` (${att.keyId ?? "unknown key"}${att.format === "dsse" ? ", DSSE" : ""})`, color),
      );
    } else {
      failed = true;
      console.log(R.bad(`✗ attestation invalid: ${att.reason ?? "unknown reason"}`, color));
    }
  } else {
    console.log(R.dim(`· no attestation present (${ATTEST_FILENAME})`, color));
  }

  return failed ? 1 : 0;
}

function cmdAudit(ctx: Context): number {
  const { cwd, color, values } = ctx;
  const manifest = readManifest(manifestPath(cwd));
  if (!manifest) {
    console.error(`error: no ${MANIFEST_FILENAME} found. Run \`skillnotary init\` first.`);
    return 2;
  }

  const threshold = asSeverity(str(values, "min-severity"), "high");
  const selected = strList(values, "skill");
  const entries = selected.length > 0
    ? manifest.skills.filter((s) => selected.includes(s.name))
    : manifest.skills;

  if (entries.length === 0) {
    console.error("error: no matching skills in the manifest");
    return 2;
  }

  const config = loadConfig(cwd);
  let worst: Severity | null = null;
  const results: unknown[] = [];

  for (const entry of entries) {
    let prepared: Prepared;
    try {
      prepared = prepareSkill(cwd, entry, config, bool(values, "refresh"));
    } catch (error) {
      console.error(`error: could not resolve ${entry.source}: ${String(error)}`);
      return 2;
    }
    const { analysis, effective } = prepared;

    const skillWorst = worstSeverity(effective);
    if (skillWorst && atLeast(skillWorst, threshold)) {
      if (worst === null || atLeast(skillWorst, worst)) worst = skillWorst;
    }
    results.push({
      name: entry.name,
      source: entry.source,
      dir: prepared.dir,
      integrity: analysis.integrity,
      license: analysis.license,
      declared: analysis.declared.capabilities,
      declaredTools: analysis.declared.tools,
      observed: analysis.observed,
      counts: countBySeverity(effective),
      findings: effective,
      suppressedCount: prepared.suppressed.length,
      ignoredByConfig: prepared.ignoredSkill,
    });

    if (!bool(values, "json")) {
      console.log(R.formatAnalysisSummary(analysis, { color }, entry.name));
      const body = R.formatFindings(effective, entry.name, { color, showInfo: false });
      if (body !== "") {
        console.log(body);
      } else {
        console.log(R.dim("  no findings at low or above", color));
      }
      reportSuppressed(prepared, color);
      console.log("");
    }
  }

  if (bool(values, "json")) {
    console.log(JSON.stringify({ version: 1, skills: results }, null, 2));
  }

  if (worst !== null) {
    console.log(
      R.bad(`✗ findings at or above "${threshold}" (worst: ${worst})`, color),
    );
    return 1;
  }
  console.log(R.ok(`✓ no findings at or above "${threshold}"`, color));
  return 0;
}

function cmdPolicy(ctx: Context): number {
  const { cwd, color, values } = ctx;
  const config = loadConfig(cwd);
  const policy = readPolicy(policyPath(cwd)) ?? defaultPolicy();
  const committed = readLockfile(lockfilePath(cwd));
  const manifest = readManifest(manifestPath(cwd)) ?? emptyManifest();

  const { lockfile: fresh, analyses } = buildLockfile({
    cwd,
    manifest,
    refresh: bool(values, "refresh"),
  });

  // The config layer is applied to findings before policy sees them, so turning
  // a rule off in config also stops it producing P009 violations. That is the
  // user's call — and because the config digest is locked, changing it is drift.
  const findingsBySkill = new Map<string, Finding[]>();
  const freshCaps = new Map<string, { capabilities: CapabilityId[]; declared: CapabilityId[] }>();
  for (const [name, analysis] of analyses) {
    const application = applyConfig(analysis.findings, name, config);
    findingsBySkill.set(name, application.findings);
    for (const warning of application.warnings) {
      console.log(R.bad(`! ${sanitizeForTerminal(warning)}`, color));
    }
    freshCaps.set(name, {
      capabilities: analysis.observed,
      declared: analysis.declared.capabilities,
    });
  }

  // Policy is evaluated against what is on disk right now. `skills.lock` is
  // attacker-writable, so its capability claims only count while they still
  // agree with a fresh analysis; otherwise P010 fires.
  const lockDrift = committed ? diffLockfiles(committed, fresh) : [];

  const att = checkAttestation(cwd);
  const outcome = evaluatePolicy({
    policy,
    lockfile: committed ?? fresh,
    findingsBySkill,
    attestation: { present: att.present, valid: att.valid, ...(att.reason ? { reason: att.reason } : {}) },
    fresh: freshCaps,
    lockDrift,
  });

  for (const note of outcome.notes) console.log(R.dim(`· ${note}`, color));

  if (outcome.violations.length === 0) {
    console.log(R.ok("✓ policy satisfied", color));
    return 0;
  }

  console.log(R.bad(`✗ ${outcome.violations.length} policy violation(s):`, color));
  console.log(R.formatViolations(outcome.violations, color));
  return 1;
}

function cmdKeygen(ctx: Context): number {
  const { cwd, color, values } = ctx;
  const out = str(values, "out") ?? join(cwd, KEYFILE_FILENAME);
  if (existsSync(out) && !bool(values, "force")) {
    console.error(`error: ${out} already exists (use --force to overwrite)`);
    return 2;
  }
  const keys = generateKeyPair();
  writeKeyFile(out, keys);
  console.log(`${R.ok("wrote", color)} ${out} ${R.dim("(keep the private key secret)", color)}`);
  console.log(`  keyId      ${keyId(keys.publicKey)}`);
  console.log(`  publicKey  ${keys.publicKey}`);
  return 0;
}

function cmdSign(ctx: Context): number {
  const { cwd, color, values } = ctx;
  const keyPath = str(values, "key") ?? join(cwd, KEYFILE_FILENAME);
  if (!existsSync(keyPath)) {
    console.error(`error: no keyfile at ${keyPath}; run \`skillnotary keygen\` first`);
    return 2;
  }
  const lock = lockfilePath(cwd);
  if (!existsSync(lock)) {
    console.error(`error: no ${LOCKFILE_FILENAME}; run \`skillnotary lock\` first`);
    return 2;
  }

  const keys = readKeyFile(keyPath);
  const lockBytes = readFileSync(lock);
  const parsedLock = readLockfile(lock);

  // The predicate records what was actually reviewed: the config digest that
  // shaped the findings, and every skill's digest and capabilities.
  const attestation = signPayload(lockBytes, keys, LOCKFILE_FILENAME, {
    generator: GENERATOR,
    configDigest: parsedLock?.config?.digest ?? null,
    skills: (parsedLock?.skills ?? []).map((skill) => ({
      name: skill.name,
      integrity: skill.integrity,
      capabilities: skill.capabilities,
    })),
  });

  const out = str(values, "out") ?? attestationPath(cwd);
  writeFileSync(out, `${JSON.stringify(attestation, null, 2)}\n`, "utf8");

  const signature = attestation.signatures[0];
  console.log(`${R.ok("signed", color)} ${LOCKFILE_FILENAME} -> ${out}`);
  console.log(`  format   DSSE (${attestation.payloadType})`);
  console.log(`  keyId    ${signature?.keyid ?? "?"}`);
  console.log(`  subject  sha256:${sha256Hex(lockBytes).slice(0, 24)}...`);
  console.log(
    R.dim(
      `  predicate covers ${parsedLock?.skills.length ?? 0} skill(s) and the config digest`,
      color,
    ),
  );
  return 0;
}

function cmdSbom(ctx: Context): number {
  const { cwd, color, values } = ctx;
  const lockfile = readLockfile(lockfilePath(cwd));
  if (!lockfile) {
    console.error(`error: no ${LOCKFILE_FILENAME}; run \`skillnotary lock\` first`);
    return 2;
  }
  const sbom = buildSbom(lockfile, str(values, "name") ?? basename(cwd) ?? "agent-skills");
  const json = `${JSON.stringify(sbom, null, 2)}\n`;

  const out = str(values, "out");
  if (out) {
    writeFileSync(resolve(cwd, out), json, "utf8");
    console.log(`${R.ok("wrote", color)} ${out} ${R.dim(`(${sbom.components.length} components)`, color)}`);
  } else {
    process.stdout.write(json);
  }
  return 0;
}

function cmdDiscover(ctx: Context): number {
  const { cwd, color, values } = ctx;
  const found = discoverSkills({
    cwd,
    home: homedir(),
    includeBareDirectories: bool(values, "include-bare"),
  });

  if (bool(values, "json")) {
    console.log(JSON.stringify({ version: 1, skills: found }, null, 2));
    return 0;
  }

  if (found.length === 0) {
    console.log(R.dim("no skills found in known harness locations", color));
    console.log("");
    console.log(R.dim("looked in: .claude/skills, .agents/skills, .opencode/skills, .dsh/skills,", color));
    console.log(R.dim("           .codex/skills, .cursor/skills, skills/ (project and $HOME)", color));
    return 0;
  }

  const nameWidth = Math.max(4, ...found.map((f) => f.name.length));
  console.log(R.dim(`  ${"SKILL".padEnd(nameWidth)}  HARNESS              SCOPE`, color));
  for (const skill of found) {
    console.log(
      `  ${sanitizeForTerminal(skill.name).padEnd(nameWidth)}  ${skill.harness.padEnd(20)} ${skill.scope}`,
    );
  }
  console.log("");
  console.log(
    R.dim(
      `${found.length} skill(s). Add one with: skillnotary add ${sanitizeForTerminal(found[0]?.dir ?? "<path>")}`,
      color,
    ),
  );
  return 0;
}

function cmdCi(ctx: Context): number {
  const { cwd, color, values } = ctx;
  console.log(R.bold("skillnotary ci", color));
  console.log("");

  console.log(R.bold("[1/3] lockfile integrity", color));
  const verifyCode = cmdVerify(ctx);
  console.log("");

  console.log(R.bold("[2/3] policy", color));
  const policyCode = cmdPolicy(ctx);
  console.log("");

  console.log(R.bold("[3/3] risk audit", color));
  const threshold = asSeverity(str(values, "min-severity"), "high");
  const config = loadConfig(cwd);
  const manifest = readManifest(manifestPath(cwd)) ?? emptyManifest();
  let auditCode = 0;
  if (manifest.skills.length === 0) {
    console.log(R.dim("  no skills in the manifest", color));
  } else {
    const { analyses } = buildLockfile({ cwd, manifest, refresh: bool(values, "refresh") });
    let worst: Severity | null = null;
    for (const [name, analysis] of analyses) {
      const application = applyConfig(analysis.findings, name, config);
      for (const warning of application.warnings) {
        console.log(R.bad(`  ! ${sanitizeForTerminal(warning)}`, color));
      }
      if (application.suppressed.length > 0) {
        console.log(R.dim(`  · ${name}: ${application.suppressed.length} finding(s) suppressed by config`, color));
      }
      const found = application.findings.filter((f) => f.severity !== "info");
      if (found.length === 0) continue;
      console.log(R.formatFindings(application.findings, name, { color }));
      const w = worstSeverity(application.findings);
      if (w && atLeast(w, threshold) && (worst === null || atLeast(w, worst))) worst = w;
    }
    if (worst !== null) {
      console.log(R.bad(`  findings at or above "${threshold}"`, color));
      auditCode = 1;
    } else {
      console.log(R.ok(`  ✓ nothing at or above "${threshold}"`, color));
    }
  }

  console.log("");
  const failed = verifyCode !== 0 || policyCode !== 0 || auditCode !== 0;
  console.log(failed ? R.bad("✗ ci failed", color) : R.ok("✓ ci passed", color));
  return failed ? 1 : 0;
}

// ------------------------------------------------------------------------ main

function main(): number {
  const argv = process.argv.slice(2);
  const { values, positionals } = parse(argv);

  if (bool(values, "version") || argv[0] === "version") {
    console.log(VERSION);
    return 0;
  }

  const command = positionals[0] ?? (argv[0]?.startsWith("-") ? undefined : argv[0]);

  if (!command || command === "help" || bool(values, "help")) {
    console.log(HELP);
    return command ? 0 : 2;
  }

  const rest = positionals.slice(1);
  const ctx: Context = {
    cwd: process.cwd(),
    color: R.colorEnabled(bool(values, "no-color") ? false : (values["color"] as boolean | undefined)),
    values,
    positionals: rest,
  };

  switch (command) {
    case "init":
      return cmdInit(ctx);
    case "add":
      return cmdAdd(ctx);
    case "lock":
      return cmdLock(ctx);
    case "verify":
      return cmdVerify(ctx);
    case "audit":
      return cmdAudit(ctx);
    case "fix":
      return cmdFix(ctx);
    case "policy":
      return cmdPolicy(ctx);
    case "apply":
      return cmdApply(ctx);
    case "config":
      return cmdConfig(ctx);
    case "keygen":
      return cmdKeygen(ctx);
    case "sign":
      return cmdSign(ctx);
    case "sbom":
      return cmdSbom(ctx);
    case "discover":
      return cmdDiscover(ctx);
    case "ci":
      return cmdCi(ctx);
    default:
      console.error(`error: unknown command "${command}"`);
      console.error("");
      console.error(HELP);
      return 2;
  }
}

try {
  process.exitCode = main();
} catch (error: unknown) {
  console.error(`error: ${error instanceof Error ? error.message : String(error)}`);
  if (process.env["SKILLNOTARY_DEBUG"]) console.error(error);
  process.exitCode = 1;
}
