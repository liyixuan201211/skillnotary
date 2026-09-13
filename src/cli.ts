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
import { VERSION } from "./version.ts";
import * as R from "./report.ts";
import type { Finding, Severity } from "./types.ts";
import type { Attestation } from "./types.ts";

const HELP = `skillnotary ${VERSION} — lockfile, provenance and capability policy for AI agent skills

USAGE
  skillnotary <command> [options]

COMMANDS
  init                    Create skills.json and a default policy
  add <source>            Add a skill to the manifest (path, github:owner/repo#sub/path@ref)
  lock                    Resolve the manifest and write skills.lock
  verify                  Check the working tree against skills.lock (drift + attestation)
  audit                   Static capability and risk report
  policy                  Evaluate the policy against the locked skills
  keygen                  Generate an ed25519 signing keypair
  sign                    Attest skills.lock with your key
  sbom                    Emit an SBOM for the locked skills
  discover                Find skills installed in known harness locations
  ci                      verify + policy + audit, for CI pipelines
  help                    Show this help

OPTIONS
  --json                  Machine-readable output
  --out <path>            Write output to a file
  --key <path>            Signing keyfile (default ${KEYFILE_FILENAME})
  --name <name>           Name to record for an added skill
  --refresh               Re-clone git sources instead of using the cache
  --check                 Do not write; fail if the lockfile would change
  --min-severity <s>      info|low|medium|high|critical (default: high)
  --skill <name>          Limit to a skill (repeatable)
  --[no-]color            Force or disable colour
  -h, --help              Show this help
  -v, --version           Print the version

EXAMPLES
  skillnotary init
  skillnotary add github:acme/skills#pdf-tools@v1.2.0
  skillnotary lock && skillnotary audit
  skillnotary keygen && skillnotary sign && skillnotary verify
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

function readFindingsBySkill(
  analyses: Map<string, { findings: Finding[] }>,
): Map<string, Finding[]> {
  return new Map([...analyses].map(([name, a]) => [name, a.findings]));
}

function checkAttestation(cwd: string): { present: boolean; valid: boolean; reason?: string; attestation: Attestation | null } {
  const att = readAttestation(attestationPath(cwd));
  const lock = lockfilePath(cwd);
  if (!att) return { present: false, valid: false, attestation: null };
  if (!existsSync(lock)) {
    return { present: true, valid: false, reason: "skills.lock is missing", attestation: att };
  }
  const result = verifyPayload(att, readFileSync(lock));
  return {
    present: true,
    valid: result.valid,
    ...(result.reason !== undefined ? { reason: result.reason } : {}),
    attestation: att,
  };
}

// -------------------------------------------------------------------- commands

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

  console.log("");
  console.log("Next:");
  console.log(`  1. skillnotary add ./path/to/skill        # or github:owner/repo#sub/path@ref`);
  console.log("  2. skillnotary lock                       # pin what you reviewed");
  console.log("  3. skillnotary audit                      # see what it can do");
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

  writeManifest(mPath, upsertSkill(manifest, { name, source }));

  console.log(`${R.ok("added", color)} ${R.bold(name, color)} ${R.dim(`from ${source}`, color)}`);
  console.log(R.formatAnalysisSummary(analysis, { color }, name));
  const counts = countBySeverity(analysis.findings);
  if (counts.critical + counts.high > 0) {
    console.log("");
    console.log(R.formatFindings(analysis.findings, name, { color }));
    console.log("");
    console.log(
      R.bad(
        `warning: ${counts.critical + counts.high} finding(s) at high or above — review before locking`,
        color,
      ),
    );
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

  for (const warning of warnings) console.log(R.dim(`note: ${warning}`, color));

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
          R.dim(` (${att.attestation?.keyId ?? "unknown key"})`, color),
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

  let worst: Severity | null = null;
  const results: unknown[] = [];

  for (const entry of entries) {
    let resolved;
    try {
      resolved = resolveSpec(entry.source, { cwd, cacheDir: join(cwd, CACHE_DIRNAME) });
    } catch (error) {
      console.error(`error: could not resolve ${entry.source}: ${String(error)}`);
      return 2;
    }
    const analysis = analyzeSkill(resolved.dir, { fallbackName: entry.name });
    const skillWorst = worstSeverity(analysis.findings);
    if (skillWorst && atLeast(skillWorst, threshold)) {
      if (worst === null || atLeast(skillWorst, worst)) worst = skillWorst;
    }
    results.push({
      name: entry.name,
      source: entry.source,
      dir: resolved.dir,
      integrity: analysis.integrity,
      license: analysis.license,
      declared: analysis.declared.capabilities,
      declaredTools: analysis.declared.tools,
      observed: analysis.observed,
      counts: countBySeverity(analysis.findings),
      findings: analysis.findings,
    });

    if (!bool(values, "json")) {
      console.log(R.formatAnalysisSummary(analysis, { color }, entry.name));
      const body = R.formatFindings(analysis.findings, entry.name, { color, showInfo: false });
      if (body !== "") {
        console.log(body);
      } else {
        console.log(R.dim("  no findings at low or above", color));
      }
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
  const policy = readPolicy(policyPath(cwd)) ?? defaultPolicy();
  const committed = readLockfile(lockfilePath(cwd));
  const manifest = readManifest(manifestPath(cwd)) ?? emptyManifest();

  const { lockfile: fresh, analyses } = buildLockfile({
    cwd,
    manifest,
    refresh: bool(values, "refresh"),
  });

  const att = checkAttestation(cwd);
  const outcome = evaluatePolicy({
    policy,
    lockfile: committed ?? fresh,
    findingsBySkill: readFindingsBySkill(analyses),
    attestation: { present: att.present, valid: att.valid, ...(att.reason ? { reason: att.reason } : {}) },
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
  const attestation = signPayload(readFileSync(lock), keys, LOCKFILE_FILENAME);
  const out = str(values, "out") ?? attestationPath(cwd);
  writeFileSync(out, `${JSON.stringify(attestation, null, 2)}\n`, "utf8");

  console.log(`${R.ok("signed", color)} ${LOCKFILE_FILENAME} -> ${out}`);
  console.log(`  keyId   ${attestation.keyId}`);
  console.log(`  digest  ${attestation.subject.digest.slice(0, 28)}...`);
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
      `  ${skill.name.padEnd(nameWidth)}  ${skill.harness.padEnd(20)} ${skill.scope}`,
    );
  }
  console.log("");
  console.log(R.dim(`${found.length} skill(s). Add one with: skillnotary add ${found[0]?.dir ?? "<path>"}`, color));
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
  const manifest = readManifest(manifestPath(cwd)) ?? emptyManifest();
  let auditCode = 0;
  if (manifest.skills.length === 0) {
    console.log(R.dim("  no skills in the manifest", color));
  } else {
    const { analyses } = buildLockfile({ cwd, manifest, refresh: bool(values, "refresh") });
    let worst: Severity | null = null;
    for (const [name, analysis] of analyses) {
      const found = analysis.findings.filter((f) => f.severity !== "info");
      if (found.length === 0) continue;
      console.log(R.formatFindings(found, name, { color }));
      const w = worstSeverity(analysis.findings);
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
    case "policy":
      return cmdPolicy(ctx);
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
