/**
 * skillnotary — lockfile, provenance and capability policy for AI agent skills.
 *
 * This module is the programmatic API. The CLI in `cli.ts` is a thin wrapper
 * over it, so everything the CLI does can be done from code or a CI script:
 *
 * ```ts
 * import { analyzeSkill, buildLockfile, evaluatePolicy, applySkills } from "skillnotary";
 * ```
 */

// analyse
export {
  analyzeSkill,
  countBySeverity,
  worstSeverity,
  segmentText,
  parseFrontmatter,
  parseSuppressions,
  toolsFromFrontmatter,
} from "./analyze.ts";
export type { Segment, Frontmatter, AnalyzeOptions } from "./analyze.ts";
export { RULES, SHELL_LANGUAGES, TOOL_CAPABILITY_MAP, SIGNIFICANT_CAPABILITIES } from "./patterns.ts";
export type { Rule, RuleScope } from "./patterns.ts";

// policy
export {
  atLeast,
  defaultPolicy,
  evaluatePolicy,
  POLICY_FILENAME,
  readPolicy,
  severityRank,
  writePolicy,
} from "./policy.ts";
export type { PolicyInput, PolicyOutcome } from "./policy.ts";

// config / suppression layer
export {
  applyConfig,
  CONFIG_FILENAME,
  configDigest,
  defaultConfig,
  effectiveRules,
  ignoreMatches,
  readConfig,
  resolveTarget,
  writeConfig,
} from "./config.ts";
export type { Config, ConfigApplication, RuleSetting } from "./config.ts";

// lockfile
export {
  buildLockfile,
  diffLockfiles,
  LOCKFILE_FILENAME,
  lockfilePath,
  normalizeLockfile,
  readLockfile,
  writeLockfile,
} from "./lockfile.ts";
export type { BuildOptions, BuildResult, Drift, DriftKind } from "./lockfile.ts";

// manifest
export {
  emptyManifest,
  findSkill,
  MANIFEST_FILENAME,
  readManifest,
  removeSkill,
  selectSkills,
  upsertSkill,
  writeManifest,
} from "./manifest.ts";

// sources
export { assertSafeGitUrl, CACHE_DIRNAME, isRemote, parseSource, resolveSource, resolveSpec } from "./source.ts";
export type { ParsedSource, ResolveOptions } from "./source.ts";

// install
export { applySkills, assertSafeSkillDirName, findMissing } from "./apply.ts";
export type { AppliedSkill, ApplyOptions, ApplyResult } from "./apply.ts";

// fix
export { planAllowedTools, toolsForCapabilities, writeFix } from "./fix.ts";
export type { FixPlan } from "./fix.ts";

// provenance
export {
  ATTEST_FILENAME,
  attestationPath,
  buildStatement,
  DSSE_PAYLOAD_TYPE,
  FORMAT,
  generateKeyPair,
  KEYFILE_FILENAME,
  keyId,
  pae,
  readAttestation,
  readKeyFile,
  signPayload,
  verifyDsse,
  verifyPayload,
  writeKeyFile,
} from "./attest.ts";
export type { KeyFile, KeyPairB64, LockPredicateInput } from "./attest.ts";

// inventory
export { buildSbom, shortDigest, sriToHex } from "./sbom.ts";
export type { Sbom, SbomComponent } from "./sbom.ts";

// discovery
export { discoverSkills, HARNESS_LAYOUTS, readSkillName } from "./discover.ts";
export type { DiscoveredSkill, HarnessLayout } from "./discover.ts";

// primitives
export { digestTree } from "./hash.ts";
export type { TreeDigest } from "./hash.ts";
export {
  canonicalJson,
  globMatch,
  LIMITS,
  matchesAny,
  sanitizeForTerminal,
  sha256Hex,
  sri,
  walkFiles,
  walkTree,
} from "./util.ts";
export type { WalkResult } from "./util.ts";
export { GENERATOR, VERSION } from "./version.ts";

// types
export { ALL_CAPABILITIES, CAPABILITY_HELP, SEVERITY_ORDER } from "./types.ts";
export type {
  Attestation,
  AttestationFile,
  CapabilityId,
  DeclaredPermissions,
  DsseEnvelope,
  Finding,
  InTotoStatement,
  Lockfile,
  LockedSkill,
  Manifest,
  ManifestSkill,
  Policy,
  PolicyViolation,
  ResolvedSource,
  Severity,
  SkillAnalysis,
  SuppressionDirective,
  TrustedKey,
  VerifyResult,
} from "./types.ts";
