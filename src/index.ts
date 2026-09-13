/**
 * skillnotary — lockfile, provenance and capability policy for AI agent skills.
 *
 * This module is the programmatic API. The CLI in `cli.ts` is a thin wrapper
 * over it, so everything the CLI does can be done from code or a CI script.
 */

export { analyzeSkill, countBySeverity, worstSeverity, segmentText, parseFrontmatter } from "./analyze.ts";
export type { Segment, Frontmatter, AnalyzeOptions } from "./analyze.ts";
export { RULES, SHELL_LANGUAGES, TOOL_CAPABILITY_MAP, SIGNIFICANT_CAPABILITIES } from "./patterns.ts";
export type { Rule, RuleScope } from "./patterns.ts";
export {
  defaultPolicy,
  evaluatePolicy,
  readPolicy,
  writePolicy,
  severityRank,
  atLeast,
  POLICY_FILENAME,
} from "./policy.ts";
export type { PolicyInput, PolicyOutcome } from "./policy.ts";
export {
  buildLockfile,
  diffLockfiles,
  readLockfile,
  writeLockfile,
  LOCKFILE_FILENAME,
} from "./lockfile.ts";
export type { BuildOptions, BuildResult, Drift, DriftKind } from "./lockfile.ts";
export {
  emptyManifest,
  readManifest,
  writeManifest,
  upsertSkill,
  removeSkill,
  MANIFEST_FILENAME,
} from "./manifest.ts";
export { parseSource, resolveSource, resolveSpec } from "./source.ts";
export type { ParsedSource, ResolveOptions } from "./source.ts";
export {
  generateKeyPair,
  keyId,
  readAttestation,
  readKeyFile,
  signPayload,
  verifyPayload,
  writeKeyFile,
  ATTEST_FILENAME,
  KEYFILE_FILENAME,
} from "./attest.ts";
export type { KeyPairB64, KeyFile, VerifyResult } from "./attest.ts";
export { buildSbom, sriToHex, shortDigest } from "./sbom.ts";
export type { Sbom, SbomComponent } from "./sbom.ts";
export { discoverSkills, readSkillName, HARNESS_LAYOUTS } from "./discover.ts";
export type { DiscoveredSkill, HarnessLayout } from "./discover.ts";
export { digestTree } from "./hash.ts";
export type { TreeDigest } from "./hash.ts";
export { VERSION } from "./version.ts";
export type {
  Attestation,
  CapabilityId,
  DeclaredPermissions,
  Finding,
  Lockfile,
  LockedSkill,
  Manifest,
  ManifestSkill,
  Policy,
  PolicyViolation,
  ResolvedSource,
  Severity,
  SkillAnalysis,
  TrustedKey,
} from "./types.ts";
export { ALL_CAPABILITIES, CAPABILITY_HELP, SEVERITY_ORDER } from "./types.ts";
