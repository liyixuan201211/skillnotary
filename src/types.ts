/**
 * Core types for skillnotary.
 *
 * A "skill" here means an agent skill directory: a folder containing a
 * `SKILL.md` (optionally with YAML frontmatter) plus any supporting scripts,
 * resources or MCP config. That is the de-facto shape used by Claude Code,
 * opencode, openclaw, DeepSeek Harness and friends.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** Ordered from least to most severe. */
export const SEVERITY_ORDER: readonly Severity[] = [
  "info",
  "low",
  "medium",
  "high",
  "critical",
] as const;

/**
 * Capabilities describe what a skill can make your agent *do*.
 * These are the things a policy can allow or deny.
 */
export type CapabilityId =
  | "exec"
  | "network"
  | "fs.read"
  | "fs.write"
  | "secrets"
  | "install"
  | "privilege"
  | "destructive"
  | "mcp"
  | "agent.spawn";

export const ALL_CAPABILITIES: readonly CapabilityId[] = [
  "exec",
  "network",
  "fs.read",
  "fs.write",
  "secrets",
  "install",
  "privilege",
  "destructive",
  "mcp",
  "agent.spawn",
] as const;

export const CAPABILITY_HELP: Record<CapabilityId, string> = {
  exec: "Run shell commands or spawn processes",
  network: "Make outbound network requests",
  "fs.read": "Read files",
  "fs.write": "Write, move or delete files",
  secrets: "Touch credentials, tokens or key material",
  install: "Install packages at runtime (arbitrary code execution chain)",
  privilege: "Escalate privileges (sudo/runas)",
  destructive: "Irreversible operations (rm -rf, force push, mkfs)",
  mcp: "Connect to MCP servers",
  "agent.spawn": "Launch further agents or sub-agents",
};

export interface Finding {
  /** Stable rule id, e.g. R002. */
  rule: string;
  severity: Severity;
  title: string;
  detail: string;
  file: string;
  line?: number;
  evidence?: string;
  capability?: CapabilityId;
}

/** Permissions a skill claims for itself, from SKILL.md frontmatter. */
export interface DeclaredPermissions {
  /** Raw `allowed-tools` entries, e.g. ["Bash(npm run *)", "Read"]. */
  tools: string[];
  /** Capabilities derived from those tools. */
  capabilities: CapabilityId[];
}

export interface SkillAnalysis {
  name: string;
  /** Absolute or project-relative path on disk. */
  dir: string;
  description: string | null;
  license: string | null;
  /** Capabilities actually observed in the skill's text and scripts. */
  observed: CapabilityId[];
  /** Capabilities the skill declares in frontmatter. */
  declared: DeclaredPermissions;
  findings: Finding[];
  files: number;
  bytes: number;
  /** SRI-style digest of the whole tree, e.g. `sha256-...`. */
  integrity: string;
}

export interface ResolvedSource {
  type: "path" | "git";
  /** Where it came from, verbatim as written in the manifest. */
  spec: string;
  /** Filesystem location used to read the skill. */
  dir: string;
  url?: string;
  ref?: string;
  commit?: string;
  subpath?: string;
}

export interface LockedSkill {
  name: string;
  source: string;
  resolved: ResolvedSource;
  integrity: string;
  files: number;
  bytes: number;
  /** Observed capabilities, pinned at lock time. */
  capabilities: CapabilityId[];
  /** Declared capabilities, pinned at lock time. */
  declared: CapabilityId[];
  declaredTools: string[];
  license: string | null;
  description: string | null;
}

export interface Lockfile {
  lockfileVersion: 1;
  generator: string;
  skills: LockedSkill[];
}

export interface ManifestSkill {
  name: string;
  source: string;
}

export interface Manifest {
  version: 1;
  skills: ManifestSkill[];
}

export interface Policy {
  version: 1;
  /** Fail if any finding is at or above this severity. Default: "high". */
  maxSeverity?: Severity;
  /** Allow/deny individual capabilities. Anything not listed is allowed. */
  capabilities?: Partial<Record<CapabilityId, boolean>>;
  /** Glob-ish name allowlist. If set, only these skills may be installed. */
  allowSkills?: string[];
  /** Glob-ish name denylist. */
  denySkills?: string[];
  /** Require skills.lock to exist and to be in sync. Default: true. */
  requireLock?: boolean;
  /** Require a valid attestation over skills.lock. Default: false. */
  requireSignature?: boolean;
  /** Public keys (base64, SPKI) trusted to sign skills.lock. */
  trustedKeys?: TrustedKey[];
  /** Capabilities that must be explicitly declared in SKILL.md frontmatter. */
  requireDeclared?: CapabilityId[];
}

export interface TrustedKey {
  name: string;
  publicKey: string;
}

export interface Attestation {
  format: "skillnotary/attestation@1";
  subject: {
    name: string;
    /** SRI digest of the signed file. */
    digest: string;
  };
  algorithm: "ed25519";
  keyId: string;
  publicKey: string;
  signature: string;
  signedAt: string;
}

export interface PolicyViolation {
  rule: string;
  message: string;
  skill?: string;
}
