import { canonicalJson, matchesAny, readTextFileSafe, writeTextFile } from "./util.ts";
import { SEVERITY_ORDER } from "./types.ts";
import type {
  CapabilityId,
  Finding,
  Lockfile,
  Policy,
  PolicyViolation,
  Severity,
} from "./types.ts";

export const POLICY_FILENAME = "skillnotary.policy.json";

export function defaultPolicy(): Policy {
  return {
    version: 1,
    maxSeverity: "high",
    requireLock: true,
    requireSignature: false,
    capabilities: {},
  };
}

export function readPolicy(path: string): Policy | null {
  const raw = readTextFileSafe(path);
  if (raw === null) return null;
  const parsed = JSON.parse(raw) as Partial<Policy>;
  return { version: 1, ...parsed };
}

export function writePolicy(path: string, policy: Policy): void {
  writeTextFile(path, `${canonicalJson(policy)}\n`);
}

export function severityRank(severity: Severity): number {
  const index = SEVERITY_ORDER.indexOf(severity);
  return index === -1 ? 0 : index;
}

/** True when `severity` is at least as bad as `threshold`. */
export function atLeast(severity: Severity, threshold: Severity): boolean {
  return severityRank(severity) >= severityRank(threshold);
}

export interface PolicyInput {
  policy: Policy;
  lockfile: Lockfile | null;
  /** Findings per skill name, from a fresh analysis. */
  findingsBySkill: Map<string, Finding[]>;
  /** Whether an attestation was found and validated. */
  attestation: { present: boolean; valid: boolean; reason?: string };
  /**
   * Freshly observed capabilities, keyed by skill name.
   *
   * When present these are authoritative. The lockfile is attacker-writable
   * (anyone can open a PR against it), so a capability gate that trusted the
   * lockfile's own claims could be defeated simply by deleting entries from
   * `skills.lock`.
   */
  fresh?: Map<string, { capabilities: CapabilityId[]; declared: CapabilityId[] }>;
  /** Drift between the committed lockfile and a fresh resolution. */
  lockDrift?: Array<{ name: string; kind: string; detail: string }>;
}

export interface PolicyOutcome {
  violations: PolicyViolation[];
  /** Non-fatal observations worth printing. */
  notes: string[];
}

/**
 * Evaluate a policy. This is deliberately pure: it takes already-computed
 * findings and an attestation verdict so it can be unit-tested directly.
 */
export function evaluatePolicy(input: PolicyInput): PolicyOutcome {
  const { policy, lockfile, findingsBySkill, attestation } = input;
  const violations: PolicyViolation[] = [];
  const notes: string[] = [];

  // 1. A lockfile that exists and is in sync is the baseline guarantee.
  if (policy.requireLock !== false && lockfile === null) {
    violations.push({
      rule: "P001",
      message: "no skills.lock found; run `skillnotary lock` to pin your skills",
    });
  }

  // 2. Optional provenance requirement.
  if (policy.requireSignature) {
    if (!attestation.present) {
      violations.push({
        rule: "P002",
        message: "policy requires a signature but no attestation file was found",
      });
    } else if (!attestation.valid) {
      violations.push({
        rule: "P003",
        message: `attestation is not valid: ${attestation.reason ?? "unknown reason"}`,
      });
    } else if (policy.trustedKeys && policy.trustedKeys.length > 0) {
      // Signature must come from a key the policy trusts.
      const trusted = policy.trustedKeys.some(
        (k) => k.publicKey.trim() === (attestation as unknown as { publicKey?: string }).publicKey,
      );
      if (!trusted) {
        violations.push({
          rule: "P004",
          message: "attestation was signed by a key that is not in policy.trustedKeys",
        });
      }
    }
  }

  const skills = lockfile?.skills ?? [];

  // A lockfile that disagrees with the working tree cannot be trusted as the
  // basis for any capability decision, so surface that before the gates below.
  for (const drift of input.lockDrift ?? []) {
    violations.push({
      rule: "P010",
      message: `skills.lock does not match the working tree for "${drift.name}" [${drift.kind}]: ${drift.detail}`,
      skill: drift.name,
    });
  }

  for (const skill of skills) {
    // 3. Name allow/deny lists.
    if (policy.allowSkills && policy.allowSkills.length > 0) {
      if (!matchesAny(policy.allowSkills, skill.name) && !policy.allowSkills.includes(skill.name)) {
        violations.push({
          rule: "P005",
          message: `skill "${skill.name}" is not in policy.allowSkills`,
          skill: skill.name,
        });
      }
    }
    if (matchesAny(policy.denySkills, skill.name) || policy.denySkills?.includes(skill.name)) {
      violations.push({
        rule: "P006",
        message: `skill "${skill.name}" is denied by policy.denySkills`,
        skill: skill.name,
      });
    }

    // 4. Capability gates. Prefer freshly observed capabilities; the lockfile's
    //    own list is only a fallback when no fresh analysis was supplied.
    const freshEntry = input.fresh?.get(skill.name);
    const observedCaps = freshEntry?.capabilities ?? skill.capabilities;
    const declaredCaps = freshEntry?.declared ?? skill.declared;

    for (const [capability, allowed] of Object.entries(policy.capabilities ?? {}) as Array<
      [CapabilityId, boolean | undefined]
    >) {
      if (allowed !== false) continue;
      if (!observedCaps.includes(capability)) continue;
      violations.push({
        rule: "P007",
        message: `skill "${skill.name}" exercises capability "${capability}", which policy forbids`,
        skill: skill.name,
      });
    }

    // 5. Capabilities that must be declared, not merely present.
    for (const required of policy.requireDeclared ?? []) {
      if (observedCaps.includes(required) && !declaredCaps.includes(required)) {
        violations.push({
          rule: "P008",
          message: `skill "${skill.name}" uses "${required}" but does not declare it in SKILL.md`,
          skill: skill.name,
        });
      }
    }

    // 6. Severity gate over fresh findings.
    const threshold = policy.maxSeverity ?? "high";
    for (const finding of findingsBySkill.get(skill.name) ?? []) {
      if (!atLeast(finding.severity, threshold)) continue;
      violations.push({
        rule: "P009",
        message: `${finding.rule} ${finding.title} (${finding.file}${finding.line ? `:${finding.line}` : ""}) is ${finding.severity}, at or above maxSeverity=${threshold}`,
        skill: skill.name,
      });
    }
  }

  // Only nudge when the policy has not expressed an opinion either way.
  if (
    skills.some((s) => s.capabilities.includes("network")) &&
    policy.capabilities?.network === undefined
  ) {
    notes.push(
      "some skills use the network and the policy is silent about it; set capabilities.network to allow or deny explicitly",
    );
  }

  return { violations, notes };
}
