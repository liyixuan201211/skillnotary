import type { Lockfile } from "./types.ts";
import { GENERATOR } from "./version.ts";

/**
 * An SBOM for agent skills.
 *
 * The format is intentionally explicit about being our own
 * (`bomFormat: "skillnotary/sbom@1"`) while borrowing CycloneDX's vocabulary
 * (components, hashes, licenses, properties). We do not claim CycloneDX
 * conformance; a conformant exporter can be layered on later.
 */
export interface SbomHash {
  alg: "SHA-256";
  content: string;
}

export interface SbomComponent {
  type: "application";
  "bom-ref": string;
  name: string;
  version: string;
  hashes: SbomHash[];
  licenses?: Array<{ license: { id: string } }>;
  supplier?: { name: string };
  externalReferences?: Array<{ type: string; url: string }>;
  properties: Array<{ name: string; value: string }>;
}

export interface Sbom {
  bomFormat: "skillnotary/sbom@1";
  specVersion: 1;
  generatedAt: string;
  generator: string;
  metadata: {
    component: { type: "application"; name: string };
    properties: Array<{ name: string; value: string }>;
  };
  components: SbomComponent[];
}

/** `sha256-<base64>` -> lowercase hex. */
export function sriToHex(integrity: string): string {
  return Buffer.from(integrity.replace(/^sha256-/, ""), "base64").toString("hex");
}

export function shortDigest(integrity: string): string {
  return integrity.replace(/^sha256-/, "").slice(0, 16);
}

export function buildSbom(lockfile: Lockfile, projectName = "agent-skills"): Sbom {
  const components: SbomComponent[] = lockfile.skills.map((skill) => {
    const ref = `skill:${skill.name}@${shortDigest(skill.integrity)}`;
    const component: SbomComponent = {
      type: "application",
      "bom-ref": ref,
      name: skill.name,
      version: shortDigest(skill.integrity),
      hashes: [{ alg: "SHA-256", content: sriToHex(skill.integrity) }],
      properties: [
        { name: "skillnotary:capabilities", value: skill.capabilities.join(",") || "none" },
        { name: "skillnotary:declared", value: skill.declared.join(",") || "none" },
        { name: "skillnotary:declaredTools", value: skill.declaredTools.join(",") || "none" },
        { name: "skillnotary:source", value: skill.source },
        { name: "skillnotary:sourceType", value: skill.resolved.type },
        { name: "skillnotary:fileCount", value: String(skill.files) },
        { name: "skillnotary:bytes", value: String(skill.bytes) },
      ],
    };
    if (skill.license) {
      component.licenses = [{ license: { id: skill.license } }];
    }
    if (skill.resolved.url) {
      component.supplier = { name: skill.resolved.url };
      component.externalReferences = [
        { type: "vcs", url: skill.resolved.commit ? `${skill.resolved.url}#${skill.resolved.commit}` : skill.resolved.url },
      ];
    }
    return component;
  });

  return {
    bomFormat: "skillnotary/sbom@1",
    specVersion: 1,
    generatedAt: new Date().toISOString(),
    generator: GENERATOR,
    metadata: {
      component: { type: "application", name: projectName },
      properties: [{ name: "skillnotary:skillCount", value: String(components.length) }],
    },
    components,
  };
}
