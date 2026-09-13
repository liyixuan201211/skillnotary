import { readTextFileSafe, writeTextFile, canonicalJson, matchesAny } from "./util.ts";
import type { Manifest, ManifestSkill } from "./types.ts";

export const MANIFEST_FILENAME = "skills.json";

export function emptyManifest(): Manifest {
  return { version: 1, skills: [] };
}

export function readManifest(path: string): Manifest | null {
  const raw = readTextFileSafe(path);
  if (raw === null) return null;
  const parsed = JSON.parse(raw) as Partial<Manifest>;
  return {
    version: 1,
    skills: Array.isArray(parsed.skills)
      ? parsed.skills
          .filter((s): s is ManifestSkill => Boolean(s && typeof s.name === "string" && typeof s.source === "string"))
          .map((s) => ({ name: s.name, source: s.source }))
      : [],
  };
}

export function writeManifest(path: string, manifest: Manifest): void {
  writeTextFile(path, `${canonicalJson(manifest)}\n`);
}

export function upsertSkill(manifest: Manifest, skill: ManifestSkill): Manifest {
  const skills = manifest.skills.filter((s) => s.name !== skill.name);
  skills.push(skill);
  skills.sort((a, b) => a.name.localeCompare(b.name));
  return { version: 1, skills };
}

export function removeSkill(manifest: Manifest, name: string): Manifest {
  return { version: 1, skills: manifest.skills.filter((s) => s.name !== name) };
}

export function findSkill(manifest: Manifest, name: string): ManifestSkill | undefined {
  return manifest.skills.find((s) => s.name === name);
}

/** Names matching a selector: exact name, or a glob. */
export function selectSkills(manifest: Manifest, selectors: string[] | undefined): ManifestSkill[] {
  if (!selectors || selectors.length === 0) return manifest.skills;
  return manifest.skills.filter(
    (s) => selectors.includes(s.name) || matchesAny(selectors, s.name),
  );
}
