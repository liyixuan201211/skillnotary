import assert from "node:assert/strict";
import { test } from "node:test";

import { generateKeyPair, keyId, signPayload, verifyPayload } from "../src/attest.ts";
import { buildSbom, sriToHex } from "../src/sbom.ts";
import { digestTree } from "../src/hash.ts";
import { makeSkill } from "./helpers.ts";
import type { Attestation, Lockfile } from "../src/types.ts";

test("a signed payload verifies", () => {
  const keys = generateKeyPair();
  const payload = Buffer.from("skills.lock contents", "utf8");
  const attestation = signPayload(payload, keys, "skills.lock");

  assert.equal(attestation.algorithm, "ed25519");
  assert.equal(attestation.keyId, keyId(keys.publicKey));
  assert.equal(verifyPayload(attestation, payload).valid, true);
});

test("a modified payload fails verification", () => {
  const keys = generateKeyPair();
  const attestation = signPayload(Buffer.from("original"), keys, "skills.lock");
  const result = verifyPayload(attestation, Buffer.from("original + tampered"));
  assert.equal(result.valid, false);
  assert.match(result.reason ?? "", /changed since it was attested/);
});

test("a signature from another key fails verification", () => {
  const signer = generateKeyPair();
  const attacker = generateKeyPair();
  const payload = Buffer.from("payload");
  const attestation = signPayload(payload, signer, "skills.lock");

  // Swap in the attacker's public key while keeping the signature.
  const forged: Attestation = { ...attestation, publicKey: attacker.publicKey };
  assert.equal(verifyPayload(forged, payload).valid, false);
});

test("every signature is distinct for the same payload", () => {
  const keys = generateKeyPair();
  const payload = Buffer.from("same");
  const a = signPayload(payload, keys, "x");
  const b = signPayload(payload, keys, "x");
  // ed25519 is deterministic, so the signatures should in fact match.
  assert.equal(a.signature, b.signature);
  assert.equal(verifyPayload(a, payload).valid, true);
});

test("the tree digest is stable and content-sensitive", () => {
  const dir = makeSkill({ "SKILL.md": "---\nname: a\n---\nhello\n" });
  const first = digestTree(dir);
  const second = digestTree(dir);
  assert.equal(first.integrity, second.integrity);
  assert.equal(first.files, 1);
  assert.ok(first.bytes > 0);
});

test("the tree digest ignores node_modules and .git", () => {
  const dir = makeSkill({
    "SKILL.md": "---\nname: a\n---\nhello\n",
    "node_modules/dep/index.js": "module.exports = 1",
    ".git/config": "[core]",
  });
  const digest = digestTree(dir);
  assert.equal(digest.files, 1, "only SKILL.md should be counted");
  assert.ok(digest.entries["SKILL.md"]);
  assert.equal(digest.entries["node_modules/dep/index.js"], undefined);
});

test("the SBOM carries capabilities, hashes and provenance", () => {
  const lockfile: Lockfile = {
    lockfileVersion: 1,
    generator: "test",
    skills: [
      {
        name: "pdf-tools",
        source: "github:acme/skills#pdf@v1",
        resolved: {
          type: "git",
          spec: "github:acme/skills#pdf@v1",
          dir: "/tmp/x",
          url: "https://github.com/acme/skills.git",
          commit: "abc123",
        },
        integrity: "sha256-YWJj",
        files: 3,
        bytes: 100,
        capabilities: ["exec", "network"],
        declared: ["exec"],
        declaredTools: ["Bash"],
        license: "MIT",
        description: "does things",
      },
    ],
  };

  const sbom = buildSbom(lockfile, "demo");
  assert.equal(sbom.bomFormat, "skillnotary/sbom@1");
  assert.equal(sbom.components.length, 1);

  const component = sbom.components[0];
  assert.ok(component);
  assert.equal(component.name, "pdf-tools");
  assert.equal(component.hashes[0]?.alg, "SHA-256");
  assert.equal(component.hashes[0]?.content, sriToHex("sha256-YWJj"));
  assert.equal(component.licenses?.[0]?.license.id, "MIT");

  const caps = component.properties.find((p) => p.name === "skillnotary:capabilities");
  assert.equal(caps?.value, "exec,network");
});
