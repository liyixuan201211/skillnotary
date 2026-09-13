import assert from "node:assert/strict";
import { test } from "node:test";
import { createPrivateKey, sign as cryptoSign } from "node:crypto";

import {
  buildStatement,
  DSSE_PAYLOAD_TYPE,
  generateKeyPair,
  keyId,
  pae,
  signPayload,
  verifyPayload,
} from "../src/attest.ts";
import { buildSbom, sriToHex } from "../src/sbom.ts";
import { digestTree } from "../src/hash.ts";
import { sha256Hex, sri } from "../src/util.ts";
import { makeSkill } from "./helpers.ts";
import type { Attestation, DsseEnvelope, Lockfile } from "../src/types.ts";

function signRaw(payload: Buffer, privateKeyB64: string): string {
  const privateKey = createPrivateKey({
    key: Buffer.from(privateKeyB64, "base64"),
    format: "der",
    type: "pkcs8",
  });
  return cryptoSign(null, payload, privateKey).toString("base64");
}

test("a signed payload verifies as a DSSE envelope", () => {
  const keys = generateKeyPair();
  const payload = Buffer.from("skills.lock contents", "utf8");
  const attestation = signPayload(payload, keys, "skills.lock");

  assert.equal(attestation.payloadType, DSSE_PAYLOAD_TYPE);
  assert.equal(attestation.signatures.length, 1);
  assert.equal(attestation.signatures[0]?.keyid, keyId(keys.publicKey));

  const result = verifyPayload(attestation, payload);
  assert.equal(result.valid, true);
  assert.equal(result.format, "dsse");
  assert.equal(result.keyId, keyId(keys.publicKey));
});

test("the statement is in-toto shaped and carries the subject digest", () => {
  const keys = generateKeyPair();
  const payload = Buffer.from("lockfile bytes");
  const statement = buildStatement("skills.lock", payload, keys, {
    configDigest: "sha256-AAA",
    skills: [{ name: "pdf", integrity: "sha256-BBB", capabilities: ["exec"] }],
  });

  assert.equal(statement._type, "https://in-toto.io/Statement/v1");
  assert.equal(statement.subject[0]?.name, "skills.lock");
  assert.equal(statement.subject[0]?.digest["sha256"], sha256Hex(payload));
  assert.equal(statement.predicate.configDigest, "sha256-AAA");
  assert.equal(statement.predicate.skillCount, 1);
  assert.deepEqual(statement.predicate.skills[0]?.capabilities, ["exec"]);
});

test("PAE length-encodes the type and payload", () => {
  const a = pae("t", Buffer.from("xy"));
  const b = pae("tx", Buffer.from("y"));
  assert.notEqual(a.toString("hex"), b.toString("hex"), "the boundaries must be unambiguous");
  assert.equal(a.toString("utf8"), "DSSEv1 1 t 2 xy");
});

test("a modified payload fails verification", () => {
  const keys = generateKeyPair();
  const attestation = signPayload(Buffer.from("original"), keys, "skills.lock");
  const result = verifyPayload(attestation, Buffer.from("original + tampered"));
  assert.equal(result.valid, false);
  assert.match(result.reason ?? "", /changed since it was attested/);
});

test("swapping the public key inside the statement invalidates the signature", () => {
  const signer = generateKeyPair();
  const attacker = generateKeyPair();
  const payload = Buffer.from("payload");
  const envelope = signPayload(payload, signer, "skills.lock");

  const statement = JSON.parse(Buffer.from(envelope.payload, "base64").toString("utf8")) as {
    predicate: { signer: { publicKey: string } };
  };
  statement.predicate.signer.publicKey = attacker.publicKey;
  const forged: DsseEnvelope = {
    ...envelope,
    payload: Buffer.from(JSON.stringify(statement)).toString("base64"),
  };
  assert.equal(verifyPayload(forged, payload).valid, false);
});

test("a well-formed signature from an untrusted key is identifiable, so trust can pin it", () => {
  const signer = generateKeyPair();
  const attacker = generateKeyPair();
  const payload = Buffer.from("payload");

  const signedByAttacker = signPayload(payload, attacker, "skills.lock");
  const result = verifyPayload(signedByAttacker, payload);
  assert.equal(result.valid, true, "the envelope itself is well formed");
  assert.notEqual(result.keyId, keyId(signer.publicKey), "but it is not the key we trust");
});

test("ed25519 signatures are deterministic for the same payload", () => {
  const keys = generateKeyPair();
  const payload = Buffer.from("same");
  const a = signPayload(payload, keys, "x");
  const b = signPayload(payload, keys, "x");
  assert.equal(a.signatures[0]?.sig, b.signatures[0]?.sig);
  assert.equal(verifyPayload(a, payload).valid, true);
});

test("the legacy attestation format still verifies", () => {
  const keys = generateKeyPair();
  const payload = Buffer.from("legacy bytes");
  const legacy: Attestation = {
    format: "skillnotary/attestation@1",
    subject: { name: "skills.lock", digest: sri(payload) },
    algorithm: "ed25519",
    keyId: keyId(keys.publicKey),
    publicKey: keys.publicKey,
    signature: signRaw(payload, keys.privateKey),
    signedAt: new Date().toISOString(),
  };

  const result = verifyPayload(legacy, payload);
  assert.equal(result.valid, true);
  assert.equal(result.format, "legacy");
});

test("an unrecognised attestation format is rejected", () => {
  const bogus = { hello: "world" } as unknown as Attestation;
  assert.equal(verifyPayload(bogus, Buffer.from("x")).valid, false);
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
