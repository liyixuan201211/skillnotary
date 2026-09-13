import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";
import { readFileSync, writeFileSync, chmodSync } from "node:fs";
import { sha256Hex, sri, readTextFileSafe } from "./util.ts";
import { GENERATOR } from "./version.ts";
import type {
  Attestation,
  AttestationFile,
  DsseEnvelope,
  InTotoStatement,
  VerifyResult,
} from "./types.ts";

export const ATTEST_FILENAME = "skills.lock.attestation.json";
export const KEYFILE_FILENAME = "skillnotary.key.json";

/** Legacy bespoke format, still verifiable. */
export type { VerifyResult } from "./types.ts";

/** Legacy bespoke format, still verifiable. */
export const FORMAT = "skillnotary/attestation@1";

export const DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json";
export const STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
export const PREDICATE_TYPE = "https://skillnotary.dev/attestation/skills/v1";

export interface KeyPairB64 {
  publicKey: string;
  privateKey: string;
}

export function generateKeyPair(): KeyPairB64 {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKey: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    privateKey: privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
  };
}

export interface KeyFile extends KeyPairB64 {
  version: 1;
  algorithm: "ed25519";
  createdAt: string;
}

/** Write a keypair. The private half never leaves this file unencrypted. */
export function writeKeyFile(path: string, keys: KeyPairB64): KeyFile {
  const file: KeyFile = {
    version: 1,
    algorithm: "ed25519",
    createdAt: new Date().toISOString(),
    ...keys,
  };
  writeFileSync(path, `${JSON.stringify(file, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  try {
    chmodSync(path, 0o600);
  } catch {
    /* best effort on platforms without POSIX modes */
  }
  return file;
}

export function readKeyFile(path: string): KeyFile {
  const raw = readFileSync(path, "utf8");
  const parsed = JSON.parse(raw) as Partial<KeyFile>;
  if (!parsed.publicKey || !parsed.privateKey) {
    throw new Error(`keyfile ${path} is missing publicKey/privateKey`);
  }
  return {
    version: 1,
    algorithm: "ed25519",
    createdAt: parsed.createdAt ?? "",
    publicKey: parsed.publicKey,
    privateKey: parsed.privateKey,
  };
}

export function readPublicKeyOnly(path: string): { publicKey: string; privateKey?: string } {
  const raw = readFileSync(path, "utf8");
  const parsed = JSON.parse(raw) as Partial<KeyPairB64>;
  if (!parsed.publicKey) throw new Error(`keyfile ${path} is missing publicKey`);
  return parsed.privateKey
    ? { publicKey: parsed.publicKey, privateKey: parsed.privateKey }
    : { publicKey: parsed.publicKey };
}

/** A short, stable identifier for a public key. */
export function keyId(publicKeyB64: string): string {
  return `ed25519:${sha256Hex(Buffer.from(publicKeyB64, "base64")).slice(0, 16)}`;
}

/**
 * DSSE pre-authentication encoding (the signing input defined by the DSSE spec).
 *
 *   PAE(type, payload) = "DSSEv1" SP LEN(type) SP type SP LEN(payload) SP payload
 *
 * Encoding the lengths is what stops an attacker shifting bytes between the
 * type and the payload — the classic ambiguity attack on concatenation.
 */
export function pae(payloadType: string, payload: Buffer): Buffer {
  const type = Buffer.from(payloadType, "utf8");
  return Buffer.concat([
    Buffer.from("DSSEv1", "utf8"),
    Buffer.from(` ${type.length} `, "utf8"),
    type,
    Buffer.from(` ${payload.length} `, "utf8"),
    payload,
  ]);
}

export interface LockPredicateInput {
  generator?: string;
  configDigest?: string | null;
  skills?: Array<{ name: string; integrity: string; capabilities: string[] }>;
}

/**
 * Build an in-toto statement about a lockfile.
 *
 * The signer's public key travels inside the signed predicate so verification
 * is self-contained; *who* may sign is pinned separately by `policy.trustedKeys`.
 */
export function buildStatement(
  subjectName: string,
  subjectBytes: Buffer,
  keys: KeyPairB64,
  extra: LockPredicateInput = {},
): InTotoStatement {
  return {
    _type: STATEMENT_TYPE,
    subject: [{ name: subjectName, digest: { sha256: sha256Hex(subjectBytes) } }],
    predicateType: PREDICATE_TYPE,
    predicate: {
      generator: extra.generator ?? GENERATOR,
      signer: { keyId: keyId(keys.publicKey), publicKey: keys.publicKey },
      configDigest: extra.configDigest ?? null,
      skillCount: extra.skills?.length ?? 0,
      skills: (extra.skills ?? []).map((skill) => ({
        name: skill.name,
        integrity: skill.integrity,
        capabilities: skill.capabilities,
      })),
    },
  };
}

/** Sign a payload, producing a DSSE envelope. */
export function signPayload(
  payload: Buffer,
  keys: KeyPairB64,
  subjectName: string,
  extra: LockPredicateInput = {},
): DsseEnvelope {
  const statement = buildStatement(subjectName, payload, keys, extra);
  const encoded = Buffer.from(JSON.stringify(statement), "utf8");
  const privateKey = createPrivateKey({
    key: Buffer.from(keys.privateKey, "base64"),
    format: "der",
    type: "pkcs8",
  });
  const signature = cryptoSign(null, pae(DSSE_PAYLOAD_TYPE, encoded), privateKey);
  return {
    payloadType: DSSE_PAYLOAD_TYPE,
    payload: encoded.toString("base64"),
    signatures: [{ keyid: keyId(keys.publicKey), sig: signature.toString("base64") }],
  };
}

function isDsse(value: unknown): value is DsseEnvelope {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return typeof record["payload"] === "string" && Array.isArray(record["signatures"]);
}

function isLegacy(value: unknown): value is Attestation {
  if (typeof value !== "object" || value === null) return false;
  return (value as Record<string, unknown>)["format"] === FORMAT;
}

/** Verify a DSSE envelope against the payload it should cover. */
export function verifyDsse(envelope: DsseEnvelope, subjectBytes: Buffer): VerifyResult {
  const payloadType = envelope.payloadType;
  if (payloadType !== DSSE_PAYLOAD_TYPE) {
    return { valid: false, reason: `unsupported DSSE payloadType: ${String(payloadType)}` };
  }

  let encoded: Buffer;
  let statement: InTotoStatement;
  try {
    encoded = Buffer.from(envelope.payload, "base64");
    statement = JSON.parse(encoded.toString("utf8")) as InTotoStatement;
  } catch {
    return { valid: false, reason: "DSSE payload is not valid base64 JSON" };
  }

  // The subject digest must match the file being verified.
  const expected = sha256Hex(subjectBytes);
  const declared = statement.subject?.[0]?.digest?.sha256;
  if (declared !== expected) {
    return { valid: false, reason: "the signed file has changed since it was attested" };
  }

  const publicKeyB64 = statement.predicate?.signer?.publicKey;
  const signature = envelope.signatures[0];
  if (typeof publicKeyB64 !== "string" || signature === undefined) {
    return { valid: false, reason: "envelope is missing a signer public key or signature" };
  }

  try {
    const publicKey = createPublicKey({
      key: Buffer.from(publicKeyB64, "base64"),
      format: "der",
      type: "spki",
    });
    const ok = cryptoVerify(
      null,
      pae(payloadType, encoded),
      publicKey,
      Buffer.from(signature.sig, "base64"),
    );
    return ok
      ? { valid: true, keyId: signature.keyid, publicKey: publicKeyB64, format: "dsse" }
      : { valid: false, reason: "signature does not match the payload", format: "dsse" };
  } catch (error) {
    return { valid: false, reason: `could not verify signature: ${String(error)}`, format: "dsse" };
  }
}

/** Verify the legacy bespoke format. */
function verifyLegacy(attestation: Attestation, payload: Buffer): VerifyResult {
  const expectedDigest = sri(payload);
  if (attestation.subject.digest !== expectedDigest) {
    return { valid: false, reason: "the signed file has changed since it was attested" };
  }
  try {
    const publicKey = createPublicKey({
      key: Buffer.from(attestation.publicKey, "base64"),
      format: "der",
      type: "spki",
    });
    const ok = cryptoVerify(
      null,
      payload,
      publicKey,
      Buffer.from(attestation.signature, "base64"),
    );
    return ok
      ? { valid: true, keyId: attestation.keyId, publicKey: attestation.publicKey, format: "legacy" }
      : { valid: false, reason: "signature does not match the payload", format: "legacy" };
  } catch (error) {
    return { valid: false, reason: `could not verify signature: ${String(error)}`, format: "legacy" };
  }
}

/**
 * Verify an attestation of either format.
 *
 * DSSE envelopes are preferred; the legacy `skillnotary/attestation@1` shape is
 * still accepted so existing lockfiles keep verifying.
 */
export function verifyPayload(attestation: AttestationFile, payload: Buffer): VerifyResult {
  if (isDsse(attestation)) return verifyDsse(attestation, payload);
  if (isLegacy(attestation)) return verifyLegacy(attestation, payload);
  return { valid: false, reason: "unrecognised attestation format" };
}

export function readAttestation(path: string): AttestationFile | null {
  const raw = readTextFileSafe(path);
  if (raw === null) return null;
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (isDsse(parsed) || isLegacy(parsed)) return parsed as AttestationFile;
    return null;
  } catch {
    return null;
  }
}

export function attestationPath(cwd: string): string {
  return `${cwd}/${ATTEST_FILENAME}`;
}
