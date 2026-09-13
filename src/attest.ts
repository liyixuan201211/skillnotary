import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";
import { readFileSync, writeFileSync, chmodSync } from "node:fs";
import { sha256Hex, sri, readTextFileSafe } from "./util.ts";
import type { Attestation } from "./types.ts";

export const ATTEST_FILENAME = "skills.lock.attestation.json";
export const KEYFILE_FILENAME = "skillnotary.key.json";
export const FORMAT = "skillnotary/attestation@1";

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

export function signPayload(payload: Buffer, keys: KeyPairB64, subjectName: string): Attestation {
  const privateKey = createPrivateKey({
    key: Buffer.from(keys.privateKey, "base64"),
    format: "der",
    type: "pkcs8",
  });
  const signature = cryptoSign(null, payload, privateKey).toString("base64");
  return {
    format: FORMAT,
    subject: {
      name: subjectName,
      digest: sri(payload),
    },
    algorithm: "ed25519",
    keyId: keyId(keys.publicKey),
    publicKey: keys.publicKey,
    signature,
    signedAt: new Date().toISOString(),
  };
}

export interface VerifyResult {
  valid: boolean;
  reason?: string;
}

export function verifyPayload(attestation: Attestation, payload: Buffer): VerifyResult {
  if (attestation.format !== FORMAT) {
    return { valid: false, reason: `unsupported attestation format: ${String(attestation.format)}` };
  }
  if (attestation.algorithm !== "ed25519") {
    return { valid: false, reason: `unsupported algorithm: ${String(attestation.algorithm)}` };
  }

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
    return ok ? { valid: true } : { valid: false, reason: "signature does not match the payload" };
  } catch (error) {
    return { valid: false, reason: `could not verify signature: ${String(error)}` };
  }
}

export function readAttestation(path: string): Attestation | null {
  const raw = readTextFileSafe(path);
  if (raw === null) return null;
  try {
    return JSON.parse(raw) as Attestation;
  } catch {
    return null;
  }
}

export function attestationPath(cwd: string): string {
  return `${cwd}/${ATTEST_FILENAME}`;
}
