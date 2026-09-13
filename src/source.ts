import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { sha256Hex } from "./util.ts";
import type { ResolvedSource } from "./types.ts";

export const CACHE_DIRNAME = ".skillnotary/cache";

export interface ParsedSource {
  kind: "path" | "git";
  /** Raw spec as written by the user. */
  spec: string;
  /** Local directory for path sources. */
  path?: string;
  url?: string;
  ref?: string;
  subpath?: string;
}

/**
 * Parse a source spec. Supported forms:
 *
 *   ./vendor/pdf-tools                      local directory
 *   /abs/path/to/skill                      local directory
 *   file:./relative/skill                   local directory
 *   github:owner/repo#skills/pdf@v1.2.0     GitHub, optional subpath + ref
 *   github:owner/repo                       whole repo root
 *   git+https://host/x.git#sub/skill@main   any git remote
 *   https://host/x.git#sub/skill            any git remote
 *
 * Fragment grammar is `[subpath][@ref]`: a leading `@` means "ref only".
 */
export function parseSource(spec: string): ParsedSource {
  const trimmed = spec.trim();
  if (trimmed === "") throw new Error("empty source spec");

  if (trimmed.startsWith("github:")) {
    const { base, subpath, ref } = splitFragment(trimmed.slice("github:".length));
    return {
      kind: "git",
      spec,
      url: `https://github.com/${base}.git`,
      ...(subpath !== undefined ? { subpath } : {}),
      ...(ref !== undefined ? { ref } : {}),
    };
  }

  if (trimmed.startsWith("git+")) {
    const { base, subpath, ref } = splitFragment(trimmed.slice("git+".length));
    return {
      kind: "git",
      spec,
      url: base,
      ...(subpath !== undefined ? { subpath } : {}),
      ...(ref !== undefined ? { ref } : {}),
    };
  }

  if (/^(?:https?|ssh|git):\/\//.test(trimmed) || /^git@/.test(trimmed)) {
    const { base, subpath, ref } = splitFragment(trimmed);
    return {
      kind: "git",
      spec,
      url: base,
      ...(subpath !== undefined ? { subpath } : {}),
      ...(ref !== undefined ? { ref } : {}),
    };
  }

  const path = trimmed.startsWith("file:") ? trimmed.slice("file:".length) : trimmed;
  return { kind: "path", spec, path };
}

function splitFragment(input: string): { base: string; subpath?: string; ref?: string } {
  const hash = input.indexOf("#");
  if (hash === -1) return { base: input };
  const base = input.slice(0, hash);
  const fragment = input.slice(hash + 1);
  if (fragment === "") return { base };

  if (fragment.startsWith("@")) return { base, ref: fragment.slice(1) };

  const at = fragment.lastIndexOf("@");
  if (at > 0) {
    return { base, subpath: fragment.slice(0, at), ref: fragment.slice(at + 1) };
  }
  return { base, subpath: fragment };
}

function git(args: string[], cwd?: string): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

export interface ResolveOptions {
  cwd: string;
  cacheDir: string;
  /** Force a fresh clone even if the cache entry exists. */
  refresh?: boolean;
}

/** Resolve a parsed source to a directory on disk plus provenance. */
export function resolveSource(parsed: ParsedSource, options: ResolveOptions): ResolvedSource {
  if (parsed.kind === "path") {
    const dir = resolve(options.cwd, parsed.path ?? ".");
    if (!existsSync(dir)) {
      throw new Error(`source path does not exist: ${parsed.path}`);
    }
    return { type: "path", spec: parsed.spec, dir };
  }

  const url = parsed.url ?? "";
  const key = sha256Hex(url).slice(0, 16);
  const cloneDir = join(options.cacheDir, key);

  if (options.refresh && existsSync(cloneDir)) {
    rmSync(cloneDir, { recursive: true, force: true });
  }

  if (!existsSync(cloneDir)) {
    mkdirSync(options.cacheDir, { recursive: true });
    const shallow = ["clone", "--quiet", "--depth", "1"];
    if (parsed.ref) shallow.push("--branch", parsed.ref);
    try {
      git([...shallow, url, cloneDir]);
    } catch {
      // A pinned commit sha cannot be used with --branch; fall back to a full
      // clone and an explicit checkout.
      rmSync(cloneDir, { recursive: true, force: true });
      git(["clone", "--quiet", url, cloneDir]);
      if (parsed.ref) git(["checkout", "--quiet", parsed.ref], cloneDir);
    }
  } else if (parsed.ref) {
    try {
      git(["fetch", "--quiet", "--depth", "1", "origin", parsed.ref], cloneDir);
      git(["checkout", "--quiet", "FETCH_HEAD"], cloneDir);
    } catch {
      /* keep the existing checkout */
    }
  }

  let commit: string | undefined;
  try {
    commit = git(["rev-parse", "HEAD"], cloneDir);
  } catch {
    commit = undefined;
  }

  const dir = parsed.subpath ? join(cloneDir, parsed.subpath) : cloneDir;
  if (!existsSync(dir)) {
    throw new Error(`subpath not found in ${url}: ${parsed.subpath}`);
  }

  return {
    type: "git",
    spec: parsed.spec,
    dir,
    url,
    ...(parsed.ref !== undefined ? { ref: parsed.ref } : {}),
    ...(commit !== undefined ? { commit } : {}),
    ...(parsed.subpath !== undefined ? { subpath: parsed.subpath } : {}),
  };
}

export function resolveSpec(spec: string, options: ResolveOptions): ResolvedSource {
  return resolveSource(parseSource(spec), options);
}

/** True when a source is remote and therefore worth pinning in a lockfile. */
export function isRemote(parsed: ParsedSource): boolean {
  return parsed.kind === "git";
}
