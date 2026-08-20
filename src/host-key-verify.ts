/**
 * SSH host key verification against an OpenSSH known_hosts file.
 *
 * Design choice: we do NOT set ssh2's `hostHash` option, so the `hostVerifier`
 * callback receives the RAW host key blob (SSH wire format, Buffer). The
 * base64 of that raw blob is byte-for-byte the key field stored in
 * ~/.ssh/known_hosts, and the blob's leading length-prefixed string is the
 * key type ("ssh-ed25519", "ssh-rsa", ...). That lets us match host, key
 * type, and key material directly against known_hosts entries — a hashed
 * (hostHash) callback value could not be compared against known_hosts at all.
 *
 * FAIL CLOSED: unknown hosts, missing known_hosts, and key mismatches all
 * refuse the connection. The only bypass is the MCP_SSH_SKIP_HOST_KEY_VERIFY
 * environment variable, which is read at connect time (never at module load).
 */

import { readFileSync } from "fs";
import * as os from "os";
import * as path from "path";
import * as crypto from "crypto";

export const SKIP_ENV_VAR = "MCP_SSH_SKIP_HOST_KEY_VERIFY";

export interface VerifyOptions {
  /** Path to a known_hosts file. Defaults to ~/.ssh/known_hosts. */
  knownHostsPath?: string;
  /** Environment to consult for the opt-out variable. Defaults to process.env. */
  env?: Record<string, string | undefined>;
}

export type VerifyResult =
  | { ok: true; reason: "match" | "skipped" }
  | {
      ok: false;
      reason:
        | "unknown-host"
        | "key-mismatch"
        | "revoked"
        | "missing-known-hosts"
        | "malformed-key";
      message: string;
    };

/** Extract the key type ("ssh-ed25519", "ssh-rsa", ...) from a raw SSH public key blob. */
export function keyTypeFromBlob(rawKey: Buffer): string | undefined {
  if (rawKey.length < 4) return undefined;
  const len = rawKey.readUInt32BE(0);
  if (len <= 0 || len > 64 || rawKey.length < 4 + len) return undefined;
  return rawKey.subarray(4, 4 + len).toString("ascii");
}

function skipRequested(env: Record<string, string | undefined>): boolean {
  const v = env[SKIP_ENV_VAR];
  return v === "1" || v === "true" || v === "yes";
}

/**
 * Does one known_hosts host pattern match any of the candidate host strings?
 * Supports hashed `|1|salt|hash` entries (HMAC-SHA1 keyed by salt) and plain
 * (exact, case-insensitive) hostname entries. Wildcard patterns are not
 * supported and simply never match.
 */
function patternMatches(pattern: string, candidates: string[]): boolean {
  if (pattern.startsWith("|1|")) {
    const parts = pattern.split("|"); // ['', '1', saltB64, hashB64]
    if (parts.length !== 4) return false;
    let salt: Buffer;
    try {
      salt = Buffer.from(parts[2], "base64");
    } catch {
      return false;
    }
    return candidates.some(
      (c) =>
        crypto.createHmac("sha1", salt).update(c).digest("base64") === parts[3],
    );
  }
  const p = pattern.toLowerCase();
  return candidates.some((c) => c.toLowerCase() === p);
}

function keysEqual(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/**
 * Verify a raw SSH host key blob for `host`:`port` against known_hosts.
 * Pure decision function — no side effects; the known_hosts path and env are
 * injectable so it is unit-testable without touching the real ~/.ssh.
 */
export function verifyHostKey(
  host: string,
  port: number | undefined,
  rawKey: Buffer,
  options: VerifyOptions = {},
): VerifyResult {
  const env = options.env ?? process.env;
  // Opt-out is evaluated here, at verification (i.e. connect) time.
  if (skipRequested(env)) {
    return { ok: true, reason: "skipped" };
  }

  const knownHostsPath =
    options.knownHostsPath ?? path.join(os.homedir(), ".ssh", "known_hosts");

  const keyType = keyTypeFromBlob(rawKey);
  if (!keyType) {
    return {
      ok: false,
      reason: "malformed-key",
      message: `Refusing connection to ${host}: server presented a malformed host key blob.`,
    };
  }

  // OpenSSH stores non-default ports as "[host]:port"; port 22 as bare host.
  const candidates =
    port === undefined || port === 22
      ? [host, `[${host}]:22`]
      : [`[${host}]:${port}`];

  let content: string;
  try {
    content = readFileSync(knownHostsPath, "utf8");
  } catch {
    return {
      ok: false,
      reason: "missing-known-hosts",
      message:
        `Refusing connection to ${host}: known_hosts file not readable at ${knownHostsPath}. ` +
        `Connect once manually (ssh ${portFlag(port)}${host}) to record the host key, ` +
        `or set ${SKIP_ENV_VAR}=1 to explicitly skip host key verification.`,
    };
  }

  let sawMismatch = false;
  let sawRevoked = false;

  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    let fields = line.split(/\s+/);
    let marker: string | undefined;
    if (fields[0].startsWith("@")) {
      marker = fields[0];
      fields = fields.slice(1);
    }
    if (fields.length < 3) continue;
    if (marker === "@cert-authority") continue; // CA lines are not raw host keys

    const [hostField, typeField, keyField] = fields;
    if (typeField !== keyType) continue;

    const patterns = hostField.split(",");
    // A negated pattern ("!host") excludes the whole line for that host.
    if (
      patterns.some(
        (p) => p.startsWith("!") && patternMatches(p.slice(1), candidates),
      )
    ) {
      continue;
    }
    const hostMatched = patterns.some(
      (p) => !p.startsWith("!") && patternMatches(p, candidates),
    );
    if (!hostMatched) continue;

    let knownKey: Buffer;
    try {
      knownKey = Buffer.from(keyField, "base64");
    } catch {
      continue;
    }

    if (keysEqual(knownKey, rawKey)) {
      if (marker === "@revoked") {
        sawRevoked = true;
        continue;
      }
      return { ok: true, reason: "match" };
    }
    sawMismatch = true;
  }

  if (sawRevoked) {
    return {
      ok: false,
      reason: "revoked",
      message: `Refusing connection to ${host}: the presented ${keyType} host key is marked @revoked in ${knownHostsPath}.`,
    };
  }
  if (sawMismatch) {
    return {
      ok: false,
      reason: "key-mismatch",
      message:
        `HOST KEY MISMATCH for ${host}: the server's ${keyType} key does not match the entry in ${knownHostsPath}. ` +
        `This may indicate a man-in-the-middle attack. If the host key legitimately changed, ` +
        `update ${knownHostsPath} (e.g. ssh-keygen -R '${port === undefined || port === 22 ? host : `[${host}]:${port}`}' then reconnect manually).`,
    };
  }
  return {
    ok: false,
    reason: "unknown-host",
    message:
      `Refusing connection to ${host}: no ${keyType} host key for it in ${knownHostsPath}. ` +
      `Connect once manually (ssh ${portFlag(port)}${host}) to record the host key, ` +
      `or set ${SKIP_ENV_VAR}=1 to explicitly skip host key verification.`,
  };
}

function portFlag(port: number | undefined): string {
  return port === undefined || port === 22 ? "" : `-p ${port} `;
}

export interface HostVerifierHandle {
  /** Sync ssh2 hostVerifier callback (arity 1 => ssh2 treats the return value as the verdict). */
  hostVerifier: (rawKey: Buffer) => boolean;
  /** The refusal message from the last failed verification, if any. */
  lastFailure: () => string | undefined;
}

/**
 * Build an ssh2 `hostVerifier` bound to a host/port, capturing the refusal
 * reason so the caller can surface an actionable error message (ssh2 itself
 * only reports a generic handshake failure).
 */
export function createHostVerifier(
  host: string,
  port: number | undefined,
  options: VerifyOptions = {},
): HostVerifierHandle {
  let failure: string | undefined;
  return {
    hostVerifier: (rawKey: Buffer): boolean => {
      const result = verifyHostKey(host, port, rawKey, options);
      if (!result.ok) {
        failure = result.message;
        return false;
      }
      return true;
    },
    lastFailure: () => failure,
  };
}
