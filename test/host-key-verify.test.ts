import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as crypto from "node:crypto";

import {
  verifyHostKey,
  createHostVerifier,
  keyTypeFromBlob,
  SKIP_ENV_VAR,
} from "../src/host-key-verify.js";

// Build a raw SSH public key blob (wire format: uint32 len + type + material).
function makeKeyBlob(type: string, material: Buffer): Buffer {
  const t = Buffer.from(type, "ascii");
  const len = Buffer.alloc(4);
  len.writeUInt32BE(t.length, 0);
  return Buffer.concat([len, t, material]);
}

function writeKnownHosts(lines: string[]): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-ssh-khtest-"));
  const p = path.join(dir, "known_hosts");
  fs.writeFileSync(p, lines.join("\n") + "\n");
  return p;
}

function hashedPattern(host: string): string {
  const salt = crypto.randomBytes(20);
  const hash = crypto.createHmac("sha1", salt).update(host).digest("base64");
  return `|1|${salt.toString("base64")}|${hash}`;
}

const HOST = "etl.example.com";
const goodKey = makeKeyBlob("ssh-ed25519", crypto.randomBytes(32));
const wrongKey = makeKeyBlob("ssh-ed25519", crypto.randomBytes(32));
const NO_ENV = {}; // never inherit the real process env in these tests

test("known host with matching key passes (plain entry)", () => {
  const kh = writeKnownHosts([
    `${HOST} ssh-ed25519 ${goodKey.toString("base64")}`,
  ]);
  const res = verifyHostKey(HOST, 22, goodKey, {
    knownHostsPath: kh,
    env: NO_ENV,
  });
  assert.equal(res.ok, true);
});

test("known host with matching key passes (hashed |1| entry)", () => {
  const kh = writeKnownHosts([
    `${hashedPattern(HOST)} ssh-ed25519 ${goodKey.toString("base64")}`,
  ]);
  const res = verifyHostKey(HOST, 22, goodKey, {
    knownHostsPath: kh,
    env: NO_ENV,
  });
  assert.equal(res.ok, true);
});

test("unknown host refuses with operator guidance", () => {
  const kh = writeKnownHosts([
    `other.example.com ssh-ed25519 ${goodKey.toString("base64")}`,
  ]);
  const res = verifyHostKey(HOST, 22, goodKey, {
    knownHostsPath: kh,
    env: NO_ENV,
  });
  assert.equal(res.ok, false);
  if (!res.ok) {
    assert.equal(res.reason, "unknown-host");
    assert.match(res.message, /Connect once manually/);
    assert.match(res.message, new RegExp(SKIP_ENV_VAR));
  }
});

test("known host with WRONG key refuses (mismatch, possible MITM)", () => {
  const kh = writeKnownHosts([
    `${HOST} ssh-ed25519 ${goodKey.toString("base64")}`,
  ]);
  const res = verifyHostKey(HOST, 22, wrongKey, {
    knownHostsPath: kh,
    env: NO_ENV,
  });
  assert.equal(res.ok, false);
  if (!res.ok) {
    assert.equal(res.reason, "key-mismatch");
    assert.match(res.message, /HOST KEY MISMATCH/);
  }
});

test("missing known_hosts file refuses (fail closed)", () => {
  const res = verifyHostKey(HOST, 22, goodKey, {
    knownHostsPath: "/nonexistent/known_hosts-for-mcp-ssh-test",
    env: NO_ENV,
  });
  assert.equal(res.ok, false);
  if (!res.ok) assert.equal(res.reason, "missing-known-hosts");
});

test("opt-out env var bypasses verification", () => {
  const res = verifyHostKey(HOST, 22, wrongKey, {
    knownHostsPath: "/nonexistent/known_hosts-for-mcp-ssh-test",
    env: { [SKIP_ENV_VAR]: "1" },
  });
  assert.equal(res.ok, true);
  if (res.ok) assert.equal(res.reason, "skipped");
});

test("non-standard port matches [host]:port entry and not the bare-host entry", () => {
  const kh = writeKnownHosts([
    `[${HOST}]:2222 ssh-ed25519 ${goodKey.toString("base64")}`,
  ]);
  const on2222 = verifyHostKey(HOST, 2222, goodKey, {
    knownHostsPath: kh,
    env: NO_ENV,
  });
  assert.equal(on2222.ok, true);
  const on22 = verifyHostKey(HOST, 22, goodKey, {
    knownHostsPath: kh,
    env: NO_ENV,
  });
  assert.equal(on22.ok, false);
});

test("key type must match the known_hosts entry type", () => {
  const rsaMaterial = crypto.randomBytes(64);
  const kh = writeKnownHosts([
    `${HOST} ssh-rsa ${makeKeyBlob("ssh-rsa", rsaMaterial).toString("base64")}`,
  ]);
  // Same host, but the server presents an ed25519 key: no ssh-rsa/ed25519 entry match.
  const res = verifyHostKey(HOST, 22, goodKey, {
    knownHostsPath: kh,
    env: NO_ENV,
  });
  assert.equal(res.ok, false);
  if (!res.ok) assert.equal(res.reason, "unknown-host");
});

test("keyTypeFromBlob extracts the wire-format type", () => {
  assert.equal(keyTypeFromBlob(goodKey), "ssh-ed25519");
  assert.equal(keyTypeFromBlob(Buffer.from([0, 0])), undefined);
});

test("createHostVerifier returns false and captures the refusal message", () => {
  const kh = writeKnownHosts([
    `${HOST} ssh-ed25519 ${goodKey.toString("base64")}`,
  ]);
  const handle = createHostVerifier(HOST, 22, {
    knownHostsPath: kh,
    env: NO_ENV,
  });
  assert.equal(handle.lastFailure(), undefined);
  assert.equal(handle.hostVerifier(wrongKey), false);
  assert.match(handle.lastFailure() ?? "", /HOST KEY MISMATCH/);
  // and a good key verifies true
  const handle2 = createHostVerifier(HOST, 22, {
    knownHostsPath: kh,
    env: NO_ENV,
  });
  assert.equal(handle2.hostVerifier(goodKey), true);
  assert.equal(handle2.lastFailure(), undefined);
});
