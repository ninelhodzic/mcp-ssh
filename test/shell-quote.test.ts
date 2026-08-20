import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as crypto from "node:crypto";
import { spawnSync } from "node:child_process";

import { shellQuote, isValidEnvVarName } from "../src/shell-quote.js";

// Run `sh -c "printf %s <quoted>"` and return what the shell saw as the
// single argument word — a real-shell round trip of the quoting.
function shellRoundTrip(quoted: string): {
  stdout: string;
  status: number | null;
} {
  const r = spawnSync("sh", ["-c", `printf %s ${quoted}`], {
    encoding: "utf8",
  });
  return { stdout: r.stdout, status: r.status };
}

test("benign absolute path: exact quoted form, unchanged in effect", () => {
  assert.equal(shellQuote("/var/log/foo"), "'/var/log/foo'");
  const r = shellRoundTrip(shellQuote("/var/log/foo"));
  assert.equal(r.status, 0);
  assert.equal(r.stdout, "/var/log/foo");
});

test("empty string quotes to '' and stays one empty word", () => {
  assert.equal(shellQuote(""), "''");
  const r = shellRoundTrip(shellQuote(""));
  assert.equal(r.status, 0);
  assert.equal(r.stdout, "");
});

test("command substitution $(...) is neutralized", () => {
  const hostile = "$(touch /tmp/pwned)";
  assert.equal(shellQuote(hostile), "'$(touch /tmp/pwned)'");
});

test("command substitution does not execute in a real shell", () => {
  const canary = path.join(
    os.tmpdir(),
    `mcp-ssh-sq-canary-${crypto.randomBytes(6).toString("hex")}`,
  );
  const hostile = `$(touch ${canary})`;
  const r = shellRoundTrip(shellQuote(hostile));
  assert.equal(r.status, 0);
  assert.equal(r.stdout, hostile);
  assert.equal(fs.existsSync(canary), false, "command substitution executed!");
});

test("backticks are neutralized", () => {
  const hostile = "`id`";
  assert.equal(shellQuote(hostile), "'`id`'");
  const r = shellRoundTrip(shellQuote(hostile));
  assert.equal(r.status, 0);
  assert.equal(r.stdout, hostile);
});

test("embedded single quote is escaped as '\\''", () => {
  const hostile = "a'b";
  assert.equal(shellQuote(hostile), "'a'\\''b'");
  const r = shellRoundTrip(shellQuote(hostile));
  assert.equal(r.status, 0);
  assert.equal(r.stdout, hostile);
});

test("quote-breakout payload ('; rm -rf /; ') survives as a literal", () => {
  const hostile = "'; rm -rf /; '";
  assert.equal(shellQuote(hostile), "''\\''; rm -rf /; '\\'''");
  const r = shellRoundTrip(shellQuote(hostile));
  assert.equal(r.status, 0);
  assert.equal(r.stdout, hostile);
});

test("double quotes are neutralized", () => {
  const hostile = 'a"b"c';
  assert.equal(shellQuote(hostile), "'a\"b\"c'");
  const r = shellRoundTrip(shellQuote(hostile));
  assert.equal(r.status, 0);
  assert.equal(r.stdout, hostile);
});

test("dollar variable expansion is neutralized", () => {
  const hostile = "$HOME/$PATH";
  assert.equal(shellQuote(hostile), "'$HOME/$PATH'");
  const r = shellRoundTrip(shellQuote(hostile));
  assert.equal(r.status, 0);
  assert.equal(r.stdout, hostile);
});

test("spaces stay one word", () => {
  const hostile = "a b  c";
  assert.equal(shellQuote(hostile), "'a b  c'");
  const r = shellRoundTrip(shellQuote(hostile));
  assert.equal(r.status, 0);
  assert.equal(r.stdout, hostile);
});

test("newline and semicolon stay literal", () => {
  const hostile = "a\nb; touch x";
  assert.equal(shellQuote(hostile), "'a\nb; touch x'");
  const r = shellRoundTrip(shellQuote(hostile));
  assert.equal(r.status, 0);
  assert.equal(r.stdout, hostile);
});

test("command construction: quoted hostile path behaves as data for stat/ls-shaped commands", () => {
  // Mirrors the src/index.ts call shapes: `stat ${shellQuote(p)}` and
  // `${lsCommand} ${shellQuote(p)}`. Uses a file whose NAME contains shell
  // metacharacters and asserts the built command addresses it literally.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-ssh-sq-cmd-"));
  const evilName = "a'b`c$(d) e";
  const evilPath = path.join(dir, evilName);
  fs.writeFileSync(evilPath, "x");
  try {
    const r = spawnSync("sh", ["-c", `ls -l ${shellQuote(evilPath)}`], {
      encoding: "utf8",
    });
    assert.equal(r.status, 0, r.stderr);
    assert.ok(
      r.stdout.includes(evilName),
      "ls did not resolve the literal name",
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("isValidEnvVarName accepts POSIX identifiers only", () => {
  assert.equal(isValidEnvVarName("PATH"), true);
  assert.equal(isValidEnvVarName("_x9"), true);
  assert.equal(isValidEnvVarName("NODE_ENV"), true);
  assert.equal(isValidEnvVarName(""), false);
  assert.equal(isValidEnvVarName("1ABC"), false);
  assert.equal(isValidEnvVarName("A-B"), false);
  assert.equal(isValidEnvVarName("PATH;rm -rf /"), false);
  assert.equal(isValidEnvVarName("$(id)"), false);
  assert.equal(isValidEnvVarName("A B"), false);
});
