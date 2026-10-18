// envseal's key wrapping must be exactly age's. These tests use the real
// `age` CLI in both directions: age wraps / envseal unwraps, and vice versa.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { generateAgeIdentity, identityRecipient, parseIdentity, parseRecipient, recipientKey, wrap } from "../dist/keys.js";
import { buildAgeFile, headerMac, parseAgeHeader, sshKey, tempDir } from "./helpers.js";

const hasAge = (() => {
  try {
    execFileSync("age", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
})();
const skip = hasAge ? false : "the age CLI is not installed";
const dir = tempDir();
const plaintext = Buffer.from("hello from the interop test\n");

function ageEncrypt(args) {
  return execFileSync("age", ["-e", ...args], { input: plaintext });
}

function assertUnwraps(identity, ageFile) {
  const { stanzas, mac, macInput } = parseAgeHeader(ageFile);
  const keys = stanzas.map((s) => identity.unwrap(s)).filter(Boolean);
  assert.equal(keys.length, 1, "exactly one stanza should unwrap");
  assert.deepEqual(headerMac(keys[0], macInput), mac, "file key must verify the header MAC");
}

test("age -R ssh-ed25519 → envseal unwraps", { skip }, () => {
  const key = sshKey(dir, "a");
  assertUnwraps(parseIdentity(key.private, key.path), ageEncrypt(["-R", `${key.path}.pub`]));
});

test("envseal wraps ssh-ed25519 → age -d decrypts", { skip }, () => {
  const key = sshKey(dir, "b");
  const fileKey = randomBytes(16);
  const file = join(dir, "b.age");
  writeFileSync(file, buildAgeFile(fileKey, [wrap(parseRecipient(key.public), fileKey)], plaintext));
  assert.deepEqual(execFileSync("age", ["-d", "-i", key.path, file]), plaintext);
});

test("only the right ssh key unwraps", { skip }, () => {
  const alice = sshKey(dir, "alice");
  const bob = sshKey(dir, "bob");
  const file = ageEncrypt(["-R", `${alice.path}.pub`]);
  const { stanzas } = parseAgeHeader(file);
  assert.equal(parseIdentity(bob.private, bob.path).unwrap(stanzas[0]), null);
});

test("passphrase-protected ssh key", { skip }, () => {
  const key = sshKey(dir, "locked", "correct horse");
  assert.throws(() => parseIdentity(key.private, key.path), /passphrase/);
  assert.throws(() => parseIdentity(key.private, key.path, "wrong"), /wrong passphrase/);
  assert.equal(recipientKey(identityRecipient(key.private, key.path)), recipientKey(parseRecipient(key.public)));
  assertUnwraps(parseIdentity(key.private, key.path, "correct horse"), ageEncrypt(["-R", `${key.path}.pub`]));
});

test("age-keygen identity: same recipient, unwraps age -r", { skip }, () => {
  const keyFile = join(dir, "age.txt");
  execFileSync("age-keygen", ["-o", keyFile], { stdio: "ignore" });
  const recipient = execFileSync("age-keygen", ["-y", keyFile]).toString().trim();
  const identity = parseIdentity(readFileSync(keyFile, "utf8"), keyFile);
  assert.equal(recipientKey(identity.recipient), recipient);
  assertUnwraps(identity, ageEncrypt(["-r", recipient]));
});

test("envseal age identity → age -d decrypts", { skip }, () => {
  const { secret, recipient } = generateAgeIdentity();
  const keyFile = join(dir, "gen.txt");
  writeFileSync(keyFile, secret + "\n");
  const fileKey = randomBytes(16);
  const file = join(dir, "gen.age");
  writeFileSync(file, buildAgeFile(fileKey, [wrap(recipient, fileKey)], plaintext));
  assert.deepEqual(execFileSync("age", ["-d", "-i", keyFile, file]), plaintext);
  assert.equal(execFileSync("age-keygen", ["-y", keyFile]).toString().trim(), recipientKey(recipient));
});
