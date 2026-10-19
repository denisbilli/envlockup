import assert from "node:assert/strict";
import { test } from "node:test";
import { parseEntries, splitLines } from "../dist/dotenv.js";
import { generateAgeIdentity, parseIdentity, parseRecipient, recipientKey } from "../dist/keys.js";
import { NotARecipientError, RecipientListError, SealedEnv } from "../dist/vault.js";
import { sshKey, tempDir } from "./helpers.js";

const dir = tempDir();
const alice = sshKey(dir, "alice");
const bob = sshKey(dir, "bob");
const aliceId = parseIdentity(alice.private, alice.path);
const bobId = parseIdentity(bob.private, bob.path);

const PLAIN = `# app settings
export DATABASE_URL=postgres://u:p@localhost/db
API_KEY="abc 123" # inline comment
PORT=3000
MULTI="line one
line two"
`;

function sealed(text = PLAIN) {
  const env = new SealedEnv(text);
  env.init([parseRecipient(alice.public)]);
  return new SealedEnv(env.toString());
}

test("dotenv parsing", () => {
  const values = Object.fromEntries(parseEntries(splitLines(PLAIN)).map((e) => [e.name, e.value]));
  assert.deepEqual(values, {
    DATABASE_URL: "postgres://u:p@localhost/db",
    API_KEY: "abc 123",
    PORT: "3000",
    MULTI: "line one\nline two",
  });
});

test("init encrypts every value and keeps comments", () => {
  const env = sealed();
  const text = env.toString();
  assert.match(text, /^#envlockup:v1 /);
  assert.match(text, /# app settings/);
  assert.doesNotMatch(text, /postgres|abc 123|3000|line one/);
  assert.match(text, /^export DATABASE_URL=envlockup:v1:/m);
  assert.ok(env.entries().every((e) => e.encrypted));
  env.unlock(aliceId);
  assert.equal(env.get("MULTI"), "line one\nline two");
  assert.equal(env.get("API_KEY"), "abc 123");
});

test("keep-plain and set --plain", () => {
  const env = new SealedEnv("PORT=3000\n");
  env.init([parseRecipient(alice.public)], { keepPlain: true });
  env.set("SECRET", "s3cret");
  env.set("GREETING", "it's me", { plain: true });
  const reread = new SealedEnv(env.toString());
  assert.match(reread.toString(), /^PORT=3000$/m);
  assert.match(reread.toString(), /^GREETING="it's me"$/m);
  assert.throws(() => reread.decryptAll(), /locked/);
  reread.unlock(aliceId);
  assert.deepEqual(reread.decryptAll(), { PORT: "3000", SECRET: "s3cret", GREETING: "it's me" });
});

test("a non-recipient cannot unlock", () => {
  assert.throws(() => sealed().unlock(bobId), NotARecipientError);
});

test("add and remove recipients; remove rotates the data key", () => {
  const env = sealed();
  env.unlock(aliceId);
  env.addRecipient(parseRecipient(bob.public));
  const shared = env.toString();
  const forBob = new SealedEnv(shared);
  forBob.unlock(bobId);
  assert.equal(forBob.get("PORT"), "3000");

  forBob.removeRecipients([parseRecipient(alice.public)]);
  const after = forBob.toString();
  assert.throws(() => new SealedEnv(after).unlock(aliceId), NotARecipientError);
  const check = new SealedEnv(after);
  check.unlock(bobId);
  assert.equal(check.get("API_KEY"), "abc 123");
  // Every ciphertext changed with the new data key.
  const before = new Set(new SealedEnv(shared).entries().map((e) => e.value));
  assert.ok(check.entries().every((e) => !before.has(e.value)));
});

test("ciphertexts are bound to their variable name", () => {
  const text = sealed().toString();
  const port = text.match(/^PORT=(.*)$/m)[1];
  const swapped = text.replace(/^API_KEY=.*$/m, `API_KEY=${port}`);
  assert.throws(() => new SealedEnv(swapped).unlock(aliceId), /API_KEY: cannot decrypt/);
});

test("tampered values are rejected", () => {
  const text = sealed().toString().replace(/^(PORT=envlockup:v1:.{30})(.)/m, (_, a, c) => a + (c === "A" ? "B" : "A"));
  assert.throws(() => new SealedEnv(text).unlock(aliceId), /PORT: cannot decrypt/);
});

test("age identities work as recipients (CI keys)", () => {
  const env = sealed();
  env.unlock(aliceId);
  const ci = generateAgeIdentity();
  ci.recipient.label = "ci";
  env.addRecipient(ci.recipient);
  const other = new SealedEnv(env.toString());
  assert.match(env.toString(), /^#envlockup:recipient X25519 age1\S+ \S+ \S+ ci$/m);
  other.unlock(parseIdentity(ci.secret, "ci"));
  assert.equal(other.get("PORT"), "3000");
});

test("set replaces in place and keeps export", () => {
  const env = sealed();
  env.unlock(aliceId);
  env.set("DATABASE_URL", "postgres://new");
  env.set("NEW_ONE", "x");
  const lines = env.toString().split("\n");
  assert.equal(lines.filter((l) => l.includes("DATABASE_URL")).length, 1);
  assert.ok(lines.some((l) => l.startsWith("export DATABASE_URL=envlockup:v1:")));
  assert.equal(lines.at(-2).startsWith("NEW_ONE="), true);
  assert.equal(env.get("DATABASE_URL"), "postgres://new");
});

test("a broken recipient line for someone else doesn't lock you out", () => {
  const env = sealed();
  env.unlock(aliceId);
  const ci1 = generateAgeIdentity();
  const ci2 = generateAgeIdentity();
  env.addRecipient(ci1.recipient);
  env.addRecipient(ci2.recipient);
  // Give ci1's line (checked before ci2's) a low-order, all-zero ephemeral share.
  const lines = env.toString().split("\n");
  const ci1Line = lines.findIndex((l) => l.startsWith("#envlockup:recipient X25519"));
  const parts = lines[ci1Line].split(" ");
  parts[3] = Buffer.alloc(32).toString("base64").replace(/=+$/, "");
  lines[ci1Line] = parts.join(" ");
  const other = new SealedEnv(lines.join("\n"));
  // The edit is detected; once the list is accepted, ci2 still gets in.
  assert.throws(() => other.unlock(parseIdentity(ci2.secret, "ci2")), RecipientListError);
  other.unlock(parseIdentity(ci2.secret, "ci2"), { trustRecipients: true });
  assert.equal(other.get("PORT"), "3000");
});

test("add leaves existing recipient lines untouched", () => {
  const env = sealed();
  env.unlock(aliceId);
  const before = env.toString().split("\n").filter((l) => l.startsWith("#envlockup:recipient"));
  env.addRecipient(parseRecipient(bob.public));
  const after = env.toString().split("\n").filter((l) => l.startsWith("#envlockup:recipient"));
  assert.deepEqual(after.slice(0, -1), before);
  assert.equal(after.length, before.length + 1);
});

test("a recipient line added without the key is detected, and gains no access on add", () => {
  const env = sealed();
  const mallory = generateAgeIdentity();
  const zeros = Buffer.alloc(32).toString("base64").replace(/=+$/, "");
  const forged = `#envlockup:recipient X25519 ${recipientKey(mallory.recipient)} ${zeros} ${zeros}${zeros.slice(0, 21)} ci`;
  const text = env.toString().replace(/^(#envlockup:recipient .*)$/m, `$1\n${forged}`);
  const victim = new SealedEnv(text);
  assert.throws(() => victim.unlock(aliceId), RecipientListError);
  // Even someone who accepts the list without looking doesn't hand over the key.
  victim.unlock(aliceId, { trustRecipients: true });
  victim.addRecipient(parseRecipient(bob.public));
  assert.throws(() => new SealedEnv(victim.toString()).unlock(parseIdentity(mallory.secret, "m")), NotARecipientError);
});

test("a forged stanza placed first is detected, and does not hide the real one", () => {
  const env = sealed();
  // A stanza for alice's public key, wrapping some other data key.
  const decoy = new SealedEnv("X=1\n");
  decoy.init([parseRecipient(alice.public)]);
  const forged = decoy.toString().split("\n")[1];
  const text = env.toString().replace(/^(#envlockup:v1.*)$/m, `$1\n${forged}`);
  const victim = new SealedEnv(text);
  assert.throws(() => victim.unlock(aliceId), RecipientListError);
  victim.unlock(aliceId, { trustRecipients: true });
  assert.equal(victim.get("PORT"), "3000");
});

test("set removes earlier definitions of the same name", () => {
  const env = new SealedEnv("API_KEY=old-plaintext\nOTHER=1\nAPI_KEY=older\n");
  env.init([parseRecipient(alice.public)], { keepPlain: true });
  env.set("API_KEY", "new");
  const text = env.toString();
  assert.doesNotMatch(text, /old-plaintext|older/);
  assert.equal(text.split("\n").filter((l) => l.startsWith("API_KEY=")).length, 1);
  assert.equal(env.get("API_KEY"), "new");
  assert.equal(env.get("OTHER"), "1");
});

test("control characters are dropped from labels", () => {
  const env = sealed();
  env.unlock(aliceId);
  const ci = generateAgeIdentity();
  ci.recipient.label = "ci\x1b[2K\x1b[1A";
  env.addRecipient(ci.recipient);
  assert.match(env.toString(), /^#envlockup:recipient X25519 age1\S+ \S+ \S+ ci\[2K\[1A$/m);
});

test("a plaintext definition after an encrypted one is refused", () => {
  const env = new SealedEnv(sealed().toString() + "API_KEY=attacker\n");
  assert.deepEqual(env.plaintextOverrides(), ["API_KEY"]);
  env.unlock(aliceId);
  assert.throws(() => env.decryptAll(), /API_KEY is encrypted, then set again in plaintext/);
  // Encrypting it would make the attacker's value look legitimate.
  assert.throws(() => env.encrypt(), /API_KEY is encrypted/);
  assert.throws(() => env.encrypt(["API_KEY"]), /API_KEY is encrypted/);
  // Revocation still works on such a file.
  env.addRecipient(parseRecipient(bob.public));
  env.removeRecipients([parseRecipient(bob.public)]);
  // set replaces every definition, which repairs the file.
  env.set("API_KEY", "real");
  assert.deepEqual(env.plaintextOverrides(), []);
  assert.equal(env.get("API_KEY"), "real");
});

test("a plaintext definition before an encrypted one is fine", () => {
  const env = sealed();
  env.unlock(aliceId);
  const text = "API_KEY=old\n" + env.toString();
  const reread = new SealedEnv(text);
  reread.unlock(aliceId);
  assert.equal(reread.get("API_KEY"), "abc 123");
});

test("remove re-encrypts every definition with its own value", () => {
  const env = new SealedEnv("DUP=first\nDUP=second\n");
  env.init([parseRecipient(alice.public), parseRecipient(bob.public)]);
  env.removeRecipients([parseRecipient(bob.public)]);
  const reread = new SealedEnv(env.toString());
  reread.unlock(aliceId);
  assert.equal(reread.get("DUP"), "second");
  reread.unset("DUP");
  assert.equal(reread.get("DUP"), undefined);
});

test("the recipient list is signed, and changes made with the key keep it signed", () => {
  const env = sealed();
  assert.match(env.toString(), /^#envlockup:recipient .*\n#envlockup:mac [\w-]{43}$/m);
  env.unlock(aliceId);
  assert.equal(env.recipientsVerified, true);
  env.addRecipient(parseRecipient(bob.public));
  const added = new SealedEnv(env.toString());
  added.unlock(bobId);
  added.removeRecipients([parseRecipient(alice.public)]);
  const removed = new SealedEnv(added.toString());
  removed.unlock(bobId);
  assert.equal(removed.recipientsVerified, true);
  assert.equal(removed.toString().split("\n").filter((l) => l.startsWith("#envlockup:mac ")).length, 1);
});

test("a missing or edited mac line is detected, and accepting the list signs it again", () => {
  const env = sealed();
  const text = env.toString();
  for (const bad of [text.replace(/^#envlockup:mac .*\n/m, ""), text.replace(/^(#envlockup:mac .*)(.)$/m, (_, start, last) => start + (last === "A" ? "B" : "A"))]) {
    const e = new SealedEnv(bad);
    assert.throws(() => e.unlock(aliceId), (err) => err instanceof RecipientListError && err.missing === !/#envlockup:mac/.test(bad));
    e.unlock(aliceId, { trustRecipients: true });
    assert.equal(e.recipientsVerified, false);
    e.acceptRecipients();
    const fixed = new SealedEnv(e.toString());
    fixed.unlock(aliceId);
    assert.equal(fixed.get("PORT"), "3000");
  }
  assert.throws(() => new SealedEnv(text.replace(/^(#envlockup:mac .*)$/m, "$1\n$1")), /more than one #envlockup:mac line/);
});
