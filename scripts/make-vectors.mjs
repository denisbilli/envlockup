// Generate test/vectors.json: test vectors shared by every envlockup
// implementation (the Python package reads them in python/tests).
//
//   npm run build && node scripts/make-vectors.mjs
//
// The output is random (keys, salts), so it is committed rather than rebuilt in
// CI; test/vectors.test.js checks that it still matches this implementation.
import { execFileSync } from "node:child_process";
import { createHmac, hkdfSync, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import dotenv from "dotenv";
import { SealedEnv, generateAgeIdentity, parseIdentity, parseRecipient, recipientKey } from "../dist/index.js";
import { parseEntries, splitLines } from "../dist/dotenv.js";
import { isEd25519Point } from "../dist/crypto.js";

const out = new URL("../test/vectors.json", import.meta.url);

// --- Parsing --------------------------------------------------------------------

const CASES = [
  "A=plain",
  "export B=exported",
  'C="double quoted"',
  "D='single quoted'",
  "E=`backtick`",
  "F=value#nocomment",
  "G=value # comment",
  'H="a\\"b"',
  'I="back\\\\slash"',
  'J="line1\\nline2\\r"',
  "K='no \\n escapes here'",
  'L="unterminated\nM=next line',
  "N='multi\nline'",
  'O="multi\nline with \' quote"',
  "P=",
  "Q = spaced = value",
  "R:colon syntax",
  "S.DOT-DASH=x",
  "1START=digit",
  "  T=  leading spaces  ",
  "U='# not a comment'",
  'V="${OTHER}/path"',
  "# just a comment\nW=after comment",
  'X="crlf"\r\nY=next',
  "Z=a\rZZ=old-mac line ending",
  "EMPTY=\nNEXT='quoted on next line'",
  "DUP=first\nDUP=second",
  "﻿BOM=first line",
  "NBSP= padded ",
  "LS=a B=after line separator",
  "PS='a b'",
  "FS=\x1cnot js space\x1c",
  "NEL=a\x85b",
  "UNI=àèìòù ✓ 😀",
  "ÀCCENT=key is not ascii",
  "QUOTES='a'\n'b'",
  "MIXED='a\n\"b\"",
  "TAB=\tvalue\t",
  "export  SPACES=two spaces after export",
  "exportX=not export",
  "COMMENT=x # c\u2028NEXT=after a comment and a line separator",
  "COMMENT2=x # c\u2029NEXT2=after a comment and a paragraph separator",
];

const ours = (text) => {
  const obj = {};
  for (const e of parseEntries(splitLines(text))) obj[e.name] = e.value;
  return obj;
};

// Random lines built from the characters the dotenv grammar cares about.
const ALPHABET = ["A", "b", "_", ".", "-", "=", ":", " ", "\t", "#", "'", '"', "`", "\\", "n", "r", "\n", "\r", "$", "{", "}",
  "export ", " ", " ", "﻿", "\x0b", "\x1c", "\x85", "é", "😀"];
function randomText() {
  const n = 1 + (randomBytes(1)[0] % 24);
  return Array.from(randomBytes(n), (b) => ALPHABET[b % ALPHABET.length]).join("");
}

const parse = [];
for (const text of [...CASES, ...Array.from({ length: 400 }, randomText)]) {
  const expected = { ...dotenv.parse(text) };
  const got = ours(text);
  if (JSON.stringify(Object.entries(got).sort()) !== JSON.stringify(Object.entries(expected).sort())) {
    throw new Error(`envlockup and dotenv disagree on ${JSON.stringify(text)}`);
  }
  parse.push({ text, expected });
}

// --- Keys -------------------------------------------------------------------------

const dir = mkdtempSync(join(tmpdir(), "envlockup-vectors-"));
function sshKey(name, passphrase = "") {
  const path = join(dir, name);
  execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", passphrase, "-C", `${name}@vectors`, "-f", path]);
  return { private: readFileSync(path, "utf8"), public: readFileSync(`${path}.pub`, "utf8").trim() };
}
function ageKey() {
  const { secret, recipient } = generateAgeIdentity();
  return { private: secret, public: recipientKey(recipient) };
}

const keys = {
  ssh: sshKey("ssh"),
  ssh_passphrase: { ...sshKey("ssh_passphrase", "correct horse"), passphrase: "correct horse" },
  age: ageKey(),
  // Stands in for an ssh-agent key: the agent derives an X25519 secret, which
  // is all the file needs. The SSH key on the line only names the agent key.
  agent: { ...ageKey(), agent_ssh_key: sshKey("agent").public },
  outsider_ssh: sshKey("outsider_ssh"),
  outsider_age: ageKey(),
};
rmSync(dir, { recursive: true, force: true });

// --- Files -------------------------------------------------------------------------

const PLAIN = [
  "# A comment stays as it is",
  "DATABASE_URL=postgres://user:p@ss@db:5432/app",
  "export EXPORTED=exported value",
  "EMPTY=",
  "SPACES='  padded  '",
  'MULTILINE="line 1\\nline 2"',
  "UNICODE='àèìòù ✓ 😀'",
  "QUOTES=`it's \"quoted\"`",
  "HASH='a # b'",
  "DUP=first",
  "DUP=second",
].join("\n");

const recipients = [
  parseRecipient(keys.ssh.public),
  parseRecipient(keys.ssh_passphrase.public),
  parseRecipient(keys.age.public, "ci"),
  parseRecipient(`ssh-agent ${keys.agent.public} ${keys.agent.agent_ssh_key}`),
];
const env = new SealedEnv(PLAIN);
env.init(recipients);
env.set("PLAIN_PORT", "8000", { plain: true });
const sealed = env.toString();
const expected = env.decryptAll();

const files = [{ name: "every recipient type", text: sealed, expected, keys: ["ssh", "ssh_passphrase", "age", "agent"] }];

const plainOnly = "# no envlockup header\nA=1\nB='two'\n";
files.push({ name: "plain dotenv file, no key needed", text: plainOnly, expected: ours(plainOnly), keys: [] });

// --- Errors ------------------------------------------------------------------------

const lines = sealed.split("\n");
const valueOf = (name) => lines.find((l) => l.startsWith(`${name}=`)).slice(name.length + 1);
const replaceLine = (name, value) => lines.map((l) => (l.startsWith(`${name}=`) ? `${name}=${value}` : l)).join("\n");
const tampered = valueOf("SPACES").slice(0, -2) + (valueOf("SPACES").endsWith("A") ? "BB" : "AA");
const header = lines.filter((l) => l.startsWith("#envlockup:"));
const macLine = lines.find((l) => l.startsWith("#envlockup:mac "));
const lastRecipient = lines.findLastIndex((l) => l.startsWith("#envlockup:recipient "));
// A real recipient line for the outsider, as the CLI would write it, inserted
// without updating the #envlockup:mac line: what someone without the key can do.
const withOutsider = new SealedEnv(sealed);
withOutsider.unlock(parseIdentity(keys.age.private, "age"));
withOutsider.addRecipient(parseRecipient(keys.outsider_age.public, "outsider"));
const outsiderLine = withOutsider.toString().split("\n").find((l) => l.endsWith(" outsider"));
const insertAfterRecipients = (line) => [...lines.slice(0, lastRecipient + 1), line, ...lines.slice(lastRecipient + 1)].join("\n");
const agentLine = lines.find((l) => l.startsWith("#envlockup:recipient ssh-agent "));

// Base64 that decodes to the same bytes but isn't the canonical encoding: the
// unused low bits of the last character are set.
function nonCanonical(encoded, alphabet) {
  const unused = { 2: 4, 3: 2 }[encoded.length % 4];
  if (!unused) return null;
  const last = alphabet.indexOf(encoded.at(-1));
  return encoded.slice(0, -1) + alphabet[last | 1];
}
const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const valueName = ["SPACES", "UNICODE", "QUOTES", "HASH", "DATABASE_URL", "MULTILINE"].find((n) =>
  nonCanonical(valueOf(n).slice("envlockup:v1:".length), B64URL),
);
const loose = "envlockup:v1:" + nonCanonical(valueOf(valueName).slice("envlockup:v1:".length), B64URL);
const withJunk = valueOf("SPACES").slice(0, 20) + "!*" + valueOf("SPACES").slice(20);

// An ssh-ed25519 recipient whose key is not a point on the curve.
const sshLine = lines.find((l) => l.startsWith("#envlockup:recipient ssh-ed25519 "));
let offCurve = Buffer.alloc(32);
for (let y = 2; isEd25519Point(offCurve); y++) offCurve = Buffer.from(y.toString(16).padStart(64, "0"), "hex").reverse();
const sshString = (b) => Buffer.concat([Buffer.from([0, 0, 0, b.length]), b]);
const offCurveWire = Buffer.concat([sshString(Buffer.from("ssh-ed25519")), sshString(offCurve)]).toString("base64").replace(/=+$/, "");
const offCurveLine = sshLine.replace(/^(#envlockup:recipient ssh-ed25519 )\S+/, `$1${offCurveWire}`);

// Re-sign a modified recipient list, from the spec in DESIGN.md, so that only the
// check a vector is about can catch it.
const dataKey = parseIdentity(keys.age.private, "age").unwrap(new SealedEnv(sealed).recipients.find((r) => r.recipient.type === "X25519").stanza);
function resign(fileLines) {
  const key = Buffer.from(hkdfSync("sha256", dataKey, Buffer.alloc(0), "github.com/denisbilli/envlockup/v1/recipients", 32));
  const mac = createHmac("sha256", key);
  for (const l of fileLines.filter((l) => l.startsWith("#envlockup:recipient "))) {
    const bytes = Buffer.from(l, "utf8");
    mac.update(Buffer.from([bytes.length >>> 24, (bytes.length >>> 16) & 255, (bytes.length >>> 8) & 255, bytes.length & 255]));
    mac.update(bytes);
  }
  const signed = `#envlockup:mac ${mac.digest("base64url")}`;
  return fileLines.map((l) => (l.startsWith("#envlockup:mac ") ? signed : l)).join("\n");
}
if (resign(lines) !== sealed) throw new Error("resign() does not reproduce the file's #envlockup:mac line");


const errors = [
  { name: "key that is not a recipient", text: sealed, key: "outsider_age", error: "not_a_recipient" },
  { name: "ssh key that is not a recipient", text: sealed, key: "outsider_ssh", error: "not_a_recipient" },
  { name: "value moved to another variable", text: replaceLine("SPACES", valueOf("UNICODE")), key: "age", error: "decrypt" },
  { name: "tampered value", text: replaceLine("SPACES", tampered), key: "age", error: "decrypt" },
  { name: "truncated value", text: replaceLine("SPACES", "envlockup:v1:AAAA"), key: "age", error: "decrypt" },
  { name: "unknown header line", text: sealed.replace("#envlockup:recipient", "#envlockup:future x\n#envlockup:recipient"), key: "age", error: "format" },
  { name: "newer format version", text: sealed.replace("#envlockup:v1 ", "#envlockup:v10 "), key: "age", error: "format" },
  { name: "malformed recipient line", text: `${sealed}#envlockup:recipient X25519 age1notakey AAAA AAAA\n`, key: "age", error: "format" },
  { name: "recipient line with too few fields", text: `${sealed}#envlockup:recipient ssh-ed25519 AAAA\n`, key: "age", error: "format" },
  { name: "unknown recipient type", text: `${sealed}#envlockup:recipient ssh-rsa AAAA AAAA AAAA AAAA\n`, key: "age", error: "format" },
  { name: "plaintext definition after an encrypted one", text: `${sealed}SPACES=attacker\n`, key: "age", error: "format" },
  { name: "recipient line added without the key", text: insertAfterRecipients(outsiderLine), key: "age", error: "recipients" },
  { name: "recipient line removed without the key", text: lines.filter((l) => l !== agentLine).join("\n"), key: "age", error: "recipients" },
  { name: "recipient label edited", text: lines.map((l) => (l.endsWith(" ci") ? `${l.slice(0, -3)} cj` : l)).join("\n"), key: "age", error: "recipients" },
  { name: "recipient lines reordered", text: [lines[0], lines[2], lines[1], ...lines.slice(3)].join("\n"), key: "age", error: "recipients" },
  { name: "mac line missing", text: lines.filter((l) => l !== macLine).join("\n"), key: "age", error: "recipients" },
  { name: "two mac lines", text: insertAfterRecipients(macLine), key: "age", error: "format" },
  { name: "value with characters outside base64url", text: replaceLine("SPACES", withJunk), key: "age", error: "decrypt" },
  { name: "value in non-canonical base64url", text: replaceLine(valueName, loose), key: "age", error: "decrypt" },
  { name: "ssh-ed25519 recipient that is not a curve point", text: resign(lines.map((l) => (l === sshLine ? offCurveLine : l))), key: "age", error: "format" },
  { name: "header without recipients", text: [header[0], ...lines.filter((l) => !l.startsWith("#envlockup:"))].join("\n"), key: "age", error: "format" },
];

writeFileSync(
  out,
  JSON.stringify(
    {
      comment: "Generated by scripts/make-vectors.mjs. Shared by every envlockup implementation; do not edit by hand.",
      parse,
      keys,
      files,
      errors,
    },
    null,
    2,
  ) + "\n",
);
console.log(`wrote ${parse.length} parse cases, ${files.length} files, ${errors.length} error cases to test/vectors.json`);
