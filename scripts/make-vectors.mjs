// Generate test/vectors.json: test vectors shared by every envseal
// implementation (the Python package reads them in python/tests).
//
//   npm run build && node scripts/make-vectors.mjs
//
// The output is random (keys, salts), so it is committed rather than rebuilt in
// CI; test/vectors.test.js checks that it still matches this implementation.
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import dotenv from "dotenv";
import { SealedEnv, generateAgeIdentity, parseRecipient, recipientKey } from "../dist/index.js";
import { parseEntries, splitLines } from "../dist/dotenv.js";

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
    throw new Error(`envseal and dotenv disagree on ${JSON.stringify(text)}`);
  }
  parse.push({ text, expected });
}

// --- Keys -------------------------------------------------------------------------

const dir = mkdtempSync(join(tmpdir(), "envseal-vectors-"));
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

const plainOnly = "# no envseal header\nA=1\nB='two'\n";
files.push({ name: "plain dotenv file, no key needed", text: plainOnly, expected: ours(plainOnly), keys: [] });

// --- Errors ------------------------------------------------------------------------

const lines = sealed.split("\n");
const valueOf = (name) => lines.find((l) => l.startsWith(`${name}=`)).slice(name.length + 1);
const replaceLine = (name, value) => lines.map((l) => (l.startsWith(`${name}=`) ? `${name}=${value}` : l)).join("\n");
const tampered = valueOf("SPACES").slice(0, -2) + (valueOf("SPACES").endsWith("A") ? "BB" : "AA");
const header = lines.filter((l) => l.startsWith("#envseal:"));

const errors = [
  { name: "key that is not a recipient", text: sealed, key: "outsider_age", error: "not_a_recipient" },
  { name: "ssh key that is not a recipient", text: sealed, key: "outsider_ssh", error: "not_a_recipient" },
  { name: "value moved to another variable", text: replaceLine("SPACES", valueOf("UNICODE")), key: "age", error: "decrypt" },
  { name: "tampered value", text: replaceLine("SPACES", tampered), key: "age", error: "decrypt" },
  { name: "truncated value", text: replaceLine("SPACES", "envseal:v1:AAAA"), key: "age", error: "decrypt" },
  { name: "unknown header line", text: sealed.replace("#envseal:recipient", "#envseal:future x\n#envseal:recipient"), key: "age", error: "format" },
  { name: "newer format version", text: sealed.replace("#envseal:v1 ", "#envseal:v10 "), key: "age", error: "format" },
  { name: "malformed recipient line", text: `${sealed}#envseal:recipient X25519 age1notakey AAAA AAAA\n`, key: "age", error: "format" },
  { name: "recipient line with too few fields", text: `${sealed}#envseal:recipient ssh-ed25519 AAAA\n`, key: "age", error: "format" },
  { name: "unknown recipient type", text: `${sealed}#envseal:recipient ssh-rsa AAAA AAAA AAAA AAAA\n`, key: "age", error: "format" },
  { name: "plaintext definition after an encrypted one", text: `${sealed}SPACES=attacker\n`, key: "age", error: "format" },
  { name: "header without recipients", text: [header[0], ...lines.filter((l) => !l.startsWith("#envseal:"))].join("\n"), key: "age", error: "format" },
];

writeFileSync(
  out,
  JSON.stringify(
    {
      comment: "Generated by scripts/make-vectors.mjs. Shared by every envseal implementation; do not edit by hand.",
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
