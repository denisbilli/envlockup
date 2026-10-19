// envlockup must read every file exactly as dotenv does, and write plain values
// that dotenv reads back unchanged.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import dotenv from "dotenv";
import { formatValue, parseEntries, splitLines } from "../dist/dotenv.js";

const ours = (text) => {
  const out = {};
  for (const e of parseEntries(splitLines(text))) out[e.name] = e.value;
  return out;
};

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
  "X=\"crlf\"\r\nY=next",
  "Z=a\rZZ=old-mac line ending",
  "EMPTY=\nNEXT='quoted on next line'",
  "DUP=first\nDUP=second",
];

for (const text of CASES) {
  test(`parses like dotenv: ${JSON.stringify(text)}`, () => {
    assert.deepEqual(ours(text), { ...dotenv.parse(text) });
  });
}

test("formatValue round-trips through dotenv", () => {
  const samples = [
    "", "simple", "with space", " padded ", "a#b", "quote'single", 'quote"double', "both ' and \"",
    "back`tick", "new\nline", "literal \\n backslash-n", "it's \"all\" `here`".replace("`here`", "here"),
    "tab\there", "cr\r\nlf", "cr\r'single", "unicode ✓ àèì", "$VAR ${VAR}", "=equals=", "trailing\\",
  ];
  for (let i = 0; i < 300; i++) {
    const alphabet = "ab #'\"`\\\n\r=$ ";
    samples.push(Array.from(randomBytes(8), (b) => alphabet[b % alphabet.length]).join(""));
  }
  for (const value of samples) {
    let line;
    try {
      line = `K=${formatValue(value)}`;
    } catch {
      continue; // not representable as a plain value: stored encrypted instead
    }
    assert.equal(dotenv.parse(line).K, value, `dotenv misreads ${JSON.stringify(line)}`);
    assert.equal(ours(line).K, value, `envlockup misreads ${JSON.stringify(line)}`);
  }
});
