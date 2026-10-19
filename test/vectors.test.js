// test/vectors.json is shared with the other envlockup implementations. These
// tests make sure it still describes what this one does.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { NotARecipientError, RecipientListError, SealedEnv, parseIdentity } from "../dist/index.js";
import { parseEntries, splitLines } from "../dist/dotenv.js";

const vectors = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8"));
const identity = (name) => {
  const key = vectors.keys[name];
  return parseIdentity(key.private, name, key.passphrase);
};

test("vectors: parsing", () => {
  for (const { text, expected } of vectors.parse) {
    const got = {};
    for (const e of parseEntries(splitLines(text))) got[e.name] = e.value;
    assert.deepEqual(got, expected, JSON.stringify(text));
  }
});

for (const file of vectors.files) {
  test(`vectors: ${file.name}`, () => {
    const env = new SealedEnv(file.text);
    if (file.keys.length === 0) assert.deepEqual(env.decryptAll(), file.expected);
    for (const name of file.keys) {
      const e = new SealedEnv(file.text);
      e.unlock(identity(name));
      assert.deepEqual(e.decryptAll(), file.expected, name);
    }
  });
}

for (const { name, text, key, error } of vectors.errors) {
  test(`vectors: ${name} fails (${error})`, () => {
    const attempt = () => {
      const env = new SealedEnv(text);
      env.unlock(identity(key));
      env.decryptAll();
    };
    if (error === "not_a_recipient") assert.throws(attempt, NotARecipientError);
    else if (error === "recipients") assert.throws(attempt, RecipientListError);
    else if (error === "decrypt") assert.throws(attempt, /cannot decrypt|malformed encrypted value/);
    else assert.throws(attempt, (err) => !(err instanceof NotARecipientError) && !/cannot decrypt/.test(err.message));
  });
}
