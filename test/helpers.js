import { execFileSync } from "node:child_process";
import { createCipheriv, createHmac, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hkdf } from "../dist/crypto.js";

export function tempDir() {
  return mkdtempSync(join(tmpdir(), "envseal-test-"));
}

/** Generate an ed25519 SSH key with ssh-keygen. */
export function sshKey(dir, name = "id_ed25519", passphrase = "") {
  const path = join(dir, name);
  execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", passphrase, "-C", `${name}@test`, "-f", path]);
  return { path, private: readFileSync(path, "utf8"), public: readFileSync(`${path}.pub`, "utf8").trim() };
}

const b64 = (b) => Buffer.from(b).toString("base64").replace(/=+$/, "");

/** Parse the header of an age file: stanzas, the MAC and the bytes it covers. */
export function parseAgeHeader(file) {
  const text = file.toString("latin1");
  const end = text.indexOf("\n---");
  const lines = text.slice(0, end).split("\n");
  if (lines[0] !== "age-encryption.org/v1") throw new Error("not an age file");
  const stanzas = [];
  for (let i = 1; i < lines.length; i++) {
    const [, type, ...args] = lines[i].split(" ");
    let body = "";
    for (;;) {
      const l = lines[++i];
      body += l;
      if (l.length < 64) break;
    }
    stanzas.push({ type, args, body: Buffer.from(body, "base64") });
  }
  const macLineEnd = text.indexOf("\n", end + 1);
  const mac = Buffer.from(text.slice(end + 5, macLineEnd), "base64");
  return { stanzas, mac, macInput: file.subarray(0, end + 4) };
}

export function headerMac(fileKey, macInput) {
  return createHmac("sha256", hkdf(fileKey, Buffer.alloc(0), "header", 32)).update(macInput).digest();
}

/** Build a complete single-chunk age file from stanzas made by envseal. */
export function buildAgeFile(fileKey, stanzas, plaintext) {
  let header = "age-encryption.org/v1\n";
  for (const s of stanzas) {
    header += `-> ${s.type} ${s.args.join(" ")}\n`;
    const body = b64(s.body);
    for (let i = 0; i <= body.length; i += 64) header += body.slice(i, i + 64) + "\n";
  }
  header += "---";
  const mac = headerMac(fileKey, Buffer.from(header));
  const nonce = randomBytes(16);
  const payloadKey = hkdf(fileKey, nonce, "payload", 32);
  const chunkNonce = Buffer.alloc(12);
  chunkNonce[11] = 1; // counter 0, last chunk
  const c = createCipheriv("chacha20-poly1305", payloadKey, chunkNonce, { authTagLength: 16 });
  const ct = Buffer.concat([c.update(plaintext), c.final(), c.getAuthTag()]);
  return Buffer.concat([Buffer.from(`${header} ${b64(mac)}\n`), nonce, ct]);
}
