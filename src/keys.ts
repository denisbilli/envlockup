// Recipients (public keys a file is encrypted to) and identities (private keys
// that can decrypt it):
//
//   ssh-ed25519  your existing SSH key (~/.ssh/id_ed25519), as in age
//   X25519       a native age key (AGE-SECRET-KEY-1...), handy for CI
//   ssh-agent    an X25519 key derived from a signature made by ssh-agent
//                (see agent.ts); the SSH key only tells us which agent key to use

import { createDecipheriv } from "node:crypto";
import bcrypt from "bcrypt-pbkdf";
import * as bech32 from "./bech32.js";
import {
  SSH_ED25519_LABEL,
  X25519_LABEL,
  ed25519PublicToX25519,
  ed25519SeedToX25519,
  hkdf,
  isEd25519Point,
  open,
  randomBytes,
  seal,
  sha256,
  x25519,
  x25519Base,
} from "./crypto.js";

export type Recipient =
  | { type: "ssh-ed25519"; wire: Buffer; label: string }
  | { type: "X25519"; publicKey: Buffer; label: string }
  | { type: "ssh-agent"; wire: Buffer; publicKey: Buffer; label: string };

export interface Stanza {
  type: "ssh-ed25519" | "X25519";
  args: string[];
  body: Buffer;
}

export interface Identity {
  recipient: Recipient;
  unwrap(stanza: Stanza): Buffer | null;
}

export class PassphraseRequiredError extends Error {
  constructor(public readonly source: string) {
    super(`the SSH key ${source} is protected by a passphrase`);
  }
}

const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64").replace(/=+$/, "");
/** Strict unpadded base64: only the canonical encoding of the bytes is accepted. */
const unb64 = (s: string) => {
  if (!/^[A-Za-z0-9+/]*$/.test(s)) throw new Error("invalid base64");
  const bytes = Buffer.from(s, "base64");
  if (b64(bytes) !== s) throw new Error("invalid base64");
  return bytes;
};

// --- SSH wire format ------------------------------------------------------------

class Reader {
  private pos = 0;
  constructor(private readonly buf: Buffer) {}
  u32(): number {
    if (this.pos + 4 > this.buf.length) throw new Error("truncated SSH key");
    const v = this.buf.readUInt32BE(this.pos);
    this.pos += 4;
    return v;
  }
  bytes(n: number): Buffer {
    if (this.pos + n > this.buf.length) throw new Error("truncated SSH key");
    const v = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return v;
  }
  string(): Buffer {
    return this.bytes(this.u32());
  }
  get done() {
    return this.pos === this.buf.length;
  }
}

function sshString(data: Uint8Array): Buffer {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  return Buffer.concat([len, data]);
}

function ed25519Wire(publicKey: Uint8Array): Buffer {
  return Buffer.concat([sshString(Buffer.from("ssh-ed25519")), sshString(publicKey)]);
}

/** The key type of an SSH public key in wire format, e.g. "ssh-ed25519". */
export function sshKeyType(wire: Buffer): string {
  return new Reader(wire).string().toString();
}

export function parseSSHPublicKey(text: string): { wire: Buffer; comment: string } {
  const parts = text.trim().split(/\s+/);
  if (!parts[0] || !parts[1]) throw new Error("invalid SSH public key");
  const wire = unb64(parts[1].replace(/=+$/, ""));
  if (sshKeyType(wire) !== parts[0]) throw new Error("invalid SSH public key");
  return { wire, comment: parts.slice(2).join(" ") };
}

function ed25519FromWire(wire: Buffer): Buffer {
  const r = new Reader(wire);
  const type = r.string().toString();
  if (type !== "ssh-ed25519") throw new Error(`unsupported SSH key type ${type} (only ssh-ed25519 is supported)`);
  const key = r.string();
  if (key.length !== 32 || !r.done) throw new Error("malformed ssh-ed25519 key");
  if (!isEd25519Point(key)) throw new Error("malformed ssh-ed25519 key (not a point on the curve)");
  return key;
}

// --- Recipients -------------------------------------------------------------------

function decodeAgeRecipient(s: string): Buffer {
  const { hrp, data } = bech32.decode(s);
  if (hrp !== "age" || data.length !== 32) throw new Error("invalid age recipient");
  return data;
}

/** Parse `ssh-ed25519 AAAA... [comment]`, `age1...` or `ssh-agent age1... <ssh key> [comment]`. */
export function parseRecipient(text: string, label?: string): Recipient {
  const parts = text.trim().split(/\s+/);
  if (parts[0] === "ssh-agent" && parts[1] && parts[2] && parts[3]) {
    const publicKey = decodeAgeRecipient(parts[1]);
    const { wire } = parseSSHPublicKey(`${parts[2]} ${parts[3]}`);
    return { type: "ssh-agent", wire, publicKey, label: label ?? parts.slice(4).join(" ") };
  }
  if (parts[0] === "ssh-ed25519" && parts[1]) {
    const wire = unb64(parts[1].replace(/=+$/, ""));
    ed25519FromWire(wire);
    return { type: "ssh-ed25519", wire, label: label ?? parts.slice(2).join(" ") };
  }
  if (parts[0]?.startsWith("age1")) {
    return { type: "X25519", publicKey: decodeAgeRecipient(parts[0]), label: label ?? parts.slice(1).join(" ") };
  }
  if (parts[0]?.startsWith("sk-")) throw new Error("FIDO (sk-) SSH keys cannot decrypt; use a regular ssh-ed25519 key");
  throw new Error(`unsupported recipient "${parts[0] ?? ""}" (expected ssh-ed25519 or age1...)`);
}

/** The public key in the form `parseRecipient` accepts, without the label. */
export function recipientKey(r: Recipient): string {
  switch (r.type) {
    case "ssh-ed25519":
      return `ssh-ed25519 ${r.wire.toString("base64")}`;
    case "X25519":
      return bech32.encode("age", r.publicKey);
    case "ssh-agent":
      return `ssh-agent ${bech32.encode("age", r.publicKey)} ${sshKeyType(r.wire)} ${r.wire.toString("base64")}`;
  }
}

/** Short, human-friendly fingerprint. For SSH keys it matches `ssh-keygen -l`. */
export function fingerprint(r: Recipient): string {
  const material = r.type === "X25519" ? r.publicKey : r.wire;
  return `SHA256:${b64(sha256(material))}`;
}

export function sameRecipient(a: Recipient, b: Recipient): boolean {
  return recipientKey(a) === recipientKey(b);
}

export function wrap(r: Recipient, fileKey: Uint8Array): Stanza {
  const ephemeral = randomBytes(32);
  const share = x25519Base(ephemeral);
  if (r.type === "X25519" || r.type === "ssh-agent") {
    const shared = x25519(ephemeral, r.publicKey);
    const key = hkdf(shared, Buffer.concat([share, r.publicKey]), X25519_LABEL, 32);
    return { type: "X25519", args: [b64(share)], body: seal(key, fileKey) };
  }
  const theirs = ed25519PublicToX25519(ed25519FromWire(r.wire));
  const tweak = hkdf(Buffer.alloc(0), r.wire, SSH_ED25519_LABEL, 32);
  const shared = x25519(tweak, x25519(ephemeral, theirs));
  const key = hkdf(shared, Buffer.concat([share, theirs]), SSH_ED25519_LABEL, 32);
  const tag = b64(sha256(r.wire).subarray(0, 4));
  return { type: "ssh-ed25519", args: [tag, b64(share)], body: seal(key, fileKey) };
}

// --- Identities -------------------------------------------------------------------

export function x25519Identity(secret: Buffer, label: string, agentKey?: Buffer): Identity {
  const publicKey = x25519Base(secret);
  return {
    recipient: agentKey ? { type: "ssh-agent", wire: agentKey, publicKey, label } : { type: "X25519", publicKey, label },
    unwrap(stanza) {
      if (stanza.type !== "X25519" || stanza.args.length !== 1) return null;
      try {
        const share = unb64(stanza.args[0]!);
        const shared = x25519(secret, share);
        const key = hkdf(shared, Buffer.concat([share, publicKey]), X25519_LABEL, 32);
        return open(key, stanza.body);
      } catch {
        return null;
      }
    },
  };
}

function sshEd25519Identity(publicKey: Buffer, seed: Buffer, label: string): Identity {
  const wire = ed25519Wire(publicKey);
  const ours = ed25519PublicToX25519(publicKey);
  const secret = ed25519SeedToX25519(seed);
  if (!x25519Base(secret).equals(ours)) throw new Error("SSH private key does not match its public key");
  const tag = b64(sha256(wire).subarray(0, 4));
  return {
    recipient: { type: "ssh-ed25519", wire, label },
    unwrap(stanza) {
      if (stanza.type !== "ssh-ed25519" || stanza.args.length !== 2 || stanza.args[0] !== tag) return null;
      try {
        const share = unb64(stanza.args[1]!);
        const tweak = hkdf(Buffer.alloc(0), wire, SSH_ED25519_LABEL, 32);
        const shared = x25519(tweak, x25519(secret, share));
        const key = hkdf(shared, Buffer.concat([share, ours]), SSH_ED25519_LABEL, 32);
        return open(key, stanza.body);
      } catch {
        return null;
      }
    },
  };
}

/** Generate a native age identity. Returns the `AGE-SECRET-KEY-1...` string. */
export function generateAgeIdentity(): { secret: string; recipient: Recipient } {
  const secret = randomBytes(32);
  return {
    secret: bech32.encode("age-secret-key-", secret, true),
    recipient: { type: "X25519", publicKey: x25519Base(secret), label: "" },
  };
}

interface OpenSSHKey {
  publicKey: Buffer;
  comment: string;
  encrypted: boolean;
  decrypt(passphrase?: string): { seed: Buffer; comment: string };
}

function parseOpenSSH(pem: string, source: string): OpenSSHKey {
  const m = pem.match(/-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]*?)-----END OPENSSH PRIVATE KEY-----/);
  if (!m) throw new Error(`${source} is not an OpenSSH private key`);
  const raw = Buffer.from(m[1]!.replace(/\s+/g, ""), "base64");
  const magic = Buffer.from("openssh-key-v1\0");
  if (!raw.subarray(0, magic.length).equals(magic)) throw new Error(`${source} is not an OpenSSH private key`);
  const r = new Reader(raw.subarray(magic.length));
  const cipher = r.string().toString();
  const kdf = r.string().toString();
  const kdfOptions = r.string();
  if (r.u32() !== 1) throw new Error(`${source} contains more than one key`);
  const publicKey = ed25519FromWire(r.string());
  const sealed = r.string();
  const encrypted = cipher !== "none";
  if (encrypted && (cipher !== "aes256-ctr" || kdf !== "bcrypt")) {
    throw new Error(`${source} uses unsupported encryption ${cipher}/${kdf}`);
  }

  const decrypt = (passphrase?: string) => {
    let plain = sealed;
    if (encrypted) {
      if (!passphrase) throw new PassphraseRequiredError(source);
      const opts = new Reader(kdfOptions);
      const salt = opts.string();
      const rounds = opts.u32();
      const pass = Buffer.from(passphrase, "utf8");
      const derived = Buffer.alloc(48);
      bcrypt.pbkdf(pass, pass.length, salt, salt.length, derived, derived.length, rounds);
      const d = createDecipheriv("aes-256-ctr", derived.subarray(0, 32), derived.subarray(32));
      plain = Buffer.concat([d.update(sealed), d.final()]);
    }
    const p = new Reader(plain);
    if (p.u32() !== p.u32()) {
      throw new Error(encrypted ? `wrong passphrase for ${source}` : `${source} is corrupted`);
    }
    if (p.string().toString() !== "ssh-ed25519") throw new Error(`${source} is not an ssh-ed25519 key`);
    const pub = p.string();
    const priv = p.string();
    if (!pub.equals(publicKey) || priv.length !== 64) throw new Error(`${source} is corrupted`);
    return { seed: Buffer.from(priv.subarray(0, 32)), comment: p.string().toString() };
  };

  // The comment lives in the encrypted section; for unencrypted keys we can read it now.
  const comment = encrypted ? "" : decrypt().comment;
  return { publicKey, comment, encrypted, decrypt };
}

function findAgeSecret(text: string): string | null {
  const line = text.split(/\r?\n/).find((l) => l.trim().startsWith("AGE-SECRET-KEY-1"));
  return line ? line.trim() : null;
}

/**
 * Parse a private key: an OpenSSH ed25519 key file, or an age identity
 * (`AGE-SECRET-KEY-1...`, optionally inside an age-keygen file).
 */
export function parseIdentity(text: string, source: string, passphrase?: string): Identity {
  const age = findAgeSecret(text);
  if (age) {
    const { hrp, data } = bech32.decode(age);
    if (hrp !== "age-secret-key-" || data.length !== 32) throw new Error(`${source}: invalid age secret key`);
    return x25519Identity(data, "");
  }
  const key = parseOpenSSH(text, source);
  const { seed, comment } = key.decrypt(passphrase);
  return sshEd25519Identity(key.publicKey, seed, comment);
}

/** The public half of a private key, without needing its passphrase. */
export function identityRecipient(text: string, source: string): Recipient {
  const age = findAgeSecret(text);
  if (age) return parseIdentity(age, source).recipient;
  const key = parseOpenSSH(text, source);
  return { type: "ssh-ed25519", wire: ed25519Wire(key.publicKey), label: key.comment };
}

export function isEncryptedSSHKey(text: string, source: string): boolean {
  return !findAgeSecret(text) && parseOpenSSH(text, source).encrypted;
}

export const encodeBase64 = b64;
export const decodeBase64 = unb64;
