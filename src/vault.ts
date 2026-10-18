// An envseal file is a normal .env file with a few extra comment lines:
//
//   #envseal:v1 ...
//   #envseal:recipient <type> <public key> <stanza args...> <wrapped key> [label]
//   API_KEY=envseal:v1:<base64url>
//   PORT=3000
//
// A random 32-byte data key encrypts every value. Each recipient line holds
// that data key wrapped for one public key, using the age stanza format. Each
// value is encrypted with its own key derived from the data key and a random
// salt, and is bound to its variable name, so values cannot be swapped around.

import { hkdf, open, randomBytes, seal } from "./crypto.js";
import { type Entry, formatValue, parseEntries, splitLines } from "./dotenv.js";
import {
  type Identity,
  type Recipient,
  type Stanza,
  decodeBase64,
  encodeBase64,
  fingerprint,
  parseRecipient,
  recipientKey,
  sameRecipient,
  wrap,
} from "./keys.js";

const HEADER = "#envseal:";
const VERSION_LINE = "#envseal:v1";
const RECIPIENT_LINE = "#envseal:recipient ";
const VALUE_PREFIX = "envseal:v1:";
const VALUE_INFO = "envseal.org/v1/value";

export const HEADER_COMMENT =
  "#envseal:v1 This file is encrypted with envseal and safe to commit. Edit it with `npx envseal set NAME`.";

export interface RecipientEntry {
  recipient: Recipient;
  stanza: Stanza;
}

export class NotARecipientError extends Error {
  constructor(public readonly identity: Recipient) {
    super(`this file is not encrypted for your key (${fingerprint(identity)}). Ask someone who can open it to run \`envseal add\` with your public key.`);
  }
}

export class LockedError extends Error {
  constructor() {
    super("the file is locked: an identity is needed to read or write encrypted values");
  }
}

export function isEncryptedValue(value: string): boolean {
  return value.startsWith(VALUE_PREFIX);
}

function valueAad(name: string): Buffer {
  return Buffer.from(`${VALUE_PREFIX}${name}`, "utf8");
}

function encryptValue(dataKey: Buffer, name: string, value: string): string {
  const salt = randomBytes(16);
  const key = hkdf(dataKey, salt, VALUE_INFO, 32);
  const ct = seal(key, Buffer.from(value, "utf8"), valueAad(name));
  return VALUE_PREFIX + Buffer.concat([salt, ct]).toString("base64url");
}

function decryptValue(dataKey: Buffer, name: string, value: string): string {
  const raw = Buffer.from(value.slice(VALUE_PREFIX.length), "base64url");
  if (raw.length < 32) throw new Error(`${name}: malformed encrypted value`);
  const key = hkdf(dataKey, raw.subarray(0, 16), VALUE_INFO, 32);
  try {
    return open(key, raw.subarray(16), valueAad(name)).toString("utf8");
  } catch {
    throw new Error(
      `${name}: cannot decrypt (the value was changed, or moved from another variable). Set it again with \`envseal set ${name}\`.`,
    );
  }
}

// Per recipient type: how many tokens the public key takes, and the stanza it uses.
const LINE_LAYOUT = {
  "ssh-ed25519": { keyTokens: 1, stanza: "ssh-ed25519", args: 2 },
  X25519: { keyTokens: 1, stanza: "X25519", args: 1 },
  "ssh-agent": { keyTokens: 3, stanza: "X25519", args: 1 },
} as const;

function parseRecipientLine(line: string): RecipientEntry {
  const parts = line.slice(RECIPIENT_LINE.length).trim().split(/\s+/);
  const type = parts[0] as keyof typeof LINE_LAYOUT;
  const layout = Object.hasOwn(LINE_LAYOUT, type) ? LINE_LAYOUT[type] : undefined;
  if (!layout || parts.length < 2 + layout.keyTokens + layout.args) throw new Error(`malformed envseal recipient line: ${line}`);
  const keyEnd = 1 + layout.keyTokens;
  const stanzaEnd = keyEnd + layout.args;
  const keyTokens = parts.slice(1, keyEnd).join(" ");
  const label = parts.slice(stanzaEnd + 1).join(" ");
  const recipient = parseRecipient(type === "X25519" ? keyTokens : `${type} ${keyTokens}`, label);
  if (recipient.type !== type) throw new Error(`malformed envseal recipient line: ${line}`);
  return {
    recipient,
    stanza: { type: layout.stanza, args: parts.slice(keyEnd, stanzaEnd), body: decodeBase64(parts[stanzaEnd]!) },
  };
}

function formatRecipientLine({ recipient, stanza }: RecipientEntry): string {
  const key = recipientKey(recipient);
  const parts = [recipient.type === "X25519" ? `X25519 ${key}` : key, ...stanza.args, encodeBase64(stanza.body)];
  if (recipient.label) parts.push(recipient.label.replace(/\s+/g, " "));
  return RECIPIENT_LINE + parts.join(" ");
}

export class SealedEnv {
  private lines: string[];
  private dataKey: Buffer | null = null;
  recipients: RecipientEntry[] = [];
  readonly sealed: boolean;

  constructor(text = "") {
    this.lines = splitLines(text);
    this.sealed = this.lines.some((l) => l === VERSION_LINE || l.startsWith(VERSION_LINE + " "));
    for (const line of this.lines) {
      if (line.startsWith(RECIPIENT_LINE)) this.recipients.push(parseRecipientLine(line));
      else if (line.startsWith(HEADER) && !line.startsWith(VERSION_LINE)) {
        throw new Error(`unsupported envseal header line (is your envseal up to date?): ${line}`);
      }
    }
    if (this.sealed && this.recipients.length === 0) throw new Error("envseal file has no recipients");
  }

  get unlocked(): boolean {
    return this.dataKey !== null;
  }

  entries(): (Entry & { encrypted: boolean })[] {
    return parseEntries(this.lines).map((e) => ({ ...e, encrypted: isEncryptedValue(e.value) }));
  }

  /** Recover the data key with `identity` and check that every value decrypts. */
  unlock(identity: Identity): void {
    for (const { stanza } of this.recipients) {
      const key = identity.unwrap(stanza);
      if (key) {
        if (key.length !== 32) throw new Error("malformed data key");
        this.dataKey = key;
        this.decryptAll();
        return;
      }
    }
    throw new NotARecipientError(identity.recipient);
  }

  /** All variables, decrypted. Later definitions win, as in dotenv. */
  decryptAll(): Record<string, string> {
    const out: Record<string, string> = {};
    for (const e of this.entries()) {
      out[e.name] = e.encrypted ? decryptValue(this.requireKey(), e.name, e.value) : e.value;
    }
    return out;
  }

  get(name: string): string | undefined {
    return this.decryptAll()[name];
  }

  /** Initialize a new envseal file for `recipients`, encrypting existing values unless `keepPlain`. */
  init(recipients: Recipient[], { keepPlain = false } = {}): string[] {
    if (this.sealed) throw new Error("this file already uses envseal");
    if (recipients.length === 0) throw new Error("at least one recipient is required");
    this.dataKey = randomBytes(32);
    this.setRecipients(recipients);
    return keepPlain ? [] : this.encrypt();
  }

  set(name: string, value: string, { plain = false } = {}): void {
    if (!/^[\w.-]+$/.test(name)) throw new Error(`invalid variable name: ${name}`);
    const raw = plain ? formatValue(value) : encryptValue(this.requireKey(), name, value);
    const existing = this.entries().filter((e) => e.name === name).pop();
    if (existing) {
      const exported = /^\s*export\s/.test(this.lines[existing.start]!) ? "export " : "";
      this.lines.splice(existing.start, existing.end - existing.start + 1, `${exported}${name}=${raw}`);
    } else {
      this.lines.push(`${name}=${raw}`);
    }
  }

  unset(name: string): boolean {
    const matches = this.entries().filter((e) => e.name === name);
    for (const e of matches.reverse()) this.lines.splice(e.start, e.end - e.start + 1);
    return matches.length > 0;
  }

  /** Encrypt plaintext values (all of them, or only `names`). Returns the names encrypted. */
  encrypt(names?: string[]): string[] {
    const key = this.requireKey();
    const done: string[] = [];
    const missing = new Set(names);
    for (const e of this.entries().reverse()) {
      missing.delete(e.name);
      if (e.encrypted || (names && !names.includes(e.name))) continue;
      const exported = /^\s*export\s/.test(this.lines[e.start]!) ? "export " : "";
      this.lines.splice(e.start, e.end - e.start + 1, `${exported}${e.name}=${encryptValue(key, e.name, e.value)}`);
      done.unshift(e.name);
    }
    if (missing.size) throw new Error(`no such variable: ${[...missing].join(", ")}`);
    return done;
  }

  addRecipient(recipient: Recipient): void {
    if (this.recipients.some((r) => sameRecipient(r.recipient, recipient))) {
      throw new Error(`already a recipient: ${fingerprint(recipient)}`);
    }
    this.setRecipients([...this.recipients.map((r) => r.recipient), recipient]);
  }

  /**
   * Remove recipients and rotate the data key, re-encrypting every value.
   * People removed can still read any value they saw before: rotate those secrets too.
   */
  removeRecipients(toRemove: Recipient[]): void {
    const remaining = this.recipients.map((r) => r.recipient).filter((r) => !toRemove.some((x) => sameRecipient(x, r)));
    if (remaining.length === this.recipients.length) throw new Error("no such recipient");
    if (remaining.length === 0) throw new Error("cannot remove the last recipient");
    const values = this.decryptAll();
    const encrypted = this.entries().filter((e) => e.encrypted);
    this.dataKey = randomBytes(32);
    for (const e of encrypted.reverse()) {
      const exported = /^\s*export\s/.test(this.lines[e.start]!) ? "export " : "";
      this.lines.splice(e.start, e.end - e.start + 1, `${exported}${e.name}=${encryptValue(this.dataKey, e.name, values[e.name]!)}`);
    }
    this.setRecipients(remaining);
  }

  toString(): string {
    return this.lines.join("\n") + "\n";
  }

  private setRecipients(recipients: Recipient[]): void {
    const key = this.requireKey();
    this.recipients = recipients.map((recipient) => ({ recipient, stanza: wrap(recipient, key) }));
    const body = this.lines.filter((l) => !l.startsWith(HEADER));
    const versionLine = this.lines.find((l) => l.startsWith(VERSION_LINE)) ?? HEADER_COMMENT;
    this.lines = [versionLine, ...this.recipients.map(formatRecipientLine), ...body];
    (this as { sealed: boolean }).sealed = true;
  }

  private requireKey(): Buffer {
    if (!this.dataKey) throw new LockedError();
    return this.dataKey;
  }
}
