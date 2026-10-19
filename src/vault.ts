// An envlockup file is a normal .env file with a few extra comment lines:
//
//   #envlockup:v1 ...
//   #envlockup:recipient <type> <public key> <stanza args...> <wrapped key> [label]
//   API_KEY=envlockup:v1:<base64url>
//   PORT=3000
//
// A random 32-byte data key encrypts every value. Each recipient line holds
// that data key wrapped for one public key, using the age stanza format. Each
// value is encrypted with its own key derived from the data key and a random
// salt, and is bound to its variable name, so values cannot be swapped around.

import { timingSafeEqual } from "node:crypto";
import { hkdf, hmacSha256, open, randomBytes, seal } from "./crypto.js";
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

const HEADER = "#envlockup:";
const VERSION_LINE = "#envlockup:v1";
const RECIPIENT_LINE = "#envlockup:recipient ";
const MAC_LINE = "#envlockup:mac ";
const VALUE_PREFIX = "envlockup:v1:";
const VALUE_INFO = "github.com/denisbilli/envlockup/v1/value";
const RECIPIENTS_INFO = "github.com/denisbilli/envlockup/v1/recipients";

export const HEADER_COMMENT =
  "#envlockup:v1 This file is encrypted with envlockup and safe to commit. Edit it with `npx envlockup set NAME`.";

export interface RecipientEntry {
  recipient: Recipient;
  stanza: Stanza;
}

export class NotARecipientError extends Error {
  constructor(public readonly identity: Recipient) {
    super(`this file is not encrypted for your key (${fingerprint(identity)}). Ask someone who can open it to run \`envlockup add\` with your public key.`);
  }
}

/** The recipient lines are not the ones last signed by someone who could decrypt the file. */
export class RecipientListError extends Error {
  constructor(readonly missing = false) {
    super(
      (missing
        ? "the file has no #envlockup:mac line, so nobody can tell whether its recipient list was changed. "
        : "the recipient list was changed by someone who could not decrypt the file (a #envlockup:recipient line was added, removed or edited). ") +
        "Compare `envlockup recipients` with a version you trust; if every key is one you expect, run `envlockup recipients --accept`.",
    );
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

/**
 * HMAC over the recipient lines, exactly as they appear in the file, each one
 * prefixed with its length. Only someone with the data key can compute it.
 */
function recipientsMac(dataKey: Buffer, lines: string[]): string {
  const parts = lines.flatMap((line) => {
    const bytes = Buffer.from(line, "utf8");
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    return [length, bytes];
  });
  return hmacSha256(hkdf(dataKey, Buffer.alloc(0), RECIPIENTS_INFO, 32), ...parts).toString("base64url");
}

function plaintextOverrideError(name: string): Error {
  return new Error(
    `${name} is encrypted, then set again in plaintext further down the file. ` +
      "Anyone who can edit the file can add such a line, so it is not used. " +
      `Delete the line you don't want, or run \`envlockup set ${name}\`.`,
  );
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
  const encoded = value.slice(VALUE_PREFIX.length);
  const raw = Buffer.from(encoded, "base64url");
  // Strict: unpadded base64url in its canonical form only, as in every implementation.
  if (!/^[A-Za-z0-9_-]*$/.test(encoded) || raw.toString("base64url") !== encoded || raw.length < 32) {
    throw new Error(`${name}: malformed encrypted value`);
  }
  const key = hkdf(dataKey, raw.subarray(0, 16), VALUE_INFO, 32);
  try {
    return open(key, raw.subarray(16), valueAad(name)).toString("utf8");
  } catch {
    throw new Error(
      `${name}: cannot decrypt (the value was changed, or moved from another variable). Set it again with \`envlockup set ${name}\`.`,
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
  if (!layout || parts.length < 2 + layout.keyTokens + layout.args) throw new Error(`malformed envlockup recipient line: ${line}`);
  const keyEnd = 1 + layout.keyTokens;
  const stanzaEnd = keyEnd + layout.args;
  const keyTokens = parts.slice(1, keyEnd).join(" ");
  const label = parts.slice(stanzaEnd + 1).join(" ");
  const recipient = parseRecipient(type === "X25519" ? keyTokens : `${type} ${keyTokens}`, label);
  if (recipient.type !== type) throw new Error(`malformed envlockup recipient line: ${line}`);
  return {
    recipient,
    stanza: { type: layout.stanza, args: parts.slice(keyEnd, stanzaEnd), body: decodeBase64(parts[stanzaEnd]!) },
  };
}

function formatRecipientLine({ recipient, stanza }: RecipientEntry): string {
  const key = recipientKey(recipient);
  const parts = [recipient.type === "X25519" ? `X25519 ${key}` : key, ...stanza.args, encodeBase64(stanza.body)];
  // Labels are free text from .pub comments and --label: one line, no control characters.
  const label = recipient.label.replace(/\s+/g, " ").replace(/\p{Cc}/gu, "");
  if (label) parts.push(label);
  return RECIPIENT_LINE + parts.join(" ");
}

export class SealedEnv {
  private lines: string[];
  private dataKey: Buffer | null = null;
  recipients: RecipientEntry[] = [];
  readonly sealed: boolean;
  /** After `unlock`: whether the recipient lines match the #envlockup:mac line. */
  recipientsVerified = false;

  constructor(text = "") {
    this.lines = splitLines(text);
    const isVersionLine = (l: string) => l === VERSION_LINE || l.startsWith(VERSION_LINE + " ");
    this.sealed = this.lines.some(isVersionLine);
    for (const line of this.lines) {
      if (line.startsWith(RECIPIENT_LINE)) this.recipients.push(parseRecipientLine(line));
      else if (line.startsWith(HEADER) && !isVersionLine(line) && !line.startsWith(MAC_LINE)) {
        throw new Error(`unsupported envlockup header line (is your envlockup up to date?): ${line}`);
      }
    }
    if (this.sealed && this.recipients.length === 0) throw new Error("envlockup file has no recipients");
    if (this.lines.filter((l) => l.startsWith(MAC_LINE)).length > 1) throw new Error("envlockup file has more than one #envlockup:mac line");
  }

  get unlocked(): boolean {
    return this.dataKey !== null;
  }

  entries(): (Entry & { encrypted: boolean })[] {
    return parseEntries(this.lines).map((e) => ({ ...e, encrypted: isEncryptedValue(e.value) }));
  }

  /**
   * Recover the data key with `identity`, check that every value decrypts and
   * that the recipient list is the one last signed with the data key. With
   * `trustRecipients`, an unsigned list is accepted (see `acceptRecipients`).
   */
  unlock(identity: Identity, { trustRecipients = false } = {}): void {
    // Anyone can write a stanza for a public key, so a key that unwraps but does
    // not decrypt the values may be a forgery placed before the real stanza.
    let failure: Error | undefined;
    let listFailure: RecipientListError | undefined;
    for (const { stanza } of this.recipients) {
      const key = identity.unwrap(stanza);
      if (!key) continue;
      try {
        if (key.length !== 32) throw new Error("malformed data key");
        for (const e of this.entries()) if (e.encrypted) decryptValue(key, e.name, e.value);
        const verified = this.macMatches(key);
        if (!verified && !trustRecipients) {
          listFailure ??= new RecipientListError(!this.lines.some((l) => l.startsWith(MAC_LINE)));
          continue;
        }
        this.dataKey = key;
        this.recipientsVerified = verified;
        return;
      } catch (err) {
        failure ??= err as Error;
      }
    }
    throw listFailure ?? failure ?? new NotARecipientError(identity.recipient);
  }

  /** Sign the current recipient lines, after checking them (a merge, a hand edit). */
  acceptRecipients(): void {
    this.updateMac();
    this.recipientsVerified = true;
  }

  /**
   * All variables, decrypted. Later definitions win, as in dotenv, except that a
   * plaintext definition after an encrypted one is refused: it needs no key to write.
   */
  decryptAll(): Record<string, string> {
    const [name] = this.plaintextOverrides();
    if (name) throw plaintextOverrideError(name);
    const out: Record<string, string> = {};
    for (const e of this.entries()) {
      out[e.name] = e.encrypted ? decryptValue(this.requireKey(), e.name, e.value) : e.value;
    }
    return out;
  }

  /** Names defined in plaintext after an encrypted definition of the same name. */
  plaintextOverrides(): string[] {
    const encrypted = new Set<string>();
    const found = new Set<string>();
    for (const e of this.entries()) {
      if (e.encrypted) encrypted.add(e.name);
      else if (encrypted.has(e.name)) found.add(e.name);
    }
    return [...found];
  }

  get(name: string): string | undefined {
    return this.decryptAll()[name];
  }

  /** Initialize a new envlockup file for `recipients`, encrypting existing values unless `keepPlain`. */
  init(recipients: Recipient[], { keepPlain = false } = {}): string[] {
    if (this.sealed) throw new Error("this file already uses envlockup");
    if (recipients.length === 0) throw new Error("at least one recipient is required");
    this.dataKey = randomBytes(32);
    this.setRecipients(recipients);
    return keepPlain ? [] : this.encrypt();
  }

  set(name: string, value: string, { plain = false } = {}): void {
    if (!/^[\w.-]+$/.test(name)) throw new Error(`invalid variable name: ${name}`);
    if (plain && isEncryptedValue(value)) {
      throw new Error(`a plaintext value cannot start with "${VALUE_PREFIX}": it would be read as encrypted`);
    }
    const raw = plain ? formatValue(value) : encryptValue(this.requireKey(), name, value);
    const [last, ...earlier] = this.entries()
      .filter((e) => e.name === name)
      .reverse();
    if (last) {
      const exported = /^\s*export\s/.test(this.lines[last.start]!) ? "export " : "";
      this.lines.splice(last.start, last.end - last.start + 1, `${exported}${name}=${raw}`);
      // Earlier definitions are overridden anyway, but may still hold an old value in plaintext.
      for (const e of earlier) this.lines.splice(e.start, e.end - e.start + 1);
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
    // Encrypting such a value would turn an unauthenticated line into a trusted one.
    const override = this.plaintextOverrides().find((n) => !names || names.includes(n));
    if (override) throw plaintextOverrideError(override);
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

  /**
   * Wrap the data key for one more recipient. Existing recipient lines are left
   * byte for byte: re-wrapping them would change every line (noisy diffs, merge
   * conflicts), and would turn a line added by someone without the key into one
   * that works.
   */
  addRecipient(recipient: Recipient): void {
    if (this.recipients.some((r) => sameRecipient(r.recipient, recipient))) {
      throw new Error(`already a recipient: ${fingerprint(recipient)}`);
    }
    const entry = { recipient, stanza: wrap(recipient, this.requireKey()) };
    let after = -1;
    this.lines.forEach((l, i) => {
      if (l.startsWith(RECIPIENT_LINE)) after = i;
    });
    this.lines.splice(after + 1, 0, formatRecipientLine(entry));
    this.recipients.push(entry);
    this.updateMac();
  }

  /**
   * Remove recipients and rotate the data key, re-encrypting every value.
   * People removed can still read any value they saw before: rotate those secrets too.
   */
  removeRecipients(toRemove: Recipient[]): void {
    const remaining = this.recipients.map((r) => r.recipient).filter((r) => !toRemove.some((x) => sameRecipient(x, r)));
    if (remaining.length === this.recipients.length) throw new Error("no such recipient");
    if (remaining.length === 0) throw new Error("cannot remove the last recipient");
    const oldKey = this.requireKey();
    const encrypted = this.entries().filter((e) => e.encrypted);
    const values = encrypted.map((e) => decryptValue(oldKey, e.name, e.value));
    this.dataKey = randomBytes(32);
    for (const [i, e] of [...encrypted.entries()].reverse()) {
      const exported = /^\s*export\s/.test(this.lines[e.start]!) ? "export " : "";
      this.lines.splice(e.start, e.end - e.start + 1, `${exported}${e.name}=${encryptValue(this.dataKey, e.name, values[i]!)}`);
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
    const recipientLines = this.recipients.map(formatRecipientLine);
    this.lines = [versionLine, ...recipientLines, MAC_LINE + recipientsMac(key, recipientLines), ...body];
    (this as { sealed: boolean }).sealed = true;
    this.recipientsVerified = true;
  }

  private recipientLines(): string[] {
    return this.lines.filter((l) => l.startsWith(RECIPIENT_LINE));
  }

  private macMatches(key: Buffer): boolean {
    const line = this.lines.find((l) => l.startsWith(MAC_LINE));
    if (!line) return false;
    const expected = Buffer.from(recipientsMac(key, this.recipientLines()));
    const actual = Buffer.from(line.slice(MAC_LINE.length).trim());
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  }

  /** Rewrite the #envlockup:mac line, or add it after the last recipient line. */
  private updateMac(): void {
    const line = MAC_LINE + recipientsMac(this.requireKey(), this.recipientLines());
    const existing = this.lines.findIndex((l) => l.startsWith(MAC_LINE));
    if (existing >= 0) {
      this.lines[existing] = line;
      return;
    }
    let after = -1;
    this.lines.forEach((l, i) => {
      if (l.startsWith(RECIPIENT_LINE)) after = i;
    });
    this.lines.splice(after + 1, 0, line);
  }

  private requireKey(): Buffer {
    if (!this.dataKey) throw new LockedError();
    return this.dataKey;
  }
}
