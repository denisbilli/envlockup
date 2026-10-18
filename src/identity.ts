// Where the private key comes from, in order:
//
//   1. ENVSEAL_PRIVATE_KEY  the key itself (CI: store it as a single secret)
//   2. ENVSEAL_IDENTITY     path to a key file
//   3. ssh-agent            if the file has an ssh-agent recipient the agent holds
//   4. ~/.ssh/id_ed25519    your SSH key
//
// 1 and 2 (and the CLI's -i) are "explicit": when set, nothing else is tried.
//
// A passphrase-protected SSH key is unlocked with ENVSEAL_SSH_PASSPHRASE, or
// interactively by the CLI.

import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { type Identity, type Recipient, identityRecipient, parseIdentity, parseRecipient } from "./keys.js";

export interface IdentitySource {
  text: string;
  /** Human-readable origin, used in error messages. */
  source: string;
  path?: string;
}

type Env = Record<string, string | undefined>;

export const SECRET_ENV_VARS = ["ENVSEAL_PRIVATE_KEY", "ENVSEAL_SSH_PASSPHRASE"];

export function defaultKeyPath(): string {
  return join(homedir(), ".ssh", "id_ed25519");
}

export function explicitIdentity(env: Env = process.env, path?: string): IdentitySource | null {
  if (path) return { text: readFileSync(path, "utf8"), source: path, path };
  const inline = env.ENVSEAL_PRIVATE_KEY?.trim();
  if (inline) {
    // CI systems often flatten multi-line secrets; accept literal "\n".
    const text = inline.includes("\n") ? inline : inline.replace(/\\n/g, "\n");
    return { text, source: "ENVSEAL_PRIVATE_KEY" };
  }
  const file = env.ENVSEAL_IDENTITY;
  if (file) return { text: readFileSync(file, "utf8"), source: file, path: file };
  return null;
}

export function defaultIdentity(): IdentitySource | null {
  const file = defaultKeyPath();
  return existsSync(file) ? { text: readFileSync(file, "utf8"), source: file, path: file } : null;
}

export function findIdentity(env: Env = process.env, path?: string): IdentitySource | null {
  return explicitIdentity(env, path) ?? defaultIdentity();
}

export function loadIdentity(src: IdentitySource, passphrase?: string, env: Env = process.env): Identity {
  return parseIdentity(src.text, src.source, passphrase ?? env.ENVSEAL_SSH_PASSPHRASE);
}

/** The public key matching an identity source, labelled from its .pub file when possible. */
export function publicRecipient(src: IdentitySource): Recipient {
  const recipient = identityRecipient(src.text, src.source);
  if (!recipient.label && src.path && existsSync(`${src.path}.pub`)) {
    try {
      const pub = parseRecipient(readFileSync(`${src.path}.pub`, "utf8"));
      if (pub.type === recipient.type && pub.label) recipient.label = pub.label;
    } catch {
      // The .pub file is only a source of labels; ignore anything odd in it.
    }
  }
  return recipient;
}
