// Where the private key comes from, in order:
//
//   1. ENVLOCKUP_PRIVATE_KEY  the key itself (CI: store it as a single secret)
//   2. ENVLOCKUP_IDENTITY     path to a key file
//   3. ssh-agent            if the file has an ssh-agent recipient the agent holds
//   4. ~/.ssh/id_ed25519    your SSH key
//
// 1 and 2 (and the CLI's -i) are "explicit": when set, nothing else is tried.
//
// A passphrase-protected SSH key is unlocked with ENVLOCKUP_SSH_PASSPHRASE, or
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

export const SECRET_ENV_VARS = ["ENVLOCKUP_PRIVATE_KEY", "ENVLOCKUP_SSH_PASSPHRASE"];

export function defaultKeyPath(): string {
  return join(homedir(), ".ssh", "id_ed25519");
}

/** The "no private key" message, with the advice that fits the keys this user has. */
export function noKeyMessage(agentRunning: boolean): string {
  const ssh = join(homedir(), ".ssh");
  const agentHint = agentRunning
    ? " If your key lives only in ssh-agent (a password manager's SSH agent, for example), run `npx envlockup pubkey --agent` and send the line it prints to someone who can open the file."
    : "";
  if (existsSync(join(ssh, "id_rsa"))) {
    return (
      `no usable private key: ${join(ssh, "id_rsa")} is an RSA key file, which envlockup can't use directly. ` +
      "Load it in ssh-agent (`ssh-add`) and run `npx envlockup pubkey --agent`, or create an Ed25519 key with `ssh-keygen -t ed25519`."
    );
  }
  if (existsSync(join(ssh, "id_ecdsa"))) {
    return `no usable private key: ${join(ssh, "id_ecdsa")} is an ECDSA key, which can't be used. Create an Ed25519 key with \`ssh-keygen -t ed25519\`.${agentHint}`;
  }
  return `no private key found. Create one with \`ssh-keygen -t ed25519\`, or set ENVLOCKUP_PRIVATE_KEY or ENVLOCKUP_IDENTITY.${agentHint}`;
}

export function explicitIdentity(env: Env = process.env, path?: string): IdentitySource | null {
  if (path) return { text: readFileSync(path, "utf8"), source: path, path };
  const inline = env.ENVLOCKUP_PRIVATE_KEY?.trim();
  if (inline) {
    // CI systems often flatten multi-line secrets; accept literal "\n".
    const text = inline.includes("\n") ? inline : inline.replace(/\\n/g, "\n");
    return { text, source: "ENVLOCKUP_PRIVATE_KEY" };
  }
  const file = env.ENVLOCKUP_IDENTITY;
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
  return parseIdentity(src.text, src.source, passphrase ?? env.ENVLOCKUP_SSH_PASSPHRASE);
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
