import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { agentSocket } from "./agent.js";
import { SECRET_ENV_VARS, defaultIdentity, explicitIdentity, loadIdentity } from "./identity.js";
import { type Identity, recipientKey, x25519Identity } from "./keys.js";
import { SealedEnv } from "./vault.js";

export { SealedEnv, NotARecipientError, LockedError, isEncryptedValue } from "./vault.js";
export { parseRecipient, parseIdentity, generateAgeIdentity, fingerprint, recipientKey } from "./keys.js";
export type { Recipient, Identity } from "./keys.js";

export interface ConfigOptions {
  /** Path of the file to load. Default: `ENVSEAL_FILE` or `.env` in the current directory. */
  path?: string;
  /** Overwrite variables that are already set. Default: false, as in dotenv. */
  override?: boolean;
  /** Where to write the variables. Default: `process.env`. */
  processEnv?: Record<string, string | undefined>;
  /** Private key text to use instead of the default lookup. */
  privateKey?: string;
  /** Passphrase for a protected SSH key. Default: `ENVSEAL_SSH_PASSPHRASE`. */
  passphrase?: string;
}

export interface ConfigResult {
  parsed: Record<string, string>;
  error?: Error;
}

/**
 * Decrypt a file and return its variables, without touching `process.env`.
 * The private key is only needed when the file contains encrypted values.
 */
export function load(options: Omit<ConfigOptions, "override" | "processEnv"> = {}): Record<string, string> {
  const path = resolve(options.path ?? process.env.ENVSEAL_FILE ?? ".env");
  const env = new SealedEnv(readFileSync(path, "utf8"));
  if (env.entries().some((e) => e.encrypted)) {
    const explicit = options.privateKey ? { text: options.privateKey, source: "privateKey option" } : explicitIdentity();
    let agentError: Error | undefined;
    if (!explicit) {
      try {
        const identity = agentIdentitySync(env);
        if (identity) {
          env.unlock(identity);
          return env.decryptAll();
        }
      } catch (err) {
        agentError = err as Error;
      }
    }
    const src = explicit ?? defaultIdentity();
    if (!src) {
      throw new Error(
        agentError
          ? `${path}: ${agentError.message}`
          : `${path} contains encrypted values but no private key was found. Use ~/.ssh/id_ed25519 or ssh-agent, or set ENVSEAL_PRIVATE_KEY or ENVSEAL_IDENTITY.`,
      );
    }
    env.unlock(loadIdentity(src, options.passphrase));
  }
  return env.decryptAll();
}

/** Ask ssh-agent for an identity, synchronously, via a short-lived child process. */
function agentIdentitySync(env: SealedEnv): Identity | null {
  const agentRecipients = env.recipients.filter((r) => r.recipient.type === "ssh-agent").map((r) => recipientKey(r.recipient));
  if (agentRecipients.length === 0 || !agentSocket()) return null;
  const helper = fileURLToPath(new URL("./agent-helper.js", import.meta.url));
  let out: string;
  try {
    out = execFileSync(process.execPath, [helper], { input: JSON.stringify(agentRecipients), encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });
  } catch (err) {
    const stderr = (err as { stderr?: string }).stderr?.trim();
    throw new Error(stderr || (err as Error).message);
  }
  const found = JSON.parse(out) as { secret?: string; wire?: string; comment?: string };
  if (!found.secret || !found.wire) return null;
  return x25519Identity(Buffer.from(found.secret, "hex"), found.comment ?? "", Buffer.from(found.wire, "base64"));
}

/**
 * Drop-in replacement for `dotenv.config()`: loads the file into `process.env`.
 * A missing file is reported in `error`, like dotenv; a file that cannot be
 * decrypted throws, because silently starting without secrets is worse.
 */
export function config(options: ConfigOptions = {}): ConfigResult {
  const path = resolve(options.path ?? process.env.ENVSEAL_FILE ?? ".env");
  if (!existsSync(path)) return { parsed: {}, error: new Error(`envseal: ${path} not found`) };
  const parsed = load({ ...options, path });
  const target = options.processEnv ?? process.env;
  for (const [name, value] of Object.entries(parsed)) {
    if (options.override || target[name] === undefined) target[name] = value;
  }
  // The key has done its job; don't leave it around for the rest of the app.
  for (const name of SECRET_ENV_VARS) delete process.env[name];
  return { parsed };
}
