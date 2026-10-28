#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  closeSync,
  existsSync,
  fchmodSync,
  fchownSync,
  fsyncSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { basename, dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { AgentClient, agentIdentityFor, agentRecipient, agentSocket, selectAgentKey } from "./agent.js";
import { type IdentitySource, SECRET_ENV_VARS, explicitIdentity, findIdentity, loadIdentity, noKeyMessage, publicRecipient } from "./identity.js";
import {
  type Identity,
  PassphraseRequiredError,
  type Recipient,
  fingerprint,
  generateAgeIdentity,
  isEncryptedSSHKey,
  parseRecipient,
  recipientKey,
  sameRecipient,
} from "./keys.js";
import { formatValue } from "./dotenv.js";
import { NotARecipientError, SealedEnv } from "./vault.js";

const HELP = `envlockup — encrypted .env files you can commit

Usage: envlockup [-f FILE] [-i KEY] <command> [args]

Commands:
  init [--recipient KEY]... [--agent [--key K]] [--keep-plain]
                         Start using envlockup in FILE, encrypted for your SSH
                         key (or your ssh-agent key, or the given public keys).
                         Existing values get encrypted.
  set NAME [VALUE] [--plain]
                         Set a variable. Without VALUE it is read from stdin or
                         prompted for, so it doesn't end up in your shell history.
  get NAME               Print one decrypted value.
  unset NAME             Remove a variable.
  ls                     List variable names, marking which are encrypted.
  encrypt [NAME]...      Encrypt plaintext values (all, or the ones named).
  decrypt [--format json]
                         Print the whole file decrypted, in dotenv format
                         (or as a JSON object).
  run [--override] -- COMMAND [ARGS]...
                         Run COMMAND with the variables in its environment.
                         Nothing decrypted is written to disk.
  recipients [--accept [--yes]]
                         List who can decrypt the file. With --accept, sign
                         the list as it is now, after checking it: needed
                         after a merge or an edit made without the key.
  add KEY... [--label TEXT]
                         Give access to a public key: "ssh-ed25519 AAAA...",
                         a .pub file, an age1... key, an "ssh-agent ..." line
                         from \`envlockup pubkey --agent\`, or @github-user.
  add --agent [--key K]  Give access to your own ssh-agent key, so you can
                         decrypt without a key file or passphrase prompt.
  pubkey [--agent [--key K]]
                         Print your public key, to send to someone who will
                         \`envlockup add\` it. With --agent, your ssh-agent key.
  remove WHO... [--yes]  Revoke access (fingerprint, label or number from
                         \`recipients\`) and rotate the data key. Every
                         recipient matching WHO is removed. Asks before
                         changing anything, unless --yes.
  check [--allow-plain NAME,...] [--base REF]
                         Check the file before a commit or in CI: no plaintext
                         value that is new or was encrypted in git REF
                         (default HEAD) unless allowed, and, when a key is
                         available, every value decrypts. Exits 1 on problems.
  keygen [--label TEXT]  Create a dedicated key (e.g. for CI), add it as a
                         recipient and print the private key once.

Options:
  -f, --file FILE        File to use (default: $ENVLOCKUP_FILE or .env)
  -i, --identity KEY     Private key file (default: $ENVLOCKUP_PRIVATE_KEY,
                         $ENVLOCKUP_IDENTITY, ssh-agent, or ~/.ssh/id_ed25519)
  --key K                Which ssh-agent key: fingerprint or comment
  -h, --help             Show this help
  -v, --version          Show the version
`;

class UsageError extends Error {}

interface Args {
  command?: string;
  positional: string[];
  flags: Map<string, string[]>;
  rest: string[];
}

const VALUE_FLAGS = new Set(["file", "identity", "recipient", "label", "key", "format", "base", "allow-plain"]);
const ALIASES: Record<string, string> = { f: "file", i: "identity", h: "help", v: "version", y: "yes" };

function parseArgs(argv: string[]): Args {
  const args: Args = { positional: [], flags: new Map(), rest: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--") {
      args.rest = argv.slice(i + 1);
      break;
    }
    const m = a.match(/^--?([a-z-]+)(?:=(.*))?$/);
    if (m && a !== "-") {
      const name = ALIASES[m[1]!] ?? m[1]!;
      let value = m[2] ?? "";
      if (VALUE_FLAGS.has(name) && m[2] === undefined) {
        if (i + 1 >= argv.length) throw new UsageError(`--${name} needs a value`);
        value = argv[++i]!;
      }
      args.flags.set(name, [...(args.flags.get(name) ?? []), value]);
    } else if (!args.command) {
      args.command = a;
    } else {
      args.positional.push(a);
    }
  }
  return args;
}

const out = (s: string) => process.stdout.write(s + "\n");
const info = (s: string) => process.stderr.write(s + "\n");

/** Escape control characters (except newlines) in text that may come from the file. */
function printable(s: string): string {
  return s.replace(/[^\P{Cc}\n]/gu, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`);
}

function describe(r: Recipient): string {
  return printable(`${fingerprint(r)}  ${r.type === "X25519" ? "age" : r.type}${r.label ? `  ${r.label}` : ""}`);
}

function agentClient(): AgentClient {
  const socket = agentSocket();
  if (!socket) throw new Error("no ssh-agent found: SSH_AUTH_SOCK is not set");
  return new AgentClient(socket);
}

async function promptHidden(question: string): Promise<string> {
  const stdin = process.stdin;
  if (!stdin.isTTY) throw new Error("cannot prompt: stdin is not a terminal");
  process.stderr.write(question);
  stdin.setRawMode(true);
  stdin.resume();
  stdin.setEncoding("utf8");
  return new Promise((resolvePrompt, reject) => {
    let buf = "";
    const done = (err?: Error) => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.off("data", onData);
      process.stderr.write("\n");
      if (err) reject(err);
      else resolvePrompt(buf);
    };
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n") return done();
        if (ch === "\u0003" || ch === "\u0004") return done(new Error("cancelled"));
        if (ch === "\u007f" || ch === "\b") buf = buf.slice(0, -1);
        else buf += ch;
      }
    };
    stdin.on("data", onData);
  });
}

async function promptLine(question: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    return await rl.question(question);
  } finally {
    rl.close();
  }
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/, "");
}

/** Ask before a change the user should check first; --yes skips the question. */
async function confirm(args: Args): Promise<boolean> {
  if (args.flags.has("yes")) return true;
  if (!process.stdin.isTTY) throw new UsageError("check the list above, then run again with --yes");
  return /^y(es)?$/i.test((await promptLine("Continue? [y/N] ")).trim());
}

class Session {
  readonly path: string;
  private source: IdentitySource | null | undefined;

  constructor(private readonly args: Args) {
    this.path = resolve(args.flags.get("file")?.at(-1) ?? process.env.ENVLOCKUP_FILE ?? ".env");
  }

  identitySource(): IdentitySource {
    if (this.source === undefined) this.source = findIdentity(process.env, this.args.flags.get("identity")?.at(-1));
    if (!this.source) {
      throw new Error(noKeyMessage(agentSocket() !== null));
    }
    return this.source;
  }

  async identity(): Promise<Identity> {
    const src = this.identitySource();
    try {
      return loadIdentity(src);
    } catch (err) {
      if (!(err instanceof PassphraseRequiredError) || !process.stdin.isTTY) throw err;
      return loadIdentity(src, await promptHidden(`Passphrase for ${src.source}: `));
    }
  }

  /** This user's ssh-agent recipient (signs twice to check it's deterministic). */
  async agentRecipient(): Promise<Recipient> {
    const client = agentClient();
    let preferred: Buffer | undefined;
    try {
      const src = findIdentity(process.env, this.args.flags.get("identity")?.at(-1));
      const pub = src && publicRecipient(src);
      if (pub && pub.type === "ssh-ed25519") preferred = pub.wire;
    } catch {
      // Only used to pick between several agent keys.
    }
    const key = selectAgentKey(await client.keys(), this.args.flags.get("key")?.at(-1), preferred);
    return agentRecipient(client, key);
  }

  /** Unlock with an explicit key, else ssh-agent, else ~/.ssh/id_ed25519. */
  async unlock(env: SealedEnv, options: { trustRecipients?: boolean } = {}): Promise<void> {
    const explicit = explicitIdentity(process.env, this.args.flags.get("identity")?.at(-1));
    let agentError: Error | undefined;
    const socket = agentSocket();
    if (!explicit && socket && env.recipients.some((r) => r.recipient.type === "ssh-agent")) {
      try {
        const identity = await agentIdentityFor(new AgentClient(socket), env.recipients.map((r) => r.recipient));
        if (identity) return env.unlock(identity, options);
      } catch (err) {
        agentError = err as Error;
      }
    }
    if (!explicit && !findIdentity(process.env) && agentError) throw agentError;
    const identity = await this.identity();
    env.unlock(identity, options);
    await this.suggestAgent(env, identity, socket);
  }

  /** After typing a passphrase for a key the agent already holds, point at `add --agent`. */
  private async suggestAgent(env: SealedEnv, identity: Identity, socket: string | null): Promise<void> {
    if (!socket || identity.recipient.type !== "ssh-ed25519") return;
    const { wire } = identity.recipient;
    if (env.recipients.some((r) => r.recipient.type === "ssh-agent" && r.recipient.wire.equals(wire))) return;
    try {
      if (!isEncryptedSSHKey(this.identitySource().text, this.identitySource().source)) return;
      const keys = await new AgentClient(socket).keys();
      if (keys.some((k) => k.wire.equals(wire))) {
        info("Tip: this key is loaded in ssh-agent. Run `envlockup add --agent` to stop typing its passphrase here.");
      }
    } catch {
      // Only a hint.
    }
  }

  read(): SealedEnv {
    return new SealedEnv(existsSync(this.path) ? readFileSync(this.path, "utf8") : "");
  }

  /** Read the file and unlock it, if it uses envlockup. */
  async open(): Promise<SealedEnv> {
    const env = this.read();
    if (!env.sealed) {
      if (!existsSync(this.path)) throw new Error(`${this.path} not found. Run \`envlockup init\` first.`);
      return env;
    }
    await this.unlock(env);
    return env;
  }

  async openSealed(): Promise<SealedEnv> {
    const env = await this.open();
    if (!env.sealed) throw new Error(`${this.path} does not use envlockup yet. Run \`envlockup init\` first.`);
    return env;
  }

  /**
   * Replace the file atomically. A symlinked file is updated through the link;
   * the file keeps its permissions (and its owner, when running as root).
   */
  write(env: SealedEnv): void {
    const target = existsSync(this.path) ? realpathSync(this.path) : this.path;
    const old = existsSync(target) ? statSync(target) : undefined;
    const tmp = join(dirname(target), `.${basename(target)}.${randomBytes(6).toString("hex")}.envlockup.tmp`);
    // "wx" fails if anything, a symlink included, already exists at that name.
    const fd = openSync(tmp, "wx", old ? old.mode & 0o7777 : 0o666);
    try {
      try {
        writeFileSync(fd, env.toString());
        if (old) {
          fchmodSync(fd, old.mode & 0o7777);
          if (process.getuid?.() === 0) fchownSync(fd, old.uid, old.gid);
        }
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      renameSync(tmp, target);
    } catch (err) {
      rmSync(tmp, { force: true });
      throw err;
    }
    if (process.platform !== "win32") {
      const dir = openSync(dirname(target), "r");
      try {
        fsyncSync(dir);
      } finally {
        closeSync(dir);
      }
    }
  }
}

async function resolveRecipients(specs: string[], label?: string): Promise<Recipient[]> {
  const result: Recipient[] = [];
  for (const spec of specs) {
    if (spec.startsWith("@")) {
      const user = spec.slice(1);
      if (!/^[A-Za-z0-9-]+$/.test(user)) throw new Error(`invalid GitHub user name: ${spec}`);
      const url = githubKeysUrl().replace("{user}", user);
      const res = await fetch(url);
      if (res.status === 404) throw new Error(`GitHub user ${spec} not found`);
      if (!res.ok) throw new Error(`cannot fetch keys for ${spec}: HTTP ${res.status}`);
      const published = (await res.text()).split("\n").filter(Boolean);
      const keys = published.filter((l) => l.startsWith("ssh-ed25519 "));
      if (keys.length === 0) {
        const types = [...new Set(published.map((l) => l.split(" ")[0]))];
        throw new Error(
          `${spec} has no ssh-ed25519 keys on GitHub${types.length ? ` (only ${types.join(", ")})` : ""}. ` +
            "Ask them to run `npx envlockup pubkey --agent` and add the line it prints, or to add an ssh-ed25519 key to their GitHub account.",
        );
      }
      result.push(...keys.map((k) => parseRecipient(k, label ?? spec)));
    } else if (existsSync(spec)) {
      result.push(parseRecipient(readFileSync(spec, "utf8"), label));
    } else {
      result.push(parseRecipient(spec, label));
    }
  }
  return result;
}

/** github.com, or a local server for tests: a repository must not be able to redirect `add @user`. */
function githubKeysUrl(): string {
  const custom = process.env.ENVLOCKUP_GITHUB_KEYS_URL;
  if (!custom) return "https://github.com/{user}.keys";
  const host = URL.canParse(custom) ? new URL(custom).hostname : "";
  if (!["127.0.0.1", "localhost", "[::1]"].includes(host)) {
    throw new Error("ENVLOCKUP_GITHUB_KEYS_URL is only for tests and must point to localhost");
  }
  return custom;
}

/** Every recipient matching any of `who` (a number, fingerprint, label or key). */
function findRecipients(env: SealedEnv, who: string[]): Recipient[] {
  const all = env.recipients.map((r) => r.recipient);
  const found: Recipient[] = [];
  for (const w of who) {
    const n = Number(w);
    const matches =
      Number.isInteger(n) && n >= 1 && n <= all.length
        ? [all[n - 1]!]
        : all.filter((r) => fingerprint(r) === w || fingerprint(r) === `SHA256:${w}` || r.label === w || recipientKey(r) === w);
    if (matches.length === 0) throw new Error(`no recipient matches "${w}"`);
    for (const r of matches) if (!found.some((f) => sameRecipient(f, r))) found.push(r);
  }
  return found;
}

function dotenvLine(name: string, value: string): string {
  try {
    return `${name}=${formatValue(value)}`;
  } catch {
    throw new Error(`${name} cannot be written in dotenv syntax (it mixes ', " and \`); use --format json`);
  }
}

async function run(argv: string[]): Promise<number> {
  const args = parseArgs(argv);
  if (args.flags.has("version")) {
    const pkg = createRequire(import.meta.url)("../package.json") as { version: string };
    out(pkg.version);
    return 0;
  }
  if (args.flags.has("help") || !args.command || args.command === "help") {
    out(HELP);
    return args.command || args.flags.has("help") ? 0 : 1;
  }
  const s = new Session(args);
  const [first, second] = args.positional;
  const label = args.flags.get("label")?.at(-1);

  switch (args.command) {
    case "init": {
      const env = s.read();
      const specs = args.flags.get("recipient") ?? [];
      const recipients = specs.length ? await resolveRecipients(specs) : [];
      if (args.flags.has("agent")) recipients.push(await s.agentRecipient());
      if (recipients.length === 0) recipients.push(publicRecipient(s.identitySource()));
      const encrypted = env.init(recipients, { keepPlain: args.flags.has("keep-plain") });
      s.write(env);
      info(`envlockup: ${s.path} is now encrypted for:`);
      for (const r of recipients) info(`  ${describe(r)}`);
      if (encrypted.length) info(`Encrypted ${encrypted.length} existing value(s): ${encrypted.join(", ")}`);
      info("It is safe to commit.");
      for (const line of gitAdvice(s.path)) info(line);
      return 0;
    }
    case "set": {
      if (!first) throw new UsageError("usage: envlockup set NAME [VALUE]");
      let value = second;
      if (value === undefined) value = process.stdin.isTTY ? await promptHidden(`Value for ${first}: `) : await readStdin();
      const env = await s.openSealed();
      env.set(first, value, { plain: args.flags.has("plain") });
      s.write(env);
      return 0;
    }
    case "get": {
      if (!first) throw new UsageError("usage: envlockup get NAME");
      const value = (await s.open()).get(first);
      if (value === undefined) {
        info(`envlockup: ${first} is not set`);
        return 1;
      }
      out(value);
      return 0;
    }
    case "unset": {
      if (!first) throw new UsageError("usage: envlockup unset NAME");
      const env = s.read();
      if (!env.unset(first)) {
        info(`envlockup: ${first} is not set`);
        return 1;
      }
      s.write(env);
      return 0;
    }
    case "ls": {
      const env = s.read();
      for (const e of env.entries()) out(`${e.encrypted ? "🔒" : "  "} ${e.name}`);
      for (const name of env.plaintextOverrides()) {
        info(`envlockup: warning: ${name} is encrypted, then set again in plaintext; reading the file will fail until one is removed`);
      }
      return 0;
    }
    case "check":
      return check(s, args);
    case "encrypt": {
      const env = await s.openSealed();
      const done = env.encrypt(args.positional.length ? args.positional : undefined);
      s.write(env);
      info(done.length ? `Encrypted: ${done.join(", ")}` : "Nothing to encrypt.");
      return 0;
    }
    case "decrypt": {
      const format = args.flags.get("format")?.at(-1) ?? "dotenv";
      if (format !== "dotenv" && format !== "json") throw new UsageError(`unknown format "${format}" (expected dotenv or json)`);
      const values = (await s.open()).decryptAll();
      if (format === "json") out(JSON.stringify(values, null, 2));
      else {
        const lines = Object.entries(values).map(([name, value]) => dotenvLine(name, value));
        if (lines.length) out(lines.join("\n"));
      }
      return 0;
    }
    case "run": {
      if (args.rest.length === 0) throw new UsageError("usage: envlockup run -- COMMAND [ARGS]...");
      const values = (await s.open()).decryptAll();
      const childEnv: Record<string, string | undefined> = { ...process.env };
      for (const name of SECRET_ENV_VARS) delete childEnv[name];
      for (const [name, value] of Object.entries(values)) {
        if (args.flags.has("override") || childEnv[name] === undefined) childEnv[name] = value;
      }
      return spawnChild(args.rest, childEnv);
    }
    case "recipients": {
      const env = s.read();
      if (!env.sealed) throw new Error(`${s.path} does not use envlockup yet`);
      if (!args.flags.has("accept")) {
        env.recipients.forEach((r, i) => out(`${i + 1}. ${describe(r.recipient)}`));
        return 0;
      }
      await s.unlock(env, { trustRecipients: true });
      if (env.recipientsVerified) {
        info("The recipient list is already signed: nothing to accept.");
        return 0;
      }
      info("Accepting signs this list. Everyone on it will get the data key the next time it changes (add, remove):");
      for (const r of env.recipients) info(`  ${describe(r.recipient)}`);
      if (!(await confirm(args))) {
        info("Nothing changed.");
        return 1;
      }
      env.acceptRecipients();
      s.write(env);
      info("Done. The recipient list is signed.");
      return 0;
    }
    case "add": {
      if (args.positional.length === 0 && !args.flags.has("agent")) throw new UsageError("usage: envlockup add KEY... | --agent");
      const recipients = await resolveRecipients(args.positional, label);
      const env = await s.openSealed();
      if (args.flags.has("agent")) {
        const mine = await s.agentRecipient();
        if (label) mine.label = label;
        recipients.push(mine);
      }
      for (const r of recipients) env.addRecipient(r);
      s.write(env);
      for (const r of recipients) info(`Added ${describe(r)}`);
      if (args.positional.some((p) => p.startsWith("@"))) {
        info("Keys from GitHub are trusted as published: check the fingerprints with their owner.");
      }
      return 0;
    }
    case "remove": {
      if (args.positional.length === 0) throw new UsageError("usage: envlockup remove WHO...");
      const env = await s.openSealed();
      const removed = findRecipients(env, args.positional);
      const remaining = env.recipients.map((r) => r.recipient).filter((r) => !removed.some((x) => sameRecipient(x, r)));
      if (remaining.length === 0) throw new Error("cannot remove the last recipient");
      // Every remaining line gets the new data key, including any line someone
      // added to the file without being able to decrypt it: show who that is.
      info("Removing:");
      for (const r of removed) info(`  ${describe(r)}`);
      info("The new data key will be readable by:");
      for (const r of remaining) info(`  ${describe(r)}`);
      if (!(await confirm(args))) {
        info("Nothing changed.");
        return 1;
      }
      env.removeRecipients(removed);
      s.write(env);
      info("Done. The data key was rotated. Anyone removed may still know the values they could read: rotate those secrets too.");
      return 0;
    }
    case "pubkey": {
      const r = args.flags.has("agent") ? await s.agentRecipient() : publicRecipient(s.identitySource());
      out(`${recipientKey(r)}${r.label ? ` ${r.label}` : ""}`);
      return 0;
    }
    case "keygen": {
      const env = await s.openSealed();
      const { secret, recipient } = generateAgeIdentity();
      recipient.label = label ?? "ci";
      env.addRecipient(recipient);
      s.write(env);
      info(`Added ${describe(recipient)}`);
      info("Store this private key as the secret ENVLOCKUP_PRIVATE_KEY in your CI or server. It is shown only once:");
      out(secret);
      return 0;
    }
    default: {
      const guess = COMMANDS.find((c) => editDistance(c, args.command!) <= 2);
      throw new UsageError(`unknown command "${args.command}".${guess ? ` Did you mean "${guess}"?` : ""} Run \`envlockup --help\`.`);
    }
  }
}

const COMMANDS = ["init", "set", "get", "unset", "ls", "check", "encrypt", "decrypt", "run", "recipients", "add", "remove", "pubkey", "keygen"];

function editDistance(a: string, b: string): number {
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const row = [i];
    for (let j = 1; j <= b.length; j++) row[j] = Math.min(prev[j]! + 1, row[j - 1]! + 1, prev[j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1));
    prev = row;
  }
  return prev[b.length]!;
}

/**
 * What git says about a file that just became safe to commit: the ignore rule
 * that still excludes it, and earlier commits that hold it in plaintext.
 */
function gitAdvice(path: string): string[] {
  const git = (...gitArgs: string[]) => spawnSync("git", gitArgs, { cwd: dirname(path), encoding: "utf8" });
  if (git("rev-parse", "--is-inside-work-tree").stdout?.trim() !== "true") return [];
  const advice: string[] = [];
  const ignored = git("check-ignore", "--verbose", "--", basename(path));
  if (ignored.status === 0) {
    // "<source>:<line>:<pattern>\t<path>"
    const [rule] = ignored.stdout.split("\t");
    const match = rule?.match(/^(.*):(\d+):(.*)$/);
    advice.push(
      match
        ? `Git still ignores it: line ${match[2]} of ${match[1]} ("${match[3]}"). Remove that line, then \`git add ${basename(path)}\`.`
        : `Git still ignores it (${rule}). Change your .gitignore, then \`git add ${basename(path)}\`.`,
    );
  }
  const commits = Number(git("rev-list", "--all", "--count", "--", basename(path)).stdout?.trim() || 0);
  if (commits > 0) {
    advice.push(
      `Warning: ${basename(path)} is already in ${commits} earlier commit(s), unencrypted. Encrypting it now doesn't change them: ` +
        "anyone with a copy of the repository can still read those values. Rotate those secrets.",
    );
  }
  return advice;
}

/** The file as committed in `ref`, or null if git, the commit or the file isn't there. */
function gitVersion(path: string, ref: string, explicit: boolean): SealedEnv | null {
  const cwd = dirname(path);
  const commit = spawnSync("git", ["rev-parse", "--verify", "--quiet", `${ref}^{commit}`], { cwd, encoding: "utf8" });
  if (commit.status !== 0) {
    if (explicit) throw new UsageError(`--base: ${ref} is not a commit in the git repository at ${cwd}`);
    return null;
  }
  const show = spawnSync("git", ["show", `${ref}:./${basename(path)}`], { cwd, encoding: "utf8" });
  if (show.status !== 0) return null;
  try {
    return new SealedEnv(show.stdout);
  } catch {
    return null;
  }
}

async function check(s: Session, args: Args): Promise<number> {
  if (!existsSync(s.path)) throw new Error(`${s.path} not found`);
  const env = s.read();
  const problems: string[] = [];
  if (!env.sealed) problems.push(`${s.path} does not use envlockup`);
  for (const name of env.plaintextOverrides()) problems.push(`${name} is encrypted, then set again in plaintext`);

  const allowed = new Set((args.flags.get("allow-plain") ?? []).flatMap((v) => v.split(",")).map((n) => n.trim()).filter(Boolean));
  const explicitBase = args.flags.get("base")?.at(-1);
  const ref = explicitBase ?? "HEAD";
  const before = gitVersion(s.path, ref, explicitBase !== undefined);
  const beforeEntries = before?.entries() ?? [];
  const encryptedBefore = new Set(beforeEntries.filter((e) => e.encrypted).map((e) => e.name));
  const plainBefore = new Set(beforeEntries.filter((e) => !e.encrypted).map((e) => e.name));
  let plaintextProblems = 0;
  for (const name of new Set(env.entries().filter((e) => !e.encrypted).map((e) => e.name))) {
    if (allowed.has(name)) continue;
    if (encryptedBefore.has(name)) problems.push(`${name} is in plaintext, but is encrypted in ${ref}`);
    else if (!plainBefore.has(name)) problems.push(`${name} is a new plaintext value`);
    else continue;
    plaintextProblems++;
  }

  // Values and the recipient list can only be checked with a key.
  let decryptNote: string | undefined;
  const hasKey =
    findIdentity(process.env, args.flags.get("identity")?.at(-1)) ||
    (agentSocket() && env.recipients.some((r) => r.recipient.type === "ssh-agent"));
  if (!env.sealed) {
    // Nothing to decrypt.
  } else if (!hasKey) {
    decryptNote = "not checked whether the file decrypts: no private key here (in CI, set ENVLOCKUP_PRIVATE_KEY)";
  } else {
    try {
      await s.unlock(env);
    } catch (err) {
      if (err instanceof NotARecipientError || err instanceof PassphraseRequiredError) {
        decryptNote = `not checked whether the file decrypts: ${(err as Error).message}`;
      } else {
        problems.push((err as Error).message);
      }
    }
  }

  if (!before && plaintextProblems > 0) info(`envlockup: no earlier version of the file in ${ref}, so every plaintext value counts as new`);
  for (const p of problems) info(`envlockup check: ${printable(p)}`);
  if (decryptNote) info(`envlockup: ${printable(decryptNote)}`);
  if (plaintextProblems > 0) {
    info("Encrypt them with `envlockup encrypt NAME`, or, if they are not secrets, list them with --allow-plain NAME,...");
  }
  if (problems.length) return 1;
  info(`${s.path}: OK`);
  return 0;
}

// cmd.exe metacharacters, escaped with ^ (the same rules as cross-spawn).
const CMD_META = /([()\][%!^"`<>&|;, *?])/g;

function cmdEscapeArgument(arg: string, twice: boolean): string {
  // Backslashes before a quote, or at the end (before the closing quote), are doubled.
  let quoted = `"${arg.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\*)$/, "$1$1")}"`.replace(CMD_META, "^$1");
  // A batch file that forwards its arguments with %* has cmd.exe parse them a
  // second time, which removes one more level of escaping.
  if (twice) quoted = quoted.replace(CMD_META, "^$1");
  return quoted;
}

/** `command` resolved on PATH with PATHEXT, as cmd.exe would; undefined if it isn't a file. */
function whichWindows(command: string, env: Record<string, string | undefined>): string | undefined {
  const pathVar = Object.entries(env).find(([k]) => k.toUpperCase() === "PATH")?.[1] ?? "";
  const extVar = Object.entries(env).find(([k]) => k.toUpperCase() === "PATHEXT")?.[1] ?? ".COM;.EXE;.BAT;.CMD";
  const exts = ["", ...extVar.split(";").filter(Boolean)];
  const dirs = /[\\/]/.test(command) ? [""] : [process.cwd(), ...pathVar.split(";").filter(Boolean)];
  for (const dir of dirs) {
    for (const ext of exts) {
      const candidate = dir ? join(dir, command + ext) : command + ext;
      if (existsSync(candidate) && statSync(candidate).isFile()) return candidate;
    }
  }
  return undefined;
}

/**
 * How to start `command` on Windows so that its arguments arrive unchanged.
 * Executables are started directly, without a shell. Batch files (npm, npx and
 * other .cmd shims) can only run through cmd.exe, so their arguments are
 * escaped for it, twice, because launchers pass them on with %*. Anything not
 * found on PATH (a cmd.exe built-in) goes through cmd.exe, escaped once.
 */
function windowsInvocation(
  command: string[],
  env: Record<string, string | undefined>,
): { file: string; args: string[]; verbatim: boolean } {
  const [name, ...args] = command as [string, ...string[]];
  const resolved = whichWindows(name, env);
  if (resolved && !/\.(cmd|bat)$/i.test(resolved)) return { file: resolved, args, verbatim: false };
  const target = resolved ?? name;
  const line = [target.replace(CMD_META, "^$1"), ...args.map((a) => cmdEscapeArgument(a, resolved !== undefined))].join(" ");
  const comspec = Object.entries(env).find(([k]) => k.toUpperCase() === "COMSPEC")?.[1] ?? "cmd.exe";
  return { file: comspec, args: ["/d", "/s", "/c", `"${line}"`], verbatim: true };
}

function spawnChild(command: string[], env: Record<string, string | undefined>): Promise<number> {
  return new Promise((resolveExit) => {
    let child;
    if (process.platform === "win32") {
      const { file, args, verbatim } = windowsInvocation(command, env);
      child = spawn(file, args, { stdio: "inherit", env, windowsVerbatimArguments: verbatim });
    } else {
      child = spawn(command[0]!, command.slice(1), { stdio: "inherit", env });
    }
    const forward = (signal: NodeJS.Signals) => () => child.kill(signal);
    const signals: NodeJS.Signals[] = ["SIGINT", "SIGTERM", "SIGHUP"];
    const handlers = signals.map((sig) => [sig, forward(sig)] as const);
    for (const [sig, h] of handlers) process.on(sig, h);
    child.on("error", (err) => {
      info(`envlockup: cannot run ${command[0]}: ${err.message}`);
      resolveExit(127);
    });
    child.on("exit", (code, signal) => {
      for (const [sig, h] of handlers) process.off(sig, h);
      resolveExit(code ?? (signal ? 128 + (signalNumber(signal) ?? 1) : 1));
    });
  });
}

function signalNumber(signal: NodeJS.Signals): number | undefined {
  return ({ SIGHUP: 1, SIGINT: 2, SIGTERM: 15, SIGKILL: 9 } as Record<string, number>)[signal];
}

/** Exit once stdout and stderr are flushed: into a pipe they are written asynchronously, and
 * process.exit() would drop what the reader hasn't taken yet (all but the first 64 KB). */
function exit(code: number): void {
  let pending = 2;
  const done = () => {
    if (--pending === 0) process.exit(code);
  };
  process.stdout.write("", done);
  process.stderr.write("", done);
}

run(process.argv.slice(2)).then(
  (code) => exit(code),
  (err: Error) => {
    info(`envlockup: ${printable(err.message)}`);
    exit(err instanceof UsageError ? 2 : 1);
  },
);
