#!/usr/bin/env node
import { spawn } from "node:child_process";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { AgentClient, agentIdentityFor, agentRecipient, agentSocket, selectAgentKey } from "./agent.js";
import { type IdentitySource, SECRET_ENV_VARS, explicitIdentity, findIdentity, loadIdentity, publicRecipient } from "./identity.js";
import {
  type Identity,
  PassphraseRequiredError,
  type Recipient,
  fingerprint,
  generateAgeIdentity,
  isEncryptedSSHKey,
  parseRecipient,
  recipientKey,
} from "./keys.js";
import { SealedEnv } from "./vault.js";

const HELP = `envseal — encrypted .env files you can commit

Usage: envseal [-f FILE] [-i KEY] <command> [args]

Commands:
  init [--recipient KEY]... [--agent [--key K]] [--keep-plain]
                         Start using envseal in FILE, encrypted for your SSH key
                         (or your ssh-agent key, or the given public keys).
                         Existing values get encrypted.
  set NAME [VALUE] [--plain]
                         Set a variable. Without VALUE it is read from stdin or
                         prompted for, so it doesn't end up in your shell history.
  get NAME               Print one decrypted value.
  unset NAME             Remove a variable.
  ls                     List variable names, marking which are encrypted.
  encrypt [NAME]...      Encrypt plaintext values (all, or the ones named).
  decrypt                Print the whole file decrypted, in dotenv format.
  run [--override] -- COMMAND [ARGS]...
                         Run COMMAND with the variables in its environment.
                         Nothing decrypted is written to disk.
  recipients             List who can decrypt the file.
  add KEY... [--label TEXT]
                         Give access to a public key: "ssh-ed25519 AAAA...",
                         a .pub file, an age1... key, an "ssh-agent ..." line
                         from \`envseal pubkey --agent\`, or @github-user.
  add --agent [--key K]  Give access to your own ssh-agent key, so you can
                         decrypt without a key file or passphrase prompt.
  pubkey [--agent [--key K]]
                         Print your public key, to send to someone who will
                         \`envseal add\` it. With --agent, your ssh-agent key.
  remove WHO...          Revoke access (fingerprint, label or number from
                         \`recipients\`) and rotate the data key.
  keygen [--label TEXT]  Create a dedicated key (e.g. for CI), add it as a
                         recipient and print the private key once.

Options:
  -f, --file FILE        File to use (default: $ENVSEAL_FILE or .env)
  -i, --identity KEY     Private key file (default: $ENVSEAL_PRIVATE_KEY,
                         $ENVSEAL_IDENTITY, ssh-agent, or ~/.ssh/id_ed25519)
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

const VALUE_FLAGS = new Set(["file", "identity", "recipient", "label", "key"]);
const ALIASES: Record<string, string> = { f: "file", i: "identity", h: "help", v: "version" };

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

function describe(r: Recipient): string {
  return `${fingerprint(r)}  ${r.type === "X25519" ? "age" : r.type}${r.label ? `  ${r.label}` : ""}`;
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

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/, "");
}

class Session {
  readonly path: string;
  private source: IdentitySource | null | undefined;

  constructor(private readonly args: Args) {
    this.path = resolve(args.flags.get("file")?.at(-1) ?? process.env.ENVSEAL_FILE ?? ".env");
  }

  identitySource(): IdentitySource {
    if (this.source === undefined) this.source = findIdentity(process.env, this.args.flags.get("identity")?.at(-1));
    if (!this.source) {
      throw new Error("no private key found. Create one with `ssh-keygen -t ed25519`, or set ENVSEAL_PRIVATE_KEY or ENVSEAL_IDENTITY.");
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
  async unlock(env: SealedEnv): Promise<void> {
    const explicit = explicitIdentity(process.env, this.args.flags.get("identity")?.at(-1));
    let agentError: Error | undefined;
    const socket = agentSocket();
    if (!explicit && socket && env.recipients.some((r) => r.recipient.type === "ssh-agent")) {
      try {
        const identity = await agentIdentityFor(new AgentClient(socket), env.recipients.map((r) => r.recipient));
        if (identity) return env.unlock(identity);
      } catch (err) {
        agentError = err as Error;
      }
    }
    if (!explicit && !findIdentity(process.env) && agentError) throw agentError;
    const identity = await this.identity();
    env.unlock(identity);
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
        info("Tip: this key is loaded in ssh-agent. Run `envseal add --agent` to stop typing its passphrase here.");
      }
    } catch {
      // Only a hint.
    }
  }

  read(): SealedEnv {
    return new SealedEnv(existsSync(this.path) ? readFileSync(this.path, "utf8") : "");
  }

  /** Read the file and unlock it, if it uses envseal. */
  async open(): Promise<SealedEnv> {
    const env = this.read();
    if (!env.sealed) {
      if (!existsSync(this.path)) throw new Error(`${this.path} not found. Run \`envseal init\` first.`);
      return env;
    }
    await this.unlock(env);
    return env;
  }

  async openSealed(): Promise<SealedEnv> {
    const env = await this.open();
    if (!env.sealed) throw new Error(`${this.path} does not use envseal yet. Run \`envseal init\` first.`);
    return env;
  }

  write(env: SealedEnv): void {
    const tmp = join(dirname(this.path), `.${Date.now()}.envseal.tmp`);
    writeFileSync(tmp, env.toString());
    renameSync(tmp, this.path);
  }
}

async function resolveRecipients(specs: string[], label?: string): Promise<Recipient[]> {
  const result: Recipient[] = [];
  for (const spec of specs) {
    if (spec.startsWith("@")) {
      const user = spec.slice(1);
      if (!/^[A-Za-z0-9-]+$/.test(user)) throw new Error(`invalid GitHub user name: ${spec}`);
      const url = (process.env.ENVSEAL_GITHUB_KEYS_URL ?? "https://github.com/{user}.keys").replace("{user}", user);
      const res = await fetch(url);
      if (!res.ok) throw new Error(`cannot fetch keys for ${spec}: HTTP ${res.status}`);
      const keys = (await res.text()).split("\n").filter((l) => l.startsWith("ssh-ed25519 "));
      if (keys.length === 0) throw new Error(`${spec} has no ssh-ed25519 keys on GitHub`);
      result.push(...keys.map((k) => parseRecipient(k, label ?? spec)));
    } else if (existsSync(spec)) {
      result.push(parseRecipient(readFileSync(spec, "utf8"), label));
    } else {
      result.push(parseRecipient(spec, label));
    }
  }
  return result;
}

function findRecipients(env: SealedEnv, who: string[]): Recipient[] {
  return who.map((w) => {
    const all = env.recipients.map((r) => r.recipient);
    const n = Number(w);
    if (Number.isInteger(n) && n >= 1 && n <= all.length) return all[n - 1]!;
    const matches = all.filter((r) => fingerprint(r) === w || fingerprint(r) === `SHA256:${w}` || r.label === w || recipientKey(r) === w);
    if (matches.length === 0) throw new Error(`no recipient matches "${w}"`);
    if (matches.length > 1 && !w.startsWith("@")) throw new Error(`"${w}" matches more than one recipient; use its number`);
    return matches[0]!;
  });
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
      info(`envseal: ${s.path} is now encrypted for:`);
      for (const r of recipients) info(`  ${describe(r)}`);
      if (encrypted.length) info(`Encrypted ${encrypted.length} existing value(s): ${encrypted.join(", ")}`);
      info("It is safe to commit. Check your .gitignore no longer excludes it.");
      return 0;
    }
    case "set": {
      if (!first) throw new UsageError("usage: envseal set NAME [VALUE]");
      let value = second;
      if (value === undefined) value = process.stdin.isTTY ? await promptHidden(`Value for ${first}: `) : await readStdin();
      const env = await s.openSealed();
      env.set(first, value, { plain: args.flags.has("plain") });
      s.write(env);
      return 0;
    }
    case "get": {
      if (!first) throw new UsageError("usage: envseal get NAME");
      const value = (await s.open()).get(first);
      if (value === undefined) {
        info(`envseal: ${first} is not set`);
        return 1;
      }
      out(value);
      return 0;
    }
    case "unset": {
      if (!first) throw new UsageError("usage: envseal unset NAME");
      const env = s.read();
      if (!env.unset(first)) {
        info(`envseal: ${first} is not set`);
        return 1;
      }
      s.write(env);
      return 0;
    }
    case "ls": {
      const env = s.read();
      for (const e of env.entries()) out(`${e.encrypted ? "🔒" : "  "} ${e.name}`);
      return 0;
    }
    case "encrypt": {
      const env = await s.openSealed();
      const done = env.encrypt(args.positional.length ? args.positional : undefined);
      s.write(env);
      info(done.length ? `Encrypted: ${done.join(", ")}` : "Nothing to encrypt.");
      return 0;
    }
    case "decrypt": {
      const values = (await s.open()).decryptAll();
      for (const [name, value] of Object.entries(values)) out(`${name}=${JSON.stringify(value)}`);
      return 0;
    }
    case "run": {
      if (args.rest.length === 0) throw new UsageError("usage: envseal run -- COMMAND [ARGS]...");
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
      if (!env.sealed) throw new Error(`${s.path} does not use envseal yet`);
      env.recipients.forEach((r, i) => out(`${i + 1}. ${describe(r.recipient)}`));
      return 0;
    }
    case "add": {
      if (args.positional.length === 0 && !args.flags.has("agent")) throw new UsageError("usage: envseal add KEY... | --agent");
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
      if (args.positional.length === 0) throw new UsageError("usage: envseal remove WHO...");
      const env = await s.openSealed();
      const removed = findRecipients(env, args.positional);
      env.removeRecipients(removed);
      s.write(env);
      for (const r of removed) info(`Removed ${describe(r)}`);
      info("The data key was rotated. Anyone removed may still know the values they could read: rotate those secrets too.");
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
      info("Store this private key as the secret ENVSEAL_PRIVATE_KEY in your CI or server. It is shown only once:");
      out(secret);
      return 0;
    }
    default:
      throw new UsageError(`unknown command "${args.command}". Run \`envseal --help\`.`);
  }
}

function spawnChild(command: string[], env: Record<string, string | undefined>): Promise<number> {
  return new Promise((resolveExit) => {
    // On Windows, npm, npx and friends are .cmd scripts that need a shell.
    const windows = process.platform === "win32";
    const child = windows
      ? spawn(command.map((c) => (/[\s"]/.test(c) ? `"${c.replace(/"/g, '\\"')}"` : c)).join(" "), { stdio: "inherit", env, shell: true })
      : spawn(command[0]!, command.slice(1), { stdio: "inherit", env });
    const forward = (signal: NodeJS.Signals) => () => child.kill(signal);
    const signals: NodeJS.Signals[] = ["SIGINT", "SIGTERM", "SIGHUP"];
    const handlers = signals.map((sig) => [sig, forward(sig)] as const);
    for (const [sig, h] of handlers) process.on(sig, h);
    child.on("error", (err) => {
      info(`envseal: cannot run ${command[0]}: ${err.message}`);
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

run(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err: Error) => {
    info(`envseal: ${err.message}`);
    process.exit(err instanceof UsageError ? 2 : 1);
  },
);
