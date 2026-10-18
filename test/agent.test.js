// ssh-agent support, against a real OpenSSH ssh-agent.
import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { AgentClient, agentRecipient, deriveSecret, selectAgentKey, signedData } from "../dist/agent.js";
import { parseSSHPublicKey } from "../dist/keys.js";
import { sshKey, tempDir } from "./helpers.js";

const CLI = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
const has = (cmd) => spawnSync(cmd, ["-h"]).error === undefined;
const skip = process.platform === "win32" || !has("ssh-agent") || !has("ssh-add") ? "needs OpenSSH ssh-agent on a Unix system" : false;

const dir = tempDir();
const home = join(dir, "home"); // no ~/.ssh: the agent is the only key source
const sock = join(dir, "agent.sock");
let agentProc;
let ed, rsa, locked;

function sshAdd(path, passphrase) {
  const askpass = join(dir, "askpass.sh");
  writeFileSync(askpass, `#!/bin/sh\necho '${passphrase ?? ""}'\n`);
  chmodSync(askpass, 0o700);
  execFileSync("ssh-add", [path], {
    env: { ...process.env, SSH_AUTH_SOCK: sock, SSH_ASKPASS: askpass, SSH_ASKPASS_REQUIRE: "force", DISPLAY: ":0" },
    stdio: "ignore",
  });
}

before(async () => {
  if (skip) return;
  execFileSync("mkdir", ["-p", home]);
  ed = sshKey(dir, "ed");
  locked = sshKey(dir, "locked", "pw");
  rsa = join(dir, "rsa");
  execFileSync("ssh-keygen", ["-q", "-t", "rsa", "-b", "2048", "-N", "", "-C", "rsa@test", "-f", rsa]);
  execFileSync("ssh-keygen", ["-q", "-t", "ecdsa", "-N", "", "-C", "ecdsa@test", "-f", join(dir, "ecdsa")]);
  agentProc = spawn("ssh-agent", ["-D", "-a", sock], { stdio: "ignore" });
  for (let i = 0; i < 100 && !existsSync(sock); i++) await new Promise((r) => setTimeout(r, 50));
  sshAdd(ed.path);
  sshAdd(rsa);
  sshAdd(join(dir, "ecdsa"));
});

after(() => agentProc?.kill());

const envFile = join(dir, ".env");
function cli(args, env = {}) {
  const inherited = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith("ENVSEAL_")));
  const r = spawnSync(process.execPath, [CLI, "-f", envFile, ...args], {
    env: { ...inherited, HOME: home, SSH_AUTH_SOCK: sock, ...env },
    encoding: "utf8",
  });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

test("agent signatures match ssh-keygen -Y sign (SSHSIG framing)", { skip }, async () => {
  const client = new AgentClient(sock);
  const { wire } = parseSSHPublicKey(ed.public);
  const fromAgent = await client.sign(wire, signedData());
  const msg = join(dir, "msg");
  writeFileSync(msg, "github.com/denisbilli/envseal/v1/agent-identity");
  execFileSync("ssh-keygen", ["-q", "-Y", "sign", "-n", "github.com/denisbilli/envseal", "-f", ed.path, msg]);
  const armored = readFileSync(`${msg}.sig`, "utf8").replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const sshsig = Buffer.from(armored, "base64");
  // The SSHSIG file ends with string(signature); compare it with the agent's.
  assert.ok(sshsig.subarray(sshsig.length - fromAgent.length).equals(fromAgent));
  assert.equal(deriveSecret(wire, fromAgent).length, 32);
});

test("derived recipients are stable, and differ per key", { skip }, async () => {
  const client = new AgentClient(sock);
  const keys = await client.keys();
  const edKey = selectAgentKey(keys, "ed@test");
  const rsaKey = selectAgentKey(keys, "rsa@test");
  const a = await agentRecipient(client, edKey);
  const b = await agentRecipient(client, edKey);
  const c = await agentRecipient(client, rsaKey);
  assert.deepEqual(a.publicKey, b.publicKey);
  assert.notDeepEqual(a.publicKey, c.publicKey);
  assert.throws(() => selectAgentKey(keys), /several keys/);
  assert.throws(() => selectAgentKey(keys, "ecdsa@test"), /no ssh-agent key matches/);
});

test("CLI: init --agent, then everything works with no key file", { skip }, () => {
  writeFileSync(envFile, "TOKEN=t0ps3cret\n");
  const init = cli(["init", "--agent", "--key", "ed@test"]);
  assert.equal(init.code, 0, init.stderr);
  assert.match(readFileSync(envFile, "utf8"), /^#envseal:recipient ssh-agent age1\S+ ssh-ed25519 \S+ \S+ \S+ ed@test$/m);
  assert.equal(cli(["get", "TOKEN"]).stdout, "t0ps3cret\n");
  const run = cli(["run", "--", process.execPath, "-e", "console.log(process.env.TOKEN)"]);
  assert.equal(run.stdout, "t0ps3cret\n", run.stderr);
  // Without the agent, nothing opens it.
  assert.notEqual(cli(["get", "TOKEN"], { SSH_AUTH_SOCK: "" }).code, 0);
});

test("import 'envseal/config' unlocks through the agent", { skip }, () => {
  const config = new URL("../dist/config.js", import.meta.url).href;
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", `import ${JSON.stringify(config)}; console.log(process.env.TOKEN)`], {
    cwd: dir,
    env: { PATH: process.env.PATH, HOME: home, SSH_AUTH_SOCK: sock },
    encoding: "utf8",
  });
  assert.equal(r.stdout, "t0ps3cret\n", r.stderr);
});

test("pubkey --agent output can be added by someone else", { skip }, () => {
  const line = cli(["pubkey", "--agent", "--key", "rsa@test"]);
  assert.match(line.stdout, /^ssh-agent age1\S+ ssh-rsa \S+ rsa@test\n$/);
  assert.equal(cli(["add", line.stdout.trim()]).code, 0);
  // Remove the ed25519 agent recipient: only the RSA agent key can open it now.
  assert.equal(cli(["remove", "1"]).code, 0);
  assert.equal(cli(["get", "TOKEN"]).stdout, "t0ps3cret\n");
  assert.match(cli(["recipients"]).stdout, /^1\. SHA256:\S+  ssh-agent  rsa@test\n$/);
});

test("a passphrase key: unlock once, add --agent, then no passphrase", { skip }, () => {
  writeFileSync(envFile, "TOKEN=t0ps3cret\n");
  assert.equal(cli(["init"], { ENVSEAL_IDENTITY: locked.path }).code, 0);
  sshAdd(locked.path, "pw");
  // The file is encrypted for the key file: the agent line doesn't exist yet.
  assert.match(cli(["get", "TOKEN"], { ENVSEAL_IDENTITY: locked.path }).stderr, /passphrase/);
  const hinted = cli(["get", "TOKEN"], { ENVSEAL_IDENTITY: locked.path, ENVSEAL_SSH_PASSPHRASE: "pw" });
  assert.match(hinted.stderr, /Tip: .*envseal add --agent/);
  const add = cli(["add", "--agent", "--key", "locked@test"], { ENVSEAL_IDENTITY: locked.path, ENVSEAL_SSH_PASSPHRASE: "pw" });
  assert.doesNotMatch(cli(["get", "TOKEN"], { ENVSEAL_IDENTITY: locked.path, ENVSEAL_SSH_PASSPHRASE: "pw" }).stderr, /Tip:/);
  assert.equal(add.code, 0, add.stderr);
  assert.equal(cli(["get", "TOKEN"]).stdout, "t0ps3cret\n");
});

test("an agent returning a bad signature is rejected", { skip }, async () => {
  const fakeSock = join(dir, "fake.sock");
  const { wire } = parseSSHPublicKey(ed.public);
  const str = (b) => Buffer.concat([Buffer.from([0, 0, 0, b.length].map((x, i) => (i < 2 ? 0 : i === 2 ? (b.length >> 8) & 255 : b.length & 255))), b]);
  const server = createServer((c) =>
    c.on("data", (d) => {
      const type = d[4];
      let body;
      if (type === 11) body = Buffer.concat([Buffer.from([12, 0, 0, 0, 1]), str(wire), str(Buffer.from("ed@test"))]);
      else body = Buffer.concat([Buffer.from([14]), str(Buffer.concat([str(Buffer.from("ssh-ed25519")), str(Buffer.alloc(64, 7))]))]);
      const len = Buffer.alloc(4);
      len.writeUInt32BE(body.length);
      c.end(Buffer.concat([len, body]));
    }),
  );
  await new Promise((r) => server.listen(fakeSock, r));
  const client = new AgentClient(fakeSock);
  const [key] = await client.keys();
  await assert.rejects(agentRecipient(client, key), /invalid signature/);
  server.close();
});
