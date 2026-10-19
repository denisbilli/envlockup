// Every error a new user is likely to hit says what to do next.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { parseIdentity, parseRecipient } from "../dist/keys.js";
import { SealedEnv } from "../dist/vault.js";
import { sshKey, tempDir } from "./helpers.js";

const CLI = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
const dir = tempDir();
const me = sshKey(dir, "me");
const outsider = sshKey(dir, "outsider");
const locked = sshKey(dir, "locked", "pw");
const file = join(dir, ".env");
const inherited = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith("ENVLOCKUP_") && k !== "SSH_AUTH_SOCK"));
const baseEnv = { ...inherited, HOME: dir, USERPROFILE: dir, ENVLOCKUP_IDENTITY: me.path };

function cli(args, env = {}) {
  const r = spawnSync(process.execPath, [CLI, "-f", file, ...args], { env: { ...baseEnv, ...env }, encoding: "utf8" });
  return { code: r.status, stderr: r.stderr };
}

function cliAsync(args, env = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, "-f", file, ...args], { env: { ...baseEnv, ...env } });
    let stderr = "";
    child.stderr.on("data", (d) => (stderr += d));
    child.on("close", (code) => resolve({ code, stderr }));
  });
}

writeFileSync(file, "TOKEN=secret\n");
assert.equal(cli(["init"]).code, 0);
assert.equal(cli(["add", `${locked.path}.pub`]).code, 0);

test("not a recipient: prints the exact add command", () => {
  const r = cli(["get", "TOKEN"], { ENVLOCKUP_IDENTITY: outsider.path });
  assert.equal(r.code, 1);
  const line = r.stderr.match(/npx envlockup add "(ssh-ed25519 \S+)/);
  assert.ok(line, r.stderr);
  assert.equal(line[1], outsider.public.split(" ").slice(0, 2).join(" "));
  // The printed command works as is.
  const env = new SealedEnv("A=1\n");
  env.init([parseRecipient(me.public)]);
  env.addRecipient(parseRecipient(line[1]));
  new SealedEnv(env.toString()).unlock(parseIdentity(outsider.private, "outsider"));
});

test("passphrase without a terminal: says how to avoid it", () => {
  const r = cli(["get", "TOKEN"], { ENVLOCKUP_IDENTITY: locked.path });
  assert.match(r.stderr, /ENVLOCKUP_SSH_PASSPHRASE.*envlockup add --agent/s);
});

test("no key, with an RSA or ECDSA key file: says why it isn't used", () => {
  for (const [name, expected] of [
    ["id_rsa", /id_rsa is an RSA key file.*ssh-add.*pubkey --agent/s],
    ["id_ecdsa", /id_ecdsa is an ECDSA key.*ssh-keygen -t ed25519/s],
  ]) {
    const home = tempDir();
    mkdirSync(join(home, ".ssh"));
    writeFileSync(join(home, ".ssh", name), "not read\n");
    const r = cli(["get", "TOKEN"], { HOME: home, USERPROFILE: home, ENVLOCKUP_IDENTITY: "" });
    assert.match(r.stderr, expected);
  }
});

test("adding an RSA or ECDSA public key: explains the alternative", () => {
  assert.match(cli(["add", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC bob@laptop"]).stderr, /ssh-rsa public keys can't be added yet.*pubkey --agent/s);
  assert.match(cli(["add", "ecdsa-sha2-nistp256 AAAAE2VjZHNh bob@laptop"]).stderr, /ECDSA keys can't be used/);
});

test("@user: unknown user, and a user with only RSA keys", async () => {
  const server = createServer((req, res) => {
    if (req.url === "/rsa-only.keys") return res.end("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC\n");
    res.statusCode = 404;
    res.end("Not Found");
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const env = { ENVLOCKUP_GITHUB_KEYS_URL: `http://127.0.0.1:${server.address().port}/{user}.keys` };
  try {
    assert.match((await cliAsync(["add", "@nobody"], env)).stderr, /GitHub user @nobody not found/);
    assert.match((await cliAsync(["add", "@rsa-only"], env)).stderr, /no ssh-ed25519 keys on GitHub \(only ssh-rsa\).*pubkey --agent/s);
  } finally {
    server.close();
  }
});

test("a mistyped command suggests the closest one", () => {
  const r = cli(["sett", "X"]);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /unknown command "sett"\. Did you mean "set"\?/);
  assert.doesNotMatch(cli(["frobnicate"]).stderr, /Did you mean/);
});

test("a value that doesn't decrypt mentions the merge case", () => {
  const env = new SealedEnv("A=1\n");
  env.init([parseRecipient(me.public)]);
  const other = new SealedEnv("A=2\n");
  other.init([parseRecipient(me.public)]);
  // A value encrypted under another data key, as after a remove merged with a set.
  const mixed = env.toString().replace(/^A=.*$/m, other.toString().match(/^A=.*$/m)[0]);
  assert.throws(() => new SealedEnv(mixed).unlock(parseIdentity(me.private, "me")), /another branch \(a `remove` merged with a `set`\)/);
});
