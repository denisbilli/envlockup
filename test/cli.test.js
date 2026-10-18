import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { sshKey, tempDir } from "./helpers.js";

const CLI = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
const dir = tempDir();
const me = sshKey(dir, "me");
const locked = sshKey(dir, "locked", "pw");
const file = join(dir, ".env");
const inherited = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith("ENVSEAL_")));
const baseEnv = { ...inherited, HOME: dir, ENVSEAL_IDENTITY: me.path };

function cli(args, { env = {}, input } = {}) {
  const r = spawnSync(process.execPath, [CLI, "-f", file, ...args], { env: { ...baseEnv, ...env }, input, encoding: "utf8" });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

test("init, set, get, ls, decrypt", () => {
  writeFileSync(file, "PORT=3000\nTOKEN=plain-secret\n");
  assert.equal(cli(["init"]).code, 0);
  assert.doesNotMatch(readFileSync(file, "utf8"), /plain-secret/);
  assert.equal(cli(["set", "PASSWORD"], { input: "from stdin\n" }).code, 0);
  assert.equal(cli(["set", "MODE", "dev", "--plain"]).code, 0);
  assert.equal(cli(["get", "PASSWORD"]).stdout, "from stdin\n");
  assert.equal(cli(["get", "TOKEN"]).stdout, "plain-secret\n");
  assert.match(cli(["ls"]).stdout, /🔒 PORT\n🔒 TOKEN\n🔒 PASSWORD\n   MODE/);
  assert.match(cli(["decrypt"]).stdout, /^TOKEN="plain-secret"$/m);
  assert.equal(cli(["get", "NOPE"]).code, 1);
});

test("run injects variables and hides the private key from the child", () => {
  const script = "console.log(JSON.stringify([process.env.TOKEN, process.env.PORT, process.env.ENVSEAL_PRIVATE_KEY ?? null]))";
  const keyText = readFileSync(me.path, "utf8");
  const r = cli(["run", "--", process.execPath, "-e", script], { env: { ENVSEAL_IDENTITY: "", ENVSEAL_PRIVATE_KEY: keyText, PORT: "9999" } });
  assert.equal(r.code, 0, r.stderr);
  // Existing variables win unless --override.
  assert.deepEqual(JSON.parse(r.stdout), ["plain-secret", "9999", null]);
  const o = cli(["run", "--override", "--", process.execPath, "-e", script], { env: { PORT: "9999" } });
  assert.equal(JSON.parse(o.stdout)[1], "3000");
});

test("run propagates the exit code", () => {
  assert.equal(cli(["run", "--", process.execPath, "-e", "process.exit(7)"]).code, 7);
});

test("import 'envseal/config' loads the file", () => {
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", `import ${JSON.stringify(new URL("../dist/config.js", import.meta.url).href)}; console.log(process.env.PASSWORD, process.env.ENVSEAL_PRIVATE_KEY ?? "gone")`], {
    cwd: dir,
    env: { ...baseEnv, ENVSEAL_IDENTITY: "", ENVSEAL_PRIVATE_KEY: readFileSync(me.path, "utf8").replace(/\n/g, "\\n") },
    encoding: "utf8",
  });
  assert.equal(r.stdout, "from stdin gone\n", r.stderr);
});

test("add from a .pub file, keygen for CI, remove", () => {
  assert.equal(cli(["add", `${locked.path}.pub`]).code, 0);
  assert.equal(cli(["get", "TOKEN"], { env: { ENVSEAL_IDENTITY: locked.path, ENVSEAL_SSH_PASSPHRASE: "pw" } }).stdout, "plain-secret\n");
  assert.match(cli(["get", "TOKEN"], { env: { ENVSEAL_IDENTITY: locked.path } }).stderr, /passphrase/);

  const kg = cli(["keygen", "--label", "github-actions"]);
  assert.equal(kg.code, 0, kg.stderr);
  const secret = kg.stdout.trim();
  assert.match(secret, /^AGE-SECRET-KEY-1/);
  assert.equal(cli(["get", "PORT"], { env: { ENVSEAL_IDENTITY: "", ENVSEAL_PRIVATE_KEY: secret, HOME: "/nonexistent" } }).stdout, "3000\n");

  assert.match(cli(["recipients"]).stdout, /^1\. SHA256:\S+  ssh-ed25519  me@test\n2\. .*locked@test\n3\. .*age  github-actions\n$/);
  assert.equal(cli(["remove", "github-actions"]).code, 0);
  assert.match(cli(["get", "PORT"], { env: { ENVSEAL_IDENTITY: "", ENVSEAL_PRIVATE_KEY: secret, HOME: "/nonexistent" } }).stderr, /not encrypted for your key/);
});

test("add @github-user fetches ed25519 keys", async () => {
  const friend = sshKey(dir, "friend");
  const server = createServer((req, res) => {
    if (req.url === "/friend.keys") res.end(`ssh-rsa AAAAB3NzaC1yc2E= ignored\n${friend.public.split(" ").slice(0, 2).join(" ")}\n`);
    else res.writeHead(404).end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${server.address().port}/{user}.keys`;
  const run = (args) => new Promise((resolve) => {
    import("node:child_process").then(({ execFile }) =>
      execFile(process.execPath, [CLI, "-f", file, ...args], { env: { ...baseEnv, ENVSEAL_GITHUB_KEYS_URL: url } }, (err, stdout, stderr) =>
        resolve({ code: err ? err.code : 0, stdout, stderr })));
  });
  const r = await run(["add", "@friend"]);
  server.close();
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stderr, /Added SHA256:\S+  ssh-ed25519  @friend/);
  assert.equal(cli(["get", "PORT"], { env: { ENVSEAL_IDENTITY: friend.path } }).stdout, "3000\n");
});

test("usage errors exit with 2", () => {
  assert.equal(cli(["bogus"]).code, 2);
  assert.equal(cli(["run"]).code, 2);
  assert.match(execFileSync(process.execPath, [CLI, "--version"]).toString(), /^\d+\.\d+\.\d+/);
});
