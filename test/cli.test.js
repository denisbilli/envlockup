import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { chmodSync, lstatSync, mkdirSync, readFileSync, readdirSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import dotenv from "dotenv";
import { sshKey, tempDir } from "./helpers.js";

const CLI = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
const dir = tempDir();
const me = sshKey(dir, "me");
const locked = sshKey(dir, "locked", "pw");
const file = join(dir, ".env");
const inherited = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith("ENVLOCKUP_")));
const baseEnv = { ...inherited, HOME: dir, ENVLOCKUP_IDENTITY: me.path };

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
  assert.match(cli(["decrypt"]).stdout, /^TOKEN=plain-secret$/m);
  assert.equal(cli(["get", "NOPE"]).code, 1);
});

test("get prints a large value in full into a slow pipe", { skip: process.platform === "win32" && "POSIX shell" }, () => {
  const big = join(dir, "big.env");
  const value = "x".repeat(300_000);
  writeFileSync(big, `BIG=${value}\n`);
  execFileSync(process.execPath, [CLI, "-f", big, "init"], { env: baseEnv });
  // the reader starts late, so the 64 KB pipe buffer fills up while envlockup is still writing
  const cmd = `"${process.execPath}" "${CLI}" -f "${big}" get BIG | (sleep 1; wc -c)`;
  const r = spawnSync("sh", ["-c", cmd], { env: baseEnv, encoding: "utf8" });
  assert.equal(Number(r.stdout.trim()), value.length + 1);
});

test("run injects variables and hides the private key from the child", () => {
  const script = "console.log(JSON.stringify([process.env.TOKEN, process.env.PORT, process.env.ENVLOCKUP_PRIVATE_KEY ?? null]))";
  const keyText = readFileSync(me.path, "utf8");
  const r = cli(["run", "--", process.execPath, "-e", script], { env: { ENVLOCKUP_IDENTITY: "", ENVLOCKUP_PRIVATE_KEY: keyText, PORT: "9999" } });
  assert.equal(r.code, 0, r.stderr);
  // Existing variables win unless --override.
  assert.deepEqual(JSON.parse(r.stdout), ["plain-secret", "9999", null]);
  const o = cli(["run", "--override", "--", process.execPath, "-e", script], { env: { PORT: "9999" } });
  assert.equal(JSON.parse(o.stdout)[1], "3000");
});

test("run propagates the exit code", () => {
  assert.equal(cli(["run", "--", process.execPath, "-e", "process.exit(7)"]).code, 7);
});

// What cmd.exe would otherwise change: metacharacters, variables, quotes, carets,
// trailing backslashes and empty arguments.
const TRICKY_ARGS = ["a&b", "50%", "%PATH%", "x^y", 'say "hi"', 'q"&"q', "back\\slash\\", "with space", "", "!bang!", "(p)", "a|b", "<lt>", "semi;colon", "comma,", "star*", "q?"];

test("run passes arguments unchanged on Windows: programs, .cmd scripts, npm shims", { skip: process.platform !== "win32" && "Windows only" }, () => {
  const printer = join(dir, "argv.js");
  writeFileSync(printer, "console.log(JSON.stringify(process.argv.slice(2)))\n");
  const direct = cli(["run", "--", process.execPath, printer, ...TRICKY_ARGS]);
  assert.deepEqual(JSON.parse(direct.stdout), TRICKY_ARGS, direct.stderr);
  for (const sub of ["scripts", join("node_modules", ".bin")]) {
    mkdirSync(join(dir, sub), { recursive: true });
    const script = join(dir, sub, "argv.cmd");
    writeFileSync(script, `@"${process.execPath}" "${printer}" %*\r\n`);
    const r = cli(["run", "--", script, ...TRICKY_ARGS]);
    assert.deepEqual(JSON.parse(r.stdout), TRICKY_ARGS, `${sub}: ${r.stderr}`);
  }
  // A cmd.exe built-in still works.
  assert.match(cli(["run", "--", "echo", "hello"]).stdout, /hello/);
});

test("import 'envlockup/config' loads the file", () => {
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", `import ${JSON.stringify(new URL("../dist/config.js", import.meta.url).href)}; console.log(process.env.PASSWORD, process.env.ENVLOCKUP_PRIVATE_KEY ?? "gone")`], {
    cwd: dir,
    env: { ...baseEnv, ENVLOCKUP_IDENTITY: "", ENVLOCKUP_PRIVATE_KEY: readFileSync(me.path, "utf8").replace(/\n/g, "\\n") },
    encoding: "utf8",
  });
  assert.equal(r.stdout, "from stdin gone\n", r.stderr);
});

test("add from a .pub file, keygen for CI, remove", () => {
  assert.equal(cli(["add", `${locked.path}.pub`]).code, 0);
  assert.equal(cli(["get", "TOKEN"], { env: { ENVLOCKUP_IDENTITY: locked.path, ENVLOCKUP_SSH_PASSPHRASE: "pw" } }).stdout, "plain-secret\n");
  assert.match(cli(["get", "TOKEN"], { env: { ENVLOCKUP_IDENTITY: locked.path } }).stderr, /passphrase/);

  const kg = cli(["keygen", "--label", "github-actions"]);
  assert.equal(kg.code, 0, kg.stderr);
  const secret = kg.stdout.trim();
  assert.match(secret, /^AGE-SECRET-KEY-1/);
  assert.equal(cli(["get", "PORT"], { env: { ENVLOCKUP_IDENTITY: "", ENVLOCKUP_PRIVATE_KEY: secret, HOME: "/nonexistent" } }).stdout, "3000\n");

  assert.match(cli(["recipients"]).stdout, /^1\. SHA256:\S+  ssh-ed25519  me@test\n2\. .*locked@test\n3\. .*age  github-actions\n$/);
  const refused = cli(["remove", "github-actions"]);
  assert.equal(refused.code, 2);
  assert.match(refused.stderr, /will be readable by:\n.*me@test\n.*locked@test\n/);
  assert.match(cli(["recipients"]).stdout, /github-actions/);
  assert.equal(cli(["remove", "github-actions", "--yes"]).code, 0);
  assert.match(cli(["get", "PORT"], { env: { ENVLOCKUP_IDENTITY: "", ENVLOCKUP_PRIVATE_KEY: secret, HOME: "/nonexistent" } }).stderr, /not encrypted for your key/);
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
      execFile(process.execPath, [CLI, "-f", file, ...args], { env: { ...baseEnv, ENVLOCKUP_GITHUB_KEYS_URL: url } }, (err, stdout, stderr) =>
        resolve({ code: err ? err.code : 0, stdout, stderr })));
  });
  const r = await run(["add", "@friend"]);
  server.close();
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stderr, /Added SHA256:\S+  ssh-ed25519  @friend/);
  assert.equal(cli(["get", "PORT"], { env: { ENVLOCKUP_IDENTITY: friend.path } }).stdout, "3000\n");
});

test("remove @user removes every key of that user", async () => {
  const k1 = sshKey(dir, "two1");
  const k2 = sshKey(dir, "two2");
  const server = createServer((req, res) => res.end(`${k1.public}\n${k2.public}\n`));
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${server.address().port}/{user}.keys`;
  const r = await new Promise((resolve) =>
    import("node:child_process").then(({ execFile }) =>
      execFile(process.execPath, [CLI, "-f", file, "add", "@two"], { env: { ...baseEnv, ENVLOCKUP_GITHUB_KEYS_URL: url } }, (err, stdout, stderr) =>
        resolve({ code: err ? err.code : 0, stderr }))));
  server.close();
  assert.equal(r.code, 0, r.stderr);
  assert.equal(cli(["recipients"]).stdout.match(/@two/g).length, 2);
  assert.equal(cli(["remove", "@two", "--yes"]).code, 0);
  assert.doesNotMatch(cli(["recipients"]).stdout, /@two/);
  for (const k of [k1, k2]) assert.match(cli(["get", "PORT"], { env: { ENVLOCKUP_IDENTITY: k.path } }).stderr, /not encrypted for your key/);
});

test("a recipient line added without the key stops the file until it is accepted", () => {
  const other = sshKey(dir, "unsigned");
  const signed = readFileSync(file, "utf8");
  // What a merge or a hand edit leaves behind: a new line, the old mac.
  assert.equal(cli(["add", other.path.replace(/$/, ".pub")]).code, 0);
  const added = readFileSync(file, "utf8").split("\n").find((l) => l.endsWith(" unsigned@test"));
  writeFileSync(file, signed.replace(/^(#envlockup:mac .*)$/m, `${added}\n$1`));
  const r = cli(["get", "PORT"]);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /recipient list was changed .*envlockup recipients --accept/s);
  const noTty = cli(["recipients", "--accept"]);
  assert.equal(noTty.code, 2);
  assert.match(noTty.stderr, /unsigned@test[\s\S]*--yes/);
  assert.equal(cli(["recipients", "--accept", "--yes"]).code, 0);
  assert.equal(cli(["get", "PORT"]).stdout, "3000\n");
  assert.match(cli(["recipients", "--accept"]).stderr, /already signed/);
  assert.equal(cli(["remove", "unsigned@test", "--yes"]).code, 0);
});

test("ENVLOCKUP_GITHUB_KEYS_URL must point to localhost", () => {
  const r = cli(["add", "@someone"], { env: { ENVLOCKUP_GITHUB_KEYS_URL: "https://evil.example/{user}.keys" } });
  assert.equal(r.code, 1);
  assert.match(r.stderr, /only for tests/);
});

test("decrypt prints dotenv that dotenv reads back unchanged", () => {
  const value = 'pa"ss\\word\twith \'quotes\' and\nnewline';
  assert.equal(cli(["set", "TRICKY"], { input: value }).code, 0);
  const expected = JSON.parse(cli(["decrypt", "--format", "json"]).stdout);
  assert.equal(expected.TRICKY, value);
  assert.deepEqual(dotenv.parse(cli(["decrypt"]).stdout), expected);
  assert.equal(cli(["set", "MIXED"], { input: "' \" `" }).code, 0);
  const r = cli(["decrypt"]);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /MIXED cannot be written in dotenv syntax/);
  assert.equal(r.stdout, "");
  assert.equal(cli(["unset", "MIXED"]).code, 0);
});

test("writes keep permissions, follow symlinks and leave no temp files", { skip: process.platform === "win32" && "POSIX permissions and symlinks" }, () => {
  const d = tempDir();
  const real = join(d, "shared.env");
  const link = join(d, ".env");
  writeFileSync(real, "A=1\n");
  chmodSync(real, 0o600);
  symlinkSync(real, link);
  const r = spawnSync(process.execPath, [CLI, "-f", link, "init"], { env: baseEnv, encoding: "utf8" });
  assert.equal(r.code ?? r.status, 0, r.stderr);
  assert.ok(lstatSync(link).isSymbolicLink());
  assert.ok(readFileSync(real, "utf8").startsWith("#envlockup:v1"));
  assert.equal(statSync(real).mode & 0o777, 0o600);
  assert.deepEqual(readdirSync(d).sort(), [".env", "shared.env"]);
});

test("usage errors exit with 2", () => {
  assert.equal(cli(["bogus"]).code, 2);
  assert.equal(cli(["run"]).code, 2);
  assert.match(execFileSync(process.execPath, [CLI, "--version"]).toString(), /^\d+\.\d+\.\d+/);
});
