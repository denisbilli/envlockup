import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { sshKey, tempDir } from "./helpers.js";

const CLI = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
const dir = tempDir();
const me = sshKey(dir, "me");
const repo = join(dir, "repo");
mkdirSync(repo);
const file = join(repo, ".env");
const inherited = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith("ENVLOCKUP_") && !k.startsWith("GIT_")));
const baseEnv = { ...inherited, HOME: dir, ENVLOCKUP_IDENTITY: me.path };

function cli(args, env = {}) {
  const r = spawnSync(process.execPath, [CLI, "-f", file, ...args], { env: { ...baseEnv, ...env }, cwd: repo, encoding: "utf8" });
  return { code: r.status, stderr: r.stderr };
}

function git(...args) {
  execFileSync("git", ["-c", "user.name=test", "-c", "user.email=test@example.com", ...args], { cwd: repo, stdio: "pipe" });
}

const commit = () => {
  git("add", ".env");
  git("commit", "-q", "-m", "update");
};

test("check: plaintext values must be new and allowed, or already plaintext in HEAD", () => {
  git("init", "-q");
  writeFileSync(file, "PORT=3000\nTOKEN=secret\n");
  assert.equal(cli(["init", "--keep-plain"]).code, 0);

  // Nothing committed yet: every plaintext value is new.
  let r = cli(["check"]);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /no earlier version of the file in HEAD/);
  assert.match(r.stderr, /PORT is a new plaintext value/);
  assert.match(r.stderr, /TOKEN is a new plaintext value/);
  assert.match(r.stderr, /--allow-plain/);

  r = cli(["check", "--allow-plain", "PORT"]);
  assert.equal(r.code, 1);
  assert.doesNotMatch(r.stderr, /PORT/);
  assert.equal(cli(["encrypt", "TOKEN"]).code, 0);
  assert.equal(cli(["check", "--allow-plain", "PORT"]).code, 0);
  commit();

  // PORT is plaintext in HEAD, so it no longer needs to be listed.
  assert.equal(cli(["check"]).code, 0);

  // A value added in an editor.
  writeFileSync(file, readFileSync(file, "utf8") + "DEBUG=1\n");
  r = cli(["check"]);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /DEBUG is a new plaintext value/);
  assert.equal(cli(["check", "--allow-plain", "LOG_LEVEL,DEBUG"]).code, 0);
  commit();

  // An encrypted value replaced by a plaintext one.
  writeFileSync(file, readFileSync(file, "utf8").replace(/^TOKEN=.*$/m, "TOKEN=leaked"));
  r = cli(["check"]);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /TOKEN is in plaintext, but is encrypted in HEAD/);
  git("checkout", "-q", ".env");
});

test("check: --base compares with another commit, and must exist", () => {
  writeFileSync(file, readFileSync(file, "utf8") + "EXTRA=1\n");
  commit();
  // EXTRA is plaintext in HEAD but not in HEAD~1 (what a pull request would compare against).
  assert.equal(cli(["check"]).code, 0);
  const r = cli(["check", "--base", "HEAD~1"]);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /EXTRA is a new plaintext value/);
  const bad = cli(["check", "--base", "no-such-branch"]);
  assert.equal(bad.code, 2);
  assert.match(bad.stderr, /no-such-branch is not a commit/);
});

test("check: values and the recipient list are checked when a key is available", () => {
  const good = readFileSync(file, "utf8");
  writeFileSync(file, good.replace(/^(TOKEN=envlockup:v1:.*).{4}$/m, "$1AAAA"));
  let r = cli(["check"]);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /TOKEN: cannot decrypt/);

  const other = sshKey(dir, "other");
  writeFileSync(file, good.replace(/^(#envlockup:mac .*)$/m, `#envlockup:recipient ${other.public.split(" ").slice(0, 2).join(" ")} AAAA AAAA AAAA\n$1`));
  r = cli(["check"]);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /recipient list was changed/);

  // Without a key, the rest is still checked, and the output says what wasn't.
  writeFileSync(file, good);
  r = cli(["check"], { ENVLOCKUP_IDENTITY: "", SSH_AUTH_SOCK: "" });
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stderr, /not checked whether the file decrypts/);
});

test("check: a file that doesn't use envlockup fails", () => {
  const plain = join(repo, "plain.env");
  writeFileSync(plain, "A=1\n");
  const r = spawnSync(process.execPath, [CLI, "-f", plain, "check", "--allow-plain", "A"], { env: baseEnv, cwd: repo, encoding: "utf8" });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /does not use envlockup/);
});

test("init names the .gitignore line that still excludes the file", () => {
  const project = join(dir, "ignored");
  mkdirSync(project);
  execFileSync("git", ["init", "-q"], { cwd: project });
  writeFileSync(join(project, ".gitignore"), "node_modules\n.env\n");
  writeFileSync(join(project, ".env"), "TOKEN=secret\n");
  const r = spawnSync(process.execPath, [CLI, "-f", join(project, ".env"), "init"], { env: baseEnv, cwd: project, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /Git still ignores it: line 2 of \.gitignore \("\.env"\)/);
  assert.doesNotMatch(r.stderr, /earlier commit/);
});

test("init warns when the file is already in git history unencrypted", () => {
  const project = join(dir, "history");
  mkdirSync(project);
  const g = (...a) => execFileSync("git", ["-c", "user.name=test", "-c", "user.email=test@example.com", ...a], { cwd: project, stdio: "pipe" });
  g("init", "-q");
  writeFileSync(join(project, ".env"), "TOKEN=secret\n");
  g("add", ".env");
  g("commit", "-q", "-m", "one");
  writeFileSync(join(project, ".env"), "TOKEN=secret2\n");
  g("commit", "-q", "-am", "two");
  const r = spawnSync(process.execPath, [CLI, "-f", join(project, ".env"), "init"], { env: baseEnv, cwd: project, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /already in 2 earlier commit\(s\), unencrypted.*Rotate those secrets/s);
  assert.doesNotMatch(r.stderr, /Git still ignores it/);
});
