// Runs the README's quick start exactly as written, then checks that the
// teammate added in it can read the file with their own key.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { sshKey, tempDir } from "./helpers.js";

const CLI = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");

function quickstart() {
  const block = readme.match(/<!-- quickstart[^>]*-->\s*```sh\n([\s\S]*?)```\s*<!-- \/quickstart -->/);
  assert.ok(block, "README has a quickstart block");
  return block[1]
    .split("\n")
    .map((l) => l.replace(/\s+#.*$/, "").trim())
    .filter(Boolean);
}

function run(args, { cwd, env, input = "" }) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { cwd, env, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(input);
  });
}

test("the README quick start works, including the second person", async () => {
  const home = tempDir();
  mkdirSync(join(home, ".ssh"));
  sshKey(home, join(".ssh", "id_ed25519"));
  const teammate = sshKey(home, "teammate");
  const project = join(home, "project");
  mkdirSync(project);
  writeFileSync(join(project, ".env"), "DATABASE_URL=postgres://app:secret@db/app\n");
  writeFileSync(join(project, "server.js"), "console.log(process.env.STRIPE_KEY, process.env.LOG_LEVEL)\n");

  const server = createServer((req, res) => res.end(req.url === "/octocat.keys" ? `${teammate.public}\n` : ""));
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const inherited = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith("ENVLOCKUP_") && k !== "SSH_AUTH_SOCK"));
  const env = {
    ...inherited,
    HOME: home,
    USERPROFILE: home,
    ENVLOCKUP_GITHUB_KEYS_URL: `http://127.0.0.1:${server.address().port}/{user}.keys`,
  };

  try {
    const commands = quickstart();
    assert.ok(commands.some((c) => c.startsWith("npx envlockup add @")), "the quick start adds a teammate");
    let last;
    for (const line of commands) {
      if (!line.startsWith("npx envlockup ")) continue; // npm install, git add
      const args = line.slice("npx envlockup ".length).split(/\s+/);
      last = await run(args, { cwd: project, env, input: "sk_test_123\n" });
      assert.equal(last.code, 0, `${line}\n${last.stderr}`);
    }
    // The last command is `run -- node server.js`.
    assert.equal(last.stdout.trim(), "sk_test_123 debug");
    assert.doesNotMatch(readFileSync(join(project, ".env"), "utf8"), /secret@db|sk_test_123/);

    const theirs = await run(["get", "STRIPE_KEY"], { cwd: project, env: { ...env, ENVLOCKUP_IDENTITY: teammate.path } });
    assert.equal(theirs.stdout, "sk_test_123\n", theirs.stderr);
  } finally {
    server.close();
  }
});
