#!/usr/bin/env bash
# envseal dry run: encrypt a COPY of a real .env with a throwaway key and check
# that nothing changes. The original file is never modified, values are never
# printed, and everything is deleted on exit.
#
#   ./dry-run.sh /path/to/.env [envseal package: npm name, tarball or git url]
set -euo pipefail

SRC="${1:?usage: $0 /path/to/.env [envseal-package]}"
PKG="${2:-envseal}"
[ -f "$SRC" ] || { echo "not a file: $SRC" >&2; exit 1; }
node -e 'const [a,b]=process.versions.node.split(".").map(Number);process.exit(a>22||(a===22&&b>=12)?0:1)' \
  || { echo "envseal needs Node.js 22.12 or later (found $(node -v))" >&2; exit 1; }
command -v ssh-keygen >/dev/null || { echo "ssh-keygen is required" >&2; exit 1; }
[ -f "$PKG" ] && PKG="$(cd "$(dirname "$PKG")" && pwd)/$(basename "$PKG")"

umask 077
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
ORIG_SUM="$(sha256sum "$SRC" 2>/dev/null || shasum -a 256 "$SRC")"

echo "• Installing envseal ($PKG) and dotenv into a temporary folder…"
npm install --silent --no-audit --no-fund --prefix "$WORK/pkg" "$PKG" >/dev/null
DOTENV=1
npm install --silent --no-audit --no-fund --prefix "$WORK/pkg" dotenv@16 >/dev/null 2>&1 || DOTENV=0
ENVSEAL="$WORK/pkg/node_modules/.bin/envseal"

cp "$SRC" "$WORK/.env"
ssh-keygen -q -t ed25519 -N "" -C envseal-dry-run -f "$WORK/key"
export ENVSEAL_IDENTITY="$WORK/key"
unset ENVSEAL_PRIVATE_KEY ENVSEAL_SSH_PASSPHRASE ENVSEAL_FILE

cat > "$WORK/check.mjs" <<'JS'
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
const [phase, work, hasDotenv] = process.argv.slice(2);
const require = createRequire(`${work}/pkg/`);
const { SealedEnv, load } = await import(require.resolve("envseal"));
const file = `${work}/.env`;
const names = (xs) => (xs.length ? xs.join(", ") : "none");

if (phase === "before") {
  const text = readFileSync(file, "utf8");
  const ours = new SealedEnv(text).decryptAll();
  writeFileSync(`${work}/plain.json`, JSON.stringify(ours));
  const n = Object.keys(ours).length;
  console.log(`• ${n} variable(s) found`);
  if (hasDotenv === "1") {
    const theirs = require("dotenv").parse(text);
    const all = [...new Set([...Object.keys(ours), ...Object.keys(theirs)])];
    const diff = all.filter((k) => ours[k] !== theirs[k]);
    console.log(diff.length ? `✗ envseal and dotenv read these differently: ${names(diff)}` : "✓ envseal reads the file exactly like dotenv");
    if (diff.length) process.exitCode = 3;
  } else {
    console.log("! dotenv could not be installed: parser comparison skipped");
  }
  const expand = Object.keys(ours).filter((k) => /\$\{?[A-Za-z_]/.test(ours[k]));
  if (expand.length) console.log(`! these look like \${VAR} references (dotenv-expand); envseal does not expand them: ${names(expand)}`);
} else {
  const plain = JSON.parse(readFileSync(`${work}/plain.json`, "utf8"));
  const sealedText = readFileSync(file, "utf8");
  const sealed = new SealedEnv(sealedText);
  const notEncrypted = sealed.entries().filter((e) => !e.encrypted).map((e) => e.name);
  const leaked = Object.entries(plain).filter(([, v]) => v.length >= 4 && sealedText.includes(v)).map(([k]) => k);
  const decrypted = load({ path: file });
  const all = [...new Set([...Object.keys(plain), ...Object.keys(decrypted)])];
  const changed = all.filter((k) => plain[k] !== decrypted[k]);
  console.log(notEncrypted.length ? `✗ not encrypted: ${names(notEncrypted)}` : "✓ every value is encrypted");
  console.log(leaked.length ? `✗ plaintext still visible in the file for: ${names(leaked)}` : "✓ no plaintext value appears in the encrypted file");
  console.log(changed.length ? `✗ decrypted values differ for: ${names(changed)}` : `✓ all ${all.length} value(s) decrypt back exactly`);
  if (notEncrypted.length || leaked.length || changed.length) process.exitCode = 4;
}
JS

node "$WORK/check.mjs" before "$WORK" "$DOTENV" || STATUS=$?
"$ENVSEAL" -f "$WORK/.env" init 2>/dev/null >/dev/null
node "$WORK/check.mjs" after "$WORK" || STATUS=$?

# The same values must reach a child process through `envseal run`.
RUN_OK="$(env -i PATH="$PATH" HOME="$HOME" ENVSEAL_IDENTITY="$WORK/key" "$ENVSEAL" -f "$WORK/.env" run -- \
  node -e 'const p=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));const bad=Object.keys(p).filter(k=>process.env[k]!==p[k]);console.log(bad.length?"✗ envseal run passed wrong values for: "+bad.join(", "):"✓ envseal run passes every value to the process")' "$WORK/plain.json")"
echo "$RUN_OK"
case "$RUN_OK" in ✗*) STATUS=5 ;; esac

TIME_MS="$(node -e 'const t=Date.now();require("child_process").execFileSync(process.argv[1],["-f",process.argv[2],"decrypt"],{stdio:"ignore"});console.log(Date.now()-t)' "$ENVSEAL" "$WORK/.env")"
echo "• decrypting the whole file takes ~${TIME_MS} ms (including Node.js startup)"

NOW_SUM="$(sha256sum "$SRC" 2>/dev/null || shasum -a 256 "$SRC")"
[ "$ORIG_SUM" = "$NOW_SUM" ] && echo "✓ the original file was not touched" || { echo "✗ the original file changed!"; STATUS=6; }

if [ "${STATUS:-0}" = 0 ]; then echo "Dry run passed. Temporary files deleted."; else echo "Dry run found problems (code ${STATUS}). Temporary files deleted."; fi
exit "${STATUS:-0}"
