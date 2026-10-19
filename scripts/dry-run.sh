#!/usr/bin/env bash
# envlockup dry run: encrypt a COPY of a real .env with a throwaway key and check
# that nothing changes. The original file is never modified, values are never
# printed, and everything is deleted on exit. When python3 or docker compose is
# available it also checks that python-decouple and docker compose read the
# file the same way envlockup does.
#
#   ./dry-run.sh /path/to/.env [envlockup package: npm name, tarball or git url]
set -euo pipefail

SRC="${1:?usage: $0 /path/to/.env [envlockup-package]}"
PKG="${2:-envlockup}"
[ -f "$SRC" ] || { echo "not a file: $SRC" >&2; exit 1; }
node -e 'const [a,b]=process.versions.node.split(".").map(Number);process.exit(a>22||(a===22&&b>=12)?0:1)' \
  || { echo "envlockup needs Node.js 22.12 or later (found $(node -v))" >&2; exit 1; }
command -v ssh-keygen >/dev/null || { echo "ssh-keygen is required" >&2; exit 1; }
[ -f "$PKG" ] && PKG="$(cd "$(dirname "$PKG")" && pwd)/$(basename "$PKG")"

umask 077
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
ORIG_SUM="$(sha256sum "$SRC" 2>/dev/null || shasum -a 256 "$SRC")"

echo "• Installing envlockup ($PKG) and dotenv into a temporary folder…"
npm install --silent --no-audit --no-fund --prefix "$WORK/pkg" "$PKG" >/dev/null
DOTENV=1
npm install --silent --no-audit --no-fund --prefix "$WORK/pkg" dotenv@16 >/dev/null 2>&1 || DOTENV=0
ENVLOCKUP="$WORK/pkg/node_modules/.bin/envlockup"

cp "$SRC" "$WORK/.env"
ssh-keygen -q -t ed25519 -N "" -C envlockup-dry-run -f "$WORK/key"
export ENVLOCKUP_IDENTITY="$WORK/key"
unset ENVLOCKUP_PRIVATE_KEY ENVLOCKUP_SSH_PASSPHRASE ENVLOCKUP_FILE

cat > "$WORK/check.mjs" <<'JS'
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
const [phase, work, hasDotenv] = process.argv.slice(2);
const require = createRequire(`${work}/pkg/`);
const { SealedEnv, load } = await import(require.resolve("envlockup"));
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
    console.log(diff.length ? `✗ envlockup and dotenv read these differently: ${names(diff)}` : "✓ envlockup reads the file exactly like dotenv");
    if (diff.length) process.exitCode = 3;
  } else {
    console.log("! dotenv could not be installed: parser comparison skipped");
  }
  const expand = Object.keys(ours).filter((k) => /\$\{?[A-Za-z_]/.test(ours[k]));
  if (expand.length) console.log(`! these look like \${VAR} references (dotenv-expand); envlockup does not expand them: ${names(expand)}`);
  // Comments are never encrypted: commented-out variables often hold old secrets.
  const commented = [];
  for (const line of text.split(/\r\n?|\n/)) {
    const m = /^\s*#\s*(?:export\s+)?([A-Za-z_][\w.-]*)\s*=/.exec(line);
    if (m && !line.startsWith("#envlockup:")) commented.push(m[1]);
  }
  if (commented.length) console.log(`! comments stay in plain text, and these look like commented-out variables: ${names(commented)}`);
} else if (phase === "compose-file") {
  // A compose file that interpolates every variable, to see what docker compose reads.
  const plain = JSON.parse(readFileSync(`${work}/plain.json`, "utf8"));
  const usable = Object.keys(plain).filter((k) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(k));
  const environment = Object.fromEntries(usable.map((k) => [k, `\${${k}}`]));
  writeFileSync(`${work}/compose/compose.yaml`, JSON.stringify({ services: { x: { image: "scratch", environment } } }));
} else if (phase === "compare") {
  // Compare envlockup's reading with another parser's (python-decouple, docker compose).
  const [label, path] = process.argv.slice(4);
  let ours = JSON.parse(readFileSync(`${work}/plain.json`, "utf8"));
  let theirs = JSON.parse(readFileSync(path, "utf8"));
  if (label === "docker compose") {
    // `config` writes a literal $ as $$; only names compose can interpolate are compared.
    theirs = Object.fromEntries(Object.entries(theirs.services.x.environment ?? {}).map(([k, v]) => [k, (v ?? "").replace(/\$\$/g, "$")]));
    ours = Object.fromEntries(Object.entries(ours).filter(([k]) => k in theirs));
  }
  const all = [...new Set([...Object.keys(ours), ...Object.keys(theirs)])];
  const diff = all.filter((k) => ours[k] !== theirs[k]);
  console.log(diff.length ? `✗ ${label} reads these differently from envlockup: ${names(diff)}` : `✓ ${label} reads all ${all.length} value(s) like envlockup`);
  if (diff.length) process.exitCode = 3;
} else {
  const plain = JSON.parse(readFileSync(`${work}/plain.json`, "utf8"));
  const sealedText = readFileSync(file, "utf8");
  const sealed = new SealedEnv(sealedText);
  const notEncrypted = sealed.entries().filter((e) => !e.encrypted).map((e) => e.name);

  // Where does a plaintext value still appear? Only "other" means envlockup left it visible.
  const lines = sealedText.split(/\r\n?|\n/);
  const entryAt = new Map();
  for (const e of sealed.entries()) for (let i = e.start; i <= e.end; i++) entryAt.set(i, e);
  const found = { comment: [], name: [], encrypted: [], other: [] };
  for (const [k, v] of Object.entries(plain)) {
    if (v.length < 4 || !sealedText.includes(v)) continue;
    const places = new Set();
    lines.forEach((line, i) => {
      if (!line.includes(v)) return;
      if (entryAt.has(i)) places.add(line.slice(0, line.indexOf("=")).includes(v) ? "name" : "encrypted");
      else if (line.startsWith("#envlockup:")) places.add("encrypted");
      else if (/^\s*#/.test(line)) places.add("comment");
      else places.add("other");
    });
    if (!places.size) places.add("other"); // spans several lines
    for (const p of places) found[p].push(k);
  }

  const decrypted = load({ path: file });
  const all = [...new Set([...Object.keys(plain), ...Object.keys(decrypted)])];
  const changed = all.filter((k) => plain[k] !== decrypted[k]);
  console.log(notEncrypted.length ? `✗ not encrypted: ${names(notEncrypted)}` : "✓ every value is encrypted");
  if (found.other.length) console.log(`✗ plaintext still visible in the file for: ${names(found.other)}`);
  if (found.comment.length) console.log(`! the value also appears in a comment, which is not encrypted: ${names(found.comment)}`);
  if (found.name.length) console.log(`! the value also appears in a variable name, which is not encrypted: ${names(found.name)}`);
  if (found.encrypted.length) console.log(`• the value appears by chance inside encrypted text (harmless): ${names(found.encrypted)}`);
  if (!found.other.length && !found.comment.length && !found.name.length) console.log("✓ no plaintext value appears in the encrypted file");
  console.log(changed.length ? `✗ decrypted values differ for: ${names(changed)}` : `✓ all ${all.length} value(s) decrypt back exactly`);
  if (notEncrypted.length || found.other.length || changed.length) process.exitCode = 4;
}
JS

node "$WORK/check.mjs" before "$WORK" "$DOTENV" || STATUS=$?

# Apps that read the .env with something other than dotenv see these values
# today; through `envlockup run` they would see envlockup's instead.
if command -v python3 >/dev/null && python3 -m venv "$WORK/py" >/dev/null 2>&1 \
  && "$WORK/py/bin/pip" install -q --disable-pip-version-check python-decouple >/dev/null 2>&1; then
  "$WORK/py/bin/python" -I -c 'import json, sys
from decouple import RepositoryEnv
json.dump(RepositoryEnv(sys.argv[1]).data, open(sys.argv[2], "w"))' "$WORK/.env" "$WORK/decouple.json"
  node "$WORK/check.mjs" compare "$WORK" "python-decouple" "$WORK/decouple.json" || STATUS=$?
else
  echo "! python3 or python-decouple not available: python-decouple comparison skipped"
fi
if docker compose version >/dev/null 2>&1; then
  mkdir "$WORK/compose"
  node "$WORK/check.mjs" compose-file "$WORK"
  # Its errors can quote the file, so they are not shown.
  if env -i PATH="$PATH" HOME="$HOME" docker compose --project-directory "$WORK/compose" -f "$WORK/compose/compose.yaml" \
    --env-file "$WORK/.env" config --format json >"$WORK/compose.json" 2>/dev/null; then
    node "$WORK/check.mjs" compare "$WORK" "docker compose" "$WORK/compose.json" || STATUS=$?
  else
    echo "✗ docker compose could not read the file (its error is hidden because it may quote values)"; STATUS=3
  fi
else
  echo "! docker compose not available: docker compose comparison skipped"
fi
"$ENVLOCKUP" -f "$WORK/.env" init 2>/dev/null >/dev/null
node "$WORK/check.mjs" after "$WORK" || STATUS=$?

# The same values must reach a child process through `envlockup run`.
RUN_OK="$(env -i PATH="$PATH" HOME="$HOME" ENVLOCKUP_IDENTITY="$WORK/key" "$ENVLOCKUP" -f "$WORK/.env" run -- \
  node -e 'const p=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));const bad=Object.keys(p).filter(k=>process.env[k]!==p[k]);console.log(bad.length?"✗ envlockup run passed wrong values for: "+bad.join(", "):"✓ envlockup run passes every value to the process")' "$WORK/plain.json")"
echo "$RUN_OK"
case "$RUN_OK" in ✗*) STATUS=5 ;; esac

TIME_MS="$(node -e 'const t=Date.now();require("child_process").execFileSync(process.argv[1],["-f",process.argv[2],"decrypt"],{stdio:"ignore"});console.log(Date.now()-t)' "$ENVLOCKUP" "$WORK/.env")"
echo "• decrypting the whole file takes ~${TIME_MS} ms (including Node.js startup)"

NOW_SUM="$(sha256sum "$SRC" 2>/dev/null || shasum -a 256 "$SRC")"
[ "$ORIG_SUM" = "$NOW_SUM" ] && echo "✓ the original file was not touched" || { echo "✗ the original file changed!"; STATUS=6; }

if [ "${STATUS:-0}" = 0 ]; then echo "Dry run passed. Temporary files deleted."; else echo "Dry run found problems (code ${STATUS}). Temporary files deleted."; fi
exit "${STATUS:-0}"
