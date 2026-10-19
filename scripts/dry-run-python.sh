#!/usr/bin/env bash
# envlockup dry run for Python apps, without Node.js: check that envlockup
# reads a COPY of a real .env exactly as python-decouple does, and that
# `python -m envlockup run` passes every value on. The original file is never
# modified, values are never printed, and everything is deleted on exit.
# (Encryption itself is covered by the shared test vectors.)
#
#   ./dry-run-python.sh /path/to/.env [envlockup: wheel, sdist or requirement]
#
# Set PYTHON to choose the interpreter (default: python3).
set -euo pipefail

SRC="${1:?usage: $0 /path/to/.env [envlockup package]}"
PKG="${2:-envlockup}"
PY="${PYTHON:-python3}"
[ -f "$SRC" ] || { echo "not a file: $SRC" >&2; exit 1; }
"$PY" -c 'import sys; sys.exit(sys.version_info < (3, 10))' \
  || { echo "envlockup needs Python 3.10 or later (found $("$PY" -V 2>&1))" >&2; exit 1; }
[ -f "$PKG" ] && PKG="$(cd "$(dirname "$PKG")" && pwd)/$(basename "$PKG")"

umask 077
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
ORIG_SUM="$(sha256sum "$SRC" 2>/dev/null || shasum -a 256 "$SRC")"

echo "• Installing envlockup ($PKG) and python-decouple into a temporary virtualenv…"
"$PY" -m venv "$WORK/venv" >/dev/null 2>&1 \
  || { echo "$PY -m venv failed (on Debian and Ubuntu, install the python3-venv package)" >&2; exit 1; }
VPY="$WORK/venv/bin/python"
"$VPY" -m pip install -q --disable-pip-version-check "$PKG" python-decouple >/dev/null
cp "$SRC" "$WORK/.env"

cat > "$WORK/check.py" <<'PY'
import json, re, subprocess, sys
from pathlib import Path

import envlockup
from decouple import RepositoryEnv

work = Path(sys.argv[1])
file = work / ".env"
names = lambda xs: ", ".join(xs) if xs else "none"
status = 0

ours = envlockup.load(file)
print(f"• {len(ours)} variable(s) found (envlockup {envlockup.__version__})")
encrypted = [k for k, v in ours.items() if v.startswith("envlockup:v1:")]
if encrypted:
    print(f"! these are already envlockup-encrypted, compared as ciphertext: {names(encrypted)}")

theirs = RepositoryEnv(str(file)).data
diff = [k for k in dict.fromkeys([*ours, *theirs]) if ours.get(k) != theirs.get(k)]
if diff:
    print(f"✗ python-decouple reads these differently from envlockup: {names(diff)}")
    status = 3
else:
    print(f"✓ python-decouple reads all {len(ours)} value(s) like envlockup")

expand = [k for k, v in ours.items() if re.search(r"\$\{?[A-Za-z_]", v)]
if expand:
    print(f"! these look like ${{VAR}} references; envlockup does not expand them: {names(expand)}")
commented = []
for line in file.read_text(encoding="utf-8", errors="replace").splitlines():
    m = re.match(r"\s*#\s*(?:export\s+)?([A-Za-z_][\w.-]*)\s*=", line)
    if m and not line.startswith("#envlockup:"):
        commented.append(m.group(1))
if commented:
    print(f"! comments stay in plain text, and these look like commented-out variables: {names(commented)}")

# The same values must reach a child process through `python -m envlockup run`.
(work / "plain.json").write_text(json.dumps(ours), encoding="utf-8")
child = (
    "import json, os, sys; p = json.load(open(sys.argv[1], encoding='utf-8')); "
    "print(json.dumps([k for k in p if os.environ.get(k) != p[k]]))"
)
r = subprocess.run(
    [sys.executable, "-m", "envlockup", "-f", str(file), "run", "--override", "--",
     sys.executable, "-I", "-c", child, str(work / "plain.json")],
    env={"PATH": "/usr/bin:/bin", "HOME": str(work)}, capture_output=True, text=True,
)
bad = json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else None
if bad is None:
    print(f"✗ python -m envlockup run failed (exit code {r.returncode}; output hidden: it may quote values)")
    status = 5
elif bad:
    print(f"✗ python -m envlockup run passed wrong values for: {names(bad)}")
    status = 5
else:
    print("✓ python -m envlockup run passes every value to the process")
sys.exit(status)
PY

"$VPY" -I "$WORK/check.py" "$WORK" || STATUS=$?

NOW_SUM="$(sha256sum "$SRC" 2>/dev/null || shasum -a 256 "$SRC")"
[ "$ORIG_SUM" = "$NOW_SUM" ] && echo "✓ the original file was not touched" || { echo "✗ the original file changed!"; STATUS=6; }

if [ "${STATUS:-0}" = 0 ]; then echo "Dry run passed. Temporary files deleted."; else echo "Dry run found problems (code ${STATUS}). Temporary files deleted."; fi
exit "${STATUS:-0}"
