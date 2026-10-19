"""python -m envlockup: read envlockup files from the command line.

Edit them with the envlockup CLI from npm (`npx envlockup set NAME`).
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import re
import subprocess
import sys
from pathlib import Path

from . import SECRET_ENV_VARS, _find_identity, load
from ._dotenv import format_value
from ._keys import is_encrypted_ssh_key
from .errors import EnvlockupError, PassphraseRequiredError

USAGE = """python -m envlockup [-f FILE] [-i KEY] <command>

Commands:
  get NAME               Print one decrypted value.
  decrypt [--format json]
                         Print the whole file decrypted, in dotenv format
                         (or as a JSON object).
  run [--override] -- COMMAND [ARGS]...
                         Run COMMAND with the variables in its environment.
                         Nothing decrypted is written to disk.

Options:
  -f, --file FILE        File to use (default: $ENVLOCKUP_FILE or .env)
  -i, --identity KEY     Private key file (default: $ENVLOCKUP_PRIVATE_KEY,
                         $ENVLOCKUP_IDENTITY, or ~/.ssh/id_ed25519)
"""


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m envlockup", usage=USAGE, add_help=True)
    p.add_argument("-f", "--file")
    p.add_argument("-i", "--identity")
    sub = p.add_subparsers(dest="command", required=True)
    get = sub.add_parser("get")
    get.add_argument("name")
    decrypt = sub.add_parser("decrypt")
    decrypt.add_argument("--format", choices=["dotenv", "json"], default="dotenv")
    run = sub.add_parser("run")
    run.add_argument("--override", action="store_true")
    run.add_argument("argv", nargs=argparse.REMAINDER)
    return p


def _values(args: argparse.Namespace) -> dict[str, str]:
    try:
        return load(args.file, identity=args.identity)
    except PassphraseRequiredError:
        # Ask interactively, like the Node CLI, when there is someone to ask.
        if not sys.stdin.isatty():
            raise
        found = _find_identity(None, args.identity)
        if not found or not is_encrypted_ssh_key(found[0]):
            raise
        passphrase = getpass.getpass(f"Passphrase for {found[1]}: ")
        return load(args.file, identity=args.identity, passphrase=passphrase)


# cmd.exe metacharacters, escaped with ^ (the same rules as the npm CLI and cross-spawn).
_CMD_META = re.compile(r"""([()\][%!^"`<>&|;, *?])""")


def _cmd_escape(arg: str, twice: bool) -> str:
    # Backslashes before a quote, or at the end (before the closing quote), are doubled.
    quoted = '"' + re.sub(r"(\\*)$", r"\1\1", re.sub(r'(\\*)"', r'\1\1\\"', arg)) + '"'
    quoted = _CMD_META.sub(r"^\1", quoted)
    # A node_modules/.bin shim runs cmd.exe again, which removes one level of escaping.
    return _CMD_META.sub(r"^\1", quoted) if twice else quoted


def _run(command: list[str], env: dict[str, str]) -> int:
    if os.name == "posix":
        # Replace this process, so the command gets signals and keeps our PID
        # (what systemd, supervisord and Docker expect).
        try:
            os.execvpe(command[0], command, env)
        except OSError as err:
            print(f"envlockup: cannot run {command[0]}: {err.strerror}", file=sys.stderr)
            return 127
    # Windows: resolve .exe/.cmd through PATHEXT, then wait for the child.
    exe = shutil.which(command[0], path=env.get("PATH")) or command[0]
    try:
        if re.search(r"\.(cmd|bat)$", exe, re.IGNORECASE):
            # Batch files run through cmd.exe, which would interpret & | % and
            # friends in the arguments: escape them, as the npm CLI does.
            shim = re.search(r"node_modules[\\/]\.bin[\\/][^\\/]+\.cmd$", exe, re.IGNORECASE) is not None
            line = " ".join([_CMD_META.sub(r"^\1", exe), *(_cmd_escape(a, shim) for a in command[1:])])
            comspec = env.get("COMSPEC") or os.environ.get("COMSPEC") or "cmd.exe"
            return subprocess.call(f'{comspec} /d /s /c "{line}"', env=env)
        return subprocess.call([exe, *command[1:]], env=env)
    except OSError as err:
        print(f"envlockup: cannot run {command[0]}: {err.strerror}", file=sys.stderr)
        return 127
    except KeyboardInterrupt:
        return 130


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "get":
            values = _values(args)
            if args.name not in values:
                print(f"envlockup: {args.name} is not set", file=sys.stderr)
                return 1
            print(values[args.name])
        elif args.command == "decrypt":
            values = _values(args)
            if args.format == "json":
                print(json.dumps(values, ensure_ascii=False, indent=2))
            else:
                lines = []
                for name, value in values.items():
                    try:
                        lines.append(f"{name}={format_value(value)}")
                    except ValueError:
                        print(f"envlockup: {name} cannot be written in dotenv syntax (it mixes ', \" and `); use --format json", file=sys.stderr)
                        return 1
                if lines:
                    print("\n".join(lines))
        elif args.command == "run":
            command = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
            if not command:
                print("usage: python -m envlockup run -- COMMAND [ARGS]...", file=sys.stderr)
                return 2
            values = _values(args)
            env = dict(os.environ)
            for name in SECRET_ENV_VARS:
                env.pop(name, None)
            for name, value in values.items():
                if args.override or name not in env:
                    env[name] = value
            return _run(command, env)
    except (EnvlockupError, OSError) as err:
        print(f"envlockup: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
