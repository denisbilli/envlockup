# envlockup for Python

Read [envlockup](https://github.com/denisbilli/envlockup) files from Python, without
Node.js. envlockup files are `.env` files whose values are encrypted, so they can be
committed; they are decrypted with your SSH key or a dedicated age key.

```sh
pip install envlockup
```

The package is imported as `envlockup`. It only reads files: create and edit them
with the envlockup CLI from npm (`npx envlockup init`, `npx envlockup set NAME`, ...).

## Usage

At the top of your entry point (`manage.py`, `wsgi.py`, `asgi.py`, `celery.py`,
...), before anything reads settings:

```python
import envlockup
envlockup.config()  # loads .env into os.environ, decrypting it
```

Variables already in the environment win, as with python-dotenv; pass
`override=True` to change that. A missing file is ignored; a file that cannot be
decrypted raises, because starting without secrets is worse.

Other options:

```python
envlockup.config(BASE_DIR / ".env")        # explicit path (default: $ENVLOCKUP_FILE or ./.env)
values = envlockup.load(".env")            # a dict, os.environ untouched
envlockup.load(".env", identity="/etc/app/key", passphrase="...")
```

**python-decouple** reads `os.environ` before the `.env` file, so calling
`envlockup.config()` first is all it takes: `config("SECRET_KEY")` returns the
decrypted value.

Or, without touching the code, run the app through envlockup:

```sh
python -m envlockup run -- gunicorn app.wsgi
```

On Linux and macOS the command replaces the envlockup process (same PID, signals go
straight to it), which suits systemd, supervisord and Docker.

## Keys

The private key is looked for in this order:

1. `ENVLOCKUP_PRIVATE_KEY`: the key itself. For servers and CI, create one with
   `npx envlockup keygen` and store the printed `AGE-SECRET-KEY-1...`.
2. `ENVLOCKUP_IDENTITY`: path to a key file.
3. `~/.ssh/id_ed25519`.

When 1 or 2 is set, nothing else is tried. A passphrase-protected SSH key is
unlocked with `ENVLOCKUP_SSH_PASSPHRASE` (or a prompt, in `python -m envlockup`).
`config()` and `run` remove `ENVLOCKUP_PRIVATE_KEY` and `ENVLOCKUP_SSH_PASSPHRASE`
from the environment once the file is decrypted.

ssh-agent is not supported by the Python package yet.

## Command line

```
python -m envlockup [-f FILE] [-i KEY] get NAME
python -m envlockup [-f FILE] [-i KEY] decrypt [--format json]
python -m envlockup [-f FILE] [-i KEY] run [--override] -- COMMAND [ARGS]...
```

## Compatibility

Files are parsed exactly like Node's `dotenv` package (and the envlockup CLI), not
like python-dotenv. The test suite runs the same vectors as the Node
implementation (`test/vectors.json` in the repository), generated with the real
`dotenv` package.

The file format is described in
[docs/DESIGN.md](https://github.com/denisbilli/envlockup/blob/main/docs/DESIGN.md), and
what it protects against in
[docs/THREAT_MODEL.md](https://github.com/denisbilli/envlockup/blob/main/docs/THREAT_MODEL.md).
