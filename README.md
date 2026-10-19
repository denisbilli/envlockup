# envseal

**Encrypted `.env` files you can commit. Decrypted with the SSH key you already have.**

`.env` files are plaintext secrets that get copied around, pasted into chats and
accidentally committed. Password managers and keychains fix that, but they are
one more thing to install, unlock and keep in sync.

envseal keeps the `.env` workflow and only changes one thing: the values are
encrypted, so the file can live in git next to your code. Whoever has the right
SSH key can read it. Nobody else can.

```dotenv
#envseal:v1 This file is encrypted with envseal and safe to commit. Edit it with `npx envseal set NAME`.
#envseal:recipient ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPTG... NMO1pw QJsm9jZ4... o8BS3fP3... denis@laptop
DATABASE_URL=envseal:v1:FIcxWKOGZ289iNLb84f8-j5OTwuN0cYTc2BgtJHkfQorhrMOZXwrRmye...
STRIPE_KEY=envseal:v1:d_1O_5okxkAcURxzsPU9dZWzjvRvELqCzyuTDQIHxNmEIbCaHswcn6ZMZg
LOG_LEVEL=debug
```

- **No new keys or passwords.** It uses your `~/.ssh/id_ed25519`, including passphrase-protected ones, or the key in your **ssh-agent**, so the private key never has to be on disk.
- **Drop-in for dotenv.** Replace `import "dotenv/config"` with `import "envseal/config"`.
- **Readable diffs.** Only values are encrypted. Names, comments and order stay as they are, so reviews and merges work.
- **Nothing decrypted on disk.** `envseal run -- <command>` passes the values straight to the process.
- **Standard crypto.** Keys are wrapped exactly as [age](https://age-encryption.org) does it. The test suite checks this against the real `age` CLI.
- **One small dependency** (`bcrypt-pbkdf`, for passphrase-protected SSH keys). Everything else is `node:crypto`.

> **Status: early (0.x).** The file format may still change before 1.0. Review the [design](docs/DESIGN.md) before trusting it with production secrets.

## Quick start

```sh
npm install envseal

# Encrypt your existing .env for your SSH key (values are encrypted in place)
npx envseal init

# Add or change a value. Without a value you are prompted for it,
# so it never ends up in your shell history.
npx envseal set STRIPE_KEY
npx envseal set LOG_LEVEL debug --plain   # not everything needs to be secret

git add .env    # yes, really — and remove it from .gitignore
```

Load it in your app:

```js
import "envseal/config";          // instead of "dotenv/config"
// or
import { config } from "envseal";
config({ path: ".env.production" });
```

Or don't touch the code at all:

```sh
npx envseal run -- node server.js
```

No SSH key yet? `ssh-keygen -t ed25519` creates one.

### Trying it on an existing .env first

`scripts/dry-run.sh` encrypts a *copy* of a real file with a throwaway key, in a
temporary folder, and checks that envseal reads it exactly like dotenv, that every
value is encrypted, and that everything decrypts back unchanged. It prints only
variable names, never values, and leaves the original untouched.

```sh
./scripts/dry-run.sh /srv/app/.env
```

## Sharing with someone else

```sh
npx envseal add @octocat                 # their ssh-ed25519 keys from github.com/octocat.keys
npx envseal add ~/Downloads/mario.pub    # or a .pub file
npx envseal add "ssh-ed25519 AAAA... mario@laptop"
npx envseal recipients                   # who can decrypt
npx envseal remove @octocat              # revoke all their keys and rotate the data key
```

Keys fetched from GitHub are trusted as published: confirm the fingerprint with
their owner. `remove` lists everyone who will still be able to read the file and
asks before changing anything (`--yes` in scripts). After `remove`, the person
removed still knows every value they could read before. **Rotate those
secrets**; envseal can't do that part for you.

## Using ssh-agent

If your key lives in an agent (a passphrase-protected key loaded with `ssh-add`,
or a password manager's SSH agent), envseal can use it directly. It is tested with
OpenSSH's `ssh-agent`; other agents should work as long as they sign with Ed25519
or RSA, and envseal checks that before using a key:

```sh
npx envseal init --agent           # new file, encrypted for your agent key
npx envseal add --agent            # or: add your agent key to an existing file
```

From then on, `get`, `run` and `import "envseal/config"` ask the agent and don't
need a key file or a passphrase. If the agent holds several keys, pick one with
`--key <fingerprint or comment>`.

An agent can only sign, not decrypt, so envseal derives a separate age key from
the agent's signature over a fixed, envseal-specific message. That key has its own
public part, which is what others need to give you access:

```sh
npx envseal pubkey --agent         # send this line to a teammate
# ssh-agent age1... ssh-ed25519 AAAA... denis@laptop
npx envseal add "ssh-agent age1... ssh-ed25519 AAAA... denis@laptop"   # they run this
```

`add @github-user` adds the plain SSH key, which needs the key file to decrypt.
Supported agent keys: `ssh-ed25519` and `ssh-rsa`. Hardware-backed ECDSA keys
(Secretive, Secure Enclave) and FIDO `sk-` keys can't be used, because their
signatures change every time; envseal checks this before adding a key.

## CI and servers

Don't put your personal SSH key on a server. Create a dedicated key instead:

```sh
npx envseal keygen --label github-actions
# prints AGE-SECRET-KEY-1... once
```

Store the printed key as the secret `ENVSEAL_PRIVATE_KEY` in your CI or hosting
provider. That is the only secret it needs, however many variables the file has.

```yaml
# GitHub Actions
- run: npx envseal run -- npm test
  env:
    ENVSEAL_PRIVATE_KEY: ${{ secrets.ENVSEAL_PRIVATE_KEY }}
```

## Python apps

A Python app can read the file without Node.js, with
[envseal-python](python/README.md):

```sh
pip install envseal-python
```

```python
import envseal
envseal.config()  # before anything reads settings (works with python-decouple)
```

or `python -m envseal run -- gunicorn app.wsgi`. It only reads files; edit them
with the CLI above.

## Where the private key comes from

In order:

1. `ENVSEAL_PRIVATE_KEY`: the key itself (an `AGE-SECRET-KEY-1...` or an OpenSSH private key; a literal `\n` is accepted for flattened secrets)
2. `-i FILE` or `ENVSEAL_IDENTITY`: path to a key file
3. ssh-agent (`SSH_AUTH_SOCK`), if the file has an `ssh-agent` recipient the agent holds
4. `~/.ssh/id_ed25519`

When 1 or 2 is set, nothing else is tried.

A passphrase-protected key file is unlocked with `ENVSEAL_SSH_PASSPHRASE`, or by
a prompt when you use the CLI in a terminal. `import "envseal/config"` cannot
prompt: load the key in ssh-agent and run `envseal add --agent` once instead.

envseal removes `ENVSEAL_PRIVATE_KEY` and `ENVSEAL_SSH_PASSPHRASE` from the
environment of the commands it runs, and from `process.env` after `config()`, so
child processes don't inherit them. The process itself started with them: on
Linux they stay readable in `/proc/<pid>/environ` by the same user, so prefer
`ENVSEAL_IDENTITY` (a file path) or ssh-agent where you can.

## Commands

| Command | |
|---|---|
| `init [--recipient KEY]... [--agent] [--keep-plain]` | Start using envseal; encrypts existing values |
| `set NAME [VALUE] [--plain]` | Set a value (prompted or read from stdin if omitted) |
| `get NAME` | Print one decrypted value |
| `unset NAME` | Remove a variable |
| `ls` | List names; 🔒 marks encrypted ones |
| `encrypt [NAME]...` | Encrypt values that are still plaintext |
| `decrypt [--format json]` | Print the whole file decrypted (dotenv format, or JSON) |
| `run [--override] -- CMD...` | Run a command with the variables set |
| `recipients` | List who can decrypt |
| `add KEY... [--label TEXT]` | Give access to a key, `.pub` file, `age1...`, `ssh-agent ...` line or `@github-user` |
| `add --agent [--key K]` | Give access to your own ssh-agent key |
| `pubkey [--agent] [--key K]` | Print your public key, to send to whoever will `add` you |
| `remove WHO... [--yes]` | Revoke access (fingerprint, label or number; every match) and rotate the data key |
| `keygen [--label TEXT]` | Create a dedicated key for CI/servers |

Global options: `-f FILE` (default `$ENVSEAL_FILE` or `.env`), `-i KEY`, `--key K` (which agent key).

As in dotenv, variables that are already set are not overwritten, unless you pass
`--override` (CLI) or `override: true` (API).

## What envseal protects, and what it doesn't

It protects secrets **at rest and in transit**: in the repository, in backups, in
forks, in screenshots of your editor, in a `.env` sent over chat. Without a
matching private key, the file reveals variable names and nothing else.
Comments are not encrypted: don't keep old secrets in commented-out lines.

It does **not** protect a running process. Once decrypted, values are ordinary
environment variables, visible to the process, its children and anyone who can
inspect it on that machine. It also can't protect you from someone who can change
your code or the file in the repository: review changes to the `#envseal:` lines
like you would review code. See [docs/DESIGN.md](docs/DESIGN.md) for the details.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Requirements

Node.js 22.12 or later. Keys: `ssh-ed25519` files, `ssh-ed25519` and `ssh-rsa`
keys in ssh-agent, and native age X25519 keys. RSA key files and FIDO `sk-` keys
are not supported.

## License

MIT
