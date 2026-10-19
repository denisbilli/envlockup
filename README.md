# envlockup

**Commit your `.env`. Everyone on the team decrypts it with their own SSH key.
Add or remove a person without passing a secret around.**

```dotenv
#envlockup:v1 This file is encrypted with envlockup and safe to commit. Edit it with `npx envlockup set NAME`.
#envlockup:recipient ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPTG... NMO1pw QJsm9jZ4... o8BS3fP3... denis@laptop
#envlockup:recipient ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK2r... 0bS1qA m3Xc9vLp... Hq7tYe2W... @octocat
#envlockup:mac 2mZ0rW8yQbYk3aZJ...
DATABASE_URL=envlockup:v1:FIcxWKOGZ289iNLb84f8-j5OTwuN0cYTc2BgtJHkfQorhrMOZXwrRmye...
STRIPE_KEY=envlockup:v1:d_1O_5okxkAcURxzsPU9dZWzjvRvELqCzyuTDQIHxNmEIbCaHswcn6ZMZg
LOG_LEVEL=debug
```

```js
import "envlockup/config"; // instead of "dotenv/config"
```

The file stays a normal `.env`: names, comments and order are readable, so diffs,
reviews and merges work. Only the values are encrypted, each one for every key
listed at the top.

> **Status: early (0.x).** The file format may still change before 1.0, and the
> code has not had an external security review. Read
> [what it protects](#what-it-protects-and-what-it-doesnt) before using it for
> production secrets.

## Quick start

<!-- quickstart: test/quickstart.test.js runs these commands as written -->
```sh
npm install envlockup
npx envlockup init                       # encrypts your existing .env for ~/.ssh/id_ed25519
npx envlockup set STRIPE_KEY             # prompts, so the value stays out of your shell history
npx envlockup set LOG_LEVEL debug --plain
git add .env                             # yes, commit it, and take it out of .gitignore

npx envlockup add @octocat               # a teammate, by the SSH keys on their GitHub profile
npx envlockup run -- node server.js      # or import "envlockup/config" in your code
```
<!-- /quickstart -->

Your teammate pulls, and `npx envlockup run`, `get` or `import "envlockup/config"`
just work with their own key. No SSH key yet? `ssh-keygen -t ed25519` creates one.

To try it on a real file without touching it, `scripts/dry-run.sh /srv/app/.env`
encrypts a copy with a throwaway key in a temporary folder and checks that
envlockup reads it exactly like dotenv. It prints variable names, never values.

## Should you use this?

| You want | Use |
|---|---|
| A `.env` in git where each person decrypts with their own SSH key, loaded by a library in Node or Python | envlockup |
| One shared private key per environment, the biggest ecosystem, hosted team features | [dotenvx](https://dotenvx.com) |
| KMS, YAML/JSON/INI, Kubernetes, many formats, a mature and widely used tool | [SOPS](https://github.com/getsops/sops) |
| Secrets in TOML next to [mise](https://mise.jdx.dev), many secret backends | [fnox](https://github.com/jdx/fnox) |
| No secrets in git at all | a secret manager: 1Password, Infisical, Doppler, your cloud's |

What is different here, and what isn't:

- **Per-person keys.** dotenvx encrypts a file for one key pair that everyone
  shares; removing a person means changing that key for everyone. Here each
  person has a line in the file, and `remove` takes one out and changes the key
  for the others.
- **Keys you already have.** Your `id_ed25519`, including a passphrase-protected
  one, or a key that only lives in ssh-agent (a password manager's SSH agent, for
  example). age and SOPS can't decrypt with an agent, and fnox can't use a key
  with a passphrase.
- **A library, not a binary.** `import "envlockup/config"` or `envlockup.config()`
  in Python replaces dotenv; nothing to install on servers besides the package.
- **Smaller than SOPS.** One file format (dotenv), no KMS, no plugins. If you need
  those, use SOPS.

## Sharing with someone else

```sh
npx envlockup add @octocat                 # their ssh-ed25519 keys from github.com/octocat.keys
npx envlockup add ~/Downloads/mario.pub    # or a .pub file
npx envlockup add "ssh-ed25519 AAAA... mario@laptop"
npx envlockup recipients                   # who can decrypt
npx envlockup remove @octocat              # revoke all their keys and change the data key
```

Keys fetched from GitHub are trusted as published: confirm the fingerprint with
their owner. `remove` lists everyone who will still be able to read the file and
asks before changing anything (`--yes` in scripts).

The list of recipients is signed with the file's key, so a line added by someone
who can't decrypt the file stops the file from being read, instead of quietly
getting access later. Two people running `add` on different branches conflict on
that signature: after the merge, check the list and sign it again with
`npx envlockup recipients --accept`.

### What `remove` does and doesn't do

1. The removed key can't open the file as it is after your commit.
2. The person removed still knows every value they could read before, and can
   still open every older version of the file: in git history, forks, clones, CI
   caches and backups. **Removing someone doesn't take back secrets they already
   had. Rotating those secrets at their source does.**
3. Branches that don't have your commit yet still open with the old key.

When someone leaves: `remove` them, commit, rotate each secret at the provider
(database password, API keys...), `set` the new values, commit again.

## Using ssh-agent

If your key lives in an agent (a passphrase-protected key loaded with `ssh-add`,
or a password manager's SSH agent), envlockup can use it directly. It is tested with
OpenSSH's `ssh-agent`; other agents should work as long as they sign with Ed25519
or RSA, and envlockup checks that before using a key:

```sh
npx envlockup init --agent           # new file, encrypted for your agent key
npx envlockup add --agent            # or: add your agent key to an existing file
```

From then on, `get`, `run` and `import "envlockup/config"` ask the agent and don't
need a key file or a passphrase. If the agent holds several keys, pick one with
`--key <fingerprint or comment>`.

An agent can only sign, not decrypt, so envlockup derives a separate age key from
the agent's signature over a fixed, envlockup-specific message. That key has its own
public part, which is what others need to give you access:

```sh
npx envlockup pubkey --agent         # send this line to a teammate
# ssh-agent age1... ssh-ed25519 AAAA... denis@laptop
npx envlockup add "ssh-agent age1... ssh-ed25519 AAAA... denis@laptop"   # they run this
```

`add @github-user` adds the plain SSH key, which needs the key file to decrypt.
Supported agent keys: `ssh-ed25519` and `ssh-rsa`. Hardware-backed ECDSA keys
(Secretive, Secure Enclave) and FIDO `sk-` keys can't be used, because their
signatures change every time; envlockup checks this before adding a key.

## CI and servers

Don't put your personal SSH key on a server. Create a dedicated key instead:

```sh
npx envlockup keygen --label github-actions
# prints AGE-SECRET-KEY-1... once
```

Store the printed key as the secret `ENVLOCKUP_PRIVATE_KEY` in your CI or hosting
provider. That is the only secret it needs, however many variables the file has.

```yaml
# GitHub Actions
- run: npx envlockup run -- npm test
  env:
    ENVLOCKUP_PRIVATE_KEY: ${{ secrets.ENVLOCKUP_PRIVATE_KEY }}
```

## Checking before a commit

Someone will eventually add `API_KEY=sk_live_...` in an editor and commit it.
`envlockup check` catches that:

- a plaintext value that is new, or that is encrypted in the last commit, fails
  unless it is listed with `--allow-plain` (for values that aren't secrets,
  like `PORT`); plaintext values already committed as plaintext pass;
- with a private key available, every value must decrypt and the recipient list
  must be signed, which also catches a broken merge.

```sh
# .git/hooks/pre-commit (make it executable)
#!/bin/sh
exec npx envlockup check --allow-plain PORT,LOG_LEVEL
```

In CI, compare with the branch the pull request goes into:

```yaml
# GitHub Actions
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- run: npx envlockup check --base origin/${{ github.base_ref }} --allow-plain PORT,LOG_LEVEL
  env:
    ENVLOCKUP_PRIVATE_KEY: ${{ secrets.ENVLOCKUP_PRIVATE_KEY }}
```

Without a key, `check` still checks plaintext values and says that decryption
wasn't checked.

## Python apps

A Python app can read the file without Node.js, with the
[envlockup package](python/README.md):

```sh
pip install envlockup
```

```python
import envlockup
envlockup.config()  # before anything reads settings (works with python-decouple)
```

or `python -m envlockup run -- gunicorn app.wsgi`. It only reads files; edit them
with the CLI above. ssh-agent is not supported in Python yet.

## Where the private key comes from

In order:

1. `ENVLOCKUP_PRIVATE_KEY`: the key itself (an `AGE-SECRET-KEY-1...` or an OpenSSH private key; a literal `\n` is accepted for flattened secrets)
2. `-i FILE` or `ENVLOCKUP_IDENTITY`: path to a key file
3. ssh-agent (`SSH_AUTH_SOCK`), if the file has an `ssh-agent` recipient the agent holds
4. `~/.ssh/id_ed25519`

When 1 or 2 is set, nothing else is tried.

A passphrase-protected key file is unlocked with `ENVLOCKUP_SSH_PASSPHRASE`, or by
a prompt when you use the CLI in a terminal. `import "envlockup/config"` cannot
prompt: load the key in ssh-agent and run `envlockup add --agent` once instead.

envlockup removes `ENVLOCKUP_PRIVATE_KEY` and `ENVLOCKUP_SSH_PASSPHRASE` from the
environment of the commands it runs, and from `process.env` after `config()`, so
child processes don't inherit them. The process itself started with them: on
Linux they stay readable in `/proc/<pid>/environ` by the same user, so prefer
`ENVLOCKUP_IDENTITY` (a file path) or ssh-agent where you can.

## Commands

| Command | |
|---|---|
| `init [--recipient KEY]... [--agent] [--keep-plain]` | Start using envlockup; encrypts existing values |
| `set NAME [VALUE] [--plain]` | Set a value (prompted or read from stdin if omitted) |
| `get NAME` | Print one decrypted value |
| `unset NAME` | Remove a variable |
| `ls` | List names; 🔒 marks encrypted ones |
| `encrypt [NAME]...` | Encrypt values that are still plaintext |
| `decrypt [--format json]` | Print the whole file decrypted (dotenv format, or JSON) |
| `run [--override] -- CMD...` | Run a command with the variables set |
| `recipients [--accept [--yes]]` | List who can decrypt; `--accept` signs the list after a merge or a hand edit |
| `add KEY... [--label TEXT]` | Give access to a key, `.pub` file, `age1...`, `ssh-agent ...` line or `@github-user` |
| `add --agent [--key K]` | Give access to your own ssh-agent key |
| `pubkey [--agent] [--key K]` | Print your public key, to send to whoever will `add` you |
| `remove WHO... [--yes]` | Revoke access (fingerprint, label or number; every match) and change the data key |
| `check [--allow-plain NAME,...] [--base REF]` | Fail on new plaintext values and on files that don't decrypt; for pre-commit and CI |
| `keygen [--label TEXT]` | Create a dedicated key for CI/servers |

Global options: `-f FILE` (default `$ENVLOCKUP_FILE` or `.env`), `-i KEY`, `--key K` (which agent key).

As in dotenv, variables that are already set are not overwritten, unless you pass
`--override` (CLI) or `override: true` (API).

## What it protects and what it doesn't

It protects secrets **at rest and in transit**: in the repository, in backups, in
forks, in screenshots of your editor, in a `.env` sent over chat. Without a
matching private key, the file reveals variable names, comments and the
approximate length of each value, and nothing else. Comments are not encrypted:
don't keep old secrets in commented-out lines.

It does **not** protect:

- **A running process.** Once decrypted, values are ordinary environment
  variables, visible to the process, its children and anyone who can inspect it
  on that machine.
- **Against someone who can change the file.** They can't read values, but they
  can delete a variable, replace an encrypted value with a plaintext one, or put
  back an older version. `check` and code review catch most of this; a value
  moved to another name, a modified ciphertext, an added recipient and a
  plaintext override are refused on read.
- **Secrets someone already saw.** See [what `remove` does](#what-remove-does-and-doesnt-do).
- **A compromised laptop.** Whoever has your SSH key can decrypt what you can.

The full threat model is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), the
file format in [docs/DESIGN.md](docs/DESIGN.md). To report a vulnerability, see
[SECURITY.md](SECURITY.md).

## Requirements

Node.js 22.12 or later; Python 3.10 or later for the Python package. Keys:
`ssh-ed25519` files, `ssh-ed25519` and `ssh-rsa` keys in ssh-agent, and native
age X25519 keys. RSA key files and FIDO `sk-` keys are not supported.

CI runs the tests on Linux (arm64) on every change. macOS and Windows are tested
by hand from time to time; on Windows, the ssh-agent tests and the comparison
with the `age` CLI don't run yet, so agent support there is untested.

## Prior art and credits

- [age](https://age-encryption.org): the key wrapping is age's X25519 and
  ssh-ed25519 stanzas, byte for byte, checked against the `age` CLI in the tests.
- [dotenv](https://github.com/motdotla/dotenv): files are parsed exactly as dotenv
  parses them, in both implementations.
- [SOPS](https://github.com/getsops/sops): the envelope model, a data key wrapped
  once per recipient, with only values encrypted.
- Deriving an age identity from an ssh-agent signature was done before by
  [age-plugin-sshagent](https://github.com/eszio/age-plugin-sshagent) and
  [age-plugin-ssh-agent](https://github.com/kaysond/age-plugin-ssh-agent).
- [fnox](https://github.com/jdx/fnox) and [kiln](https://kiln.sh)
  also store per-person, age-encrypted secrets in git.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
