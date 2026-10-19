# Changelog

Both packages are listed here: `envlockup` on npm (library and CLI) and
`envlockup` on PyPI (reader). The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Nothing has been
published yet; versions before the rename were called envseal and were never
released.

## Unreleased

## 0.2.0

First release under the name envlockup, for both packages. File format v1 (`#envlockup:v1`).

### npm

- Encrypted `.env` files: values encrypted with a data key wrapped for each
  recipient using age's X25519 and ssh-ed25519 stanzas.
- Recipients: `ssh-ed25519` keys (files, passphrase-protected files,
  `@github-user`), age keys (`keygen`, for CI) and ssh-agent keys (`ssh-ed25519`,
  `ssh-rsa`).
- Commands: `init`, `set`, `get`, `unset`, `ls`, `encrypt`, `decrypt`
  (`--format dotenv|json`), `run`, `recipients` (`--accept`), `add`, `pubkey`,
  `remove`, `check`, `keygen`.
- `import "envlockup/config"` and `config()`/`load()` as drop-in replacements for
  dotenv; parsing identical to the `dotenv` package.
- The recipient list is signed (`#envlockup:mac`); an added, removed or edited
  recipient line is refused.
- A plaintext definition after an encrypted one of the same name is refused.
- `remove` removes every key matching the selector, shows who will keep access
  and asks for confirmation (`--yes` otherwise).
- File writes keep permissions and owner, follow symlinks and use an exclusive
  temporary file.
- Error messages say what to do next: the exact `add` command for someone who
  isn't a recipient, why RSA and ECDSA keys don't work and what to use instead,
  how to avoid the passphrase prompt, unknown GitHub users, and the closest
  command for a typo.
- Strict base64 everywhere; `ssh-ed25519` recipients must be points on the curve;
  `set --plain` refuses values that start with `envlockup:v1:`.

### PyPI

- `envlockup.config()`, `envlockup.load()` and `python -m envlockup get|decrypt|run`.
- Reads every recipient type except ssh-agent; checks the recipient list
  signature and refuses plaintext overrides, like the npm package.
