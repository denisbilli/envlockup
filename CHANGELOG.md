# Changelog

Every package is listed here: `envlockup` on npm (library and CLI),
`envlockup` on PyPI (reader) and `Envlockup` on NuGet (reader). The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Nothing has been
published yet; versions before the rename were called envseal and were never
released.

## Unreleased

### npm

- The CLI no longer truncates its output into a pipe: `envlockup get BIG | ...`
  stopped after the first 64 KB when the reader was slower than the writer,
  because the process exited before stdout was flushed.

### NuGet

- First version of `Envlockup` for .NET: `Env.Config()` and `Env.Load()` read
  envlockup files with an SSH key (also passphrase-protected) or an age key,
  like the Python package. ssh-agent is not supported yet.

## 0.2.1

### npm

- `run` on Windows passes arguments unchanged: programs start without a
  shell, and arguments to `.cmd` and `.bat` files (npm, npx and other shims)
  are escaped for cmd.exe. Before, `&`, `|`, `%`, `^` and quotes in arguments
  were interpreted by the shell.
- `init` names the `.gitignore` line that still excludes the file, and warns
  when the file is already in earlier commits unencrypted.

### PyPI

- `python -m envlockup run` on Windows escapes arguments to `.cmd` and `.bat`
  files for cmd.exe.

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
