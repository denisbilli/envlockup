# envlockup design (format v1)

## Goals

1. Secrets stay in a `.env`-shaped file that can be committed, diffed and merged.
2. Decryption uses keys developers already have (SSH ed25519), with no daemon,
   no service and no account.
3. Any dotenv user can switch with a one-line change, in Node.js or Python.
4. No new cryptography: only well-reviewed constructions, testable against a
   reference implementation.

Non-goals: protecting secrets inside a running process, access control finer than
"can decrypt the whole file", secret rotation, audit logs.

## File format

An envlockup file is a valid dotenv file. All envlockup metadata lives in comment lines
starting with `#envlockup:`, so any dotenv parser still reads it (seeing encrypted
values as opaque strings).

```
#envlockup:v1 <free text>
#envlockup:recipient ssh-ed25519 <base64 SSH public key> <tag> <ephemeral share> <wrapped data key> [label]
#envlockup:recipient X25519 <age1... recipient> <ephemeral share> <wrapped data key> [label]
#envlockup:recipient ssh-agent <age1... recipient> <ssh key type> <base64 SSH public key> <ephemeral share> <wrapped data key> [label]
#envlockup:mac <base64url(HMAC-SHA-256 over the recipient lines)>
NAME=envlockup:v1:<base64url(salt[16] || ciphertext || tag[16])>
OTHER=plain value
```

- `#envlockup:v1`, alone or followed by a space, marks the file and its format
  version. An implementation must reject every other line starting with
  `#envlockup:`, including `#envlockup:v10` or `#envlockup:v1x`, rather than ignore it:
  a reader that skipped a newer header would hand ciphertext to the application
  as if it were the value.
- There is one `#envlockup:recipient` line per public key that can decrypt the file.
  The line carries the public key itself, so that the recipient set can be
  re-wrapped (on `add` and `remove`) without knowing anyone's private key. Fields
  are separated by whitespace; the label is everything after the wrapped key.
  Stanza fields are standard base64 without padding, as in age; the `ssh-ed25519`
  key on the line is the base64 of its SSH wire encoding.
- A file with a version line but no recipient lines is malformed.
- `#envlockup:mac` signs the recipient lines with a key derived from the data key
  (see [The recipient list](#the-recipient-list)). Writers put it right after the
  last recipient line; readers accept it anywhere, and reject a file with more
  than one.
- Values may be encrypted (`envlockup:v1:` prefix, then unpadded base64url) or plain.
  Plain values are written in dotenv syntax.
- **Comments are not encrypted**, and neither are variable names. When a value is
  encrypted its line is rewritten as `NAME=envlockup:v1:...` (keeping `export`), so
  an inline comment on that line is dropped; comment lines are kept as they are.
  Secrets left in commented-out lines stay readable by anyone with the file.

### Parsing

A file means exactly what the Node.js [`dotenv`](https://github.com/motdotla/dotenv)
package (versions 16 and 17) says it means: same line regex, same unquoting, same
quirks (an unquoted value ends at the first `#`; in double quotes only `\n` and
`\r` are unescaped; there is no `${VAR}` expansion). When a name appears more
than once, the last definition wins.

Other parsers read some files differently. In particular python-dotenv,
python-decouple and Docker Compose differ on inline comments, escapes, `export`
and `$` expansion. The envlockup implementations do not follow them; the dry-run
scripts (`scripts/dry-run.sh`, `scripts/dry-run-python.sh`) report the variables
an application would see differently after switching.

## Keys

A file has one random 32-byte **data key**.

### Wrapping the data key

For each recipient, the data key is wrapped with the corresponding age v1 stanza,
exactly as specified at https://age-encryption.org/v1:

- **`ssh-ed25519`**: the Ed25519 public key is converted to Curve25519; an
  ephemeral X25519 share is combined with it and with a tweak derived from the SSH
  public key (`HKDF-SHA-256(ikm = "", salt = ssh_key, info = "age-encryption.org/v1/ssh-ed25519")`);
  the wrapping key is `HKDF-SHA-256(ikm = shared, salt = share || pk, info = label)`;
  the data key is encrypted with ChaCha20-Poly1305 and a zero nonce. The `tag` is
  `base64(SHA-256(ssh_key)[:4])`, as in age.
- **`X25519`**: the native age recipient type (`age1...` / `AGE-SECRET-KEY-1...`),
  meant for CI and servers.
- **`ssh-agent`**: an `X25519` stanza for an age key derived through ssh-agent (see
  below). The SSH public key on the line only says which agent key to ask.

The only difference from an age file is that the wrapped key is 32 bytes rather
than 16. `test/interop.test.js` builds real age files with envlockup's stanzas and
decrypts them with the `age` CLI, and the other way around.

### Encrypting a value

```
salt  = random(16)
key   = HKDF-SHA-256(ikm = data_key, salt = salt, info = "github.com/denisbilli/envlockup/v1/value")
aad   = "envlockup:v1:" || NAME
value = "envlockup:v1:" || base64url(salt || ChaCha20-Poly1305(key, nonce = 0, value, aad))
```

- Each value gets a fresh key, so the zero nonce is never reused under one key.
- The variable name is authenticated: a ciphertext moved from `PORT` to `API_KEY`
  fails to decrypt instead of silently becoming the API key.
- Values are independent, so two people setting different variables at the same
  time produce a clean git merge.

### Decrypting a file

A reader tries each recipient line with its private key. When one unwraps (a
data key that is not 32 bytes is an error), it decrypts **every** encrypted
value with that key, including ones a later definition overrides. If any value
fails, it goes on with the next line that unwraps, since anyone can write a line
for a public key and put it first; if none works, the whole file fails. A
tampered or half-merged file is an error, never a partial set of variables.

With a data key that decrypts every value, the reader then checks the
`#envlockup:mac` line, below. A missing or wrong MAC fails the file too.

### The recipient list

Anyone can write a recipient line: it needs only a public key. Without a check,
a line added by someone who cannot decrypt the file would get the data key the
next time it is re-wrapped (`remove` re-wraps it for every line). The
`#envlockup:mac` line closes that:

```
mac_key = HKDF-SHA-256(ikm = data key, salt = "", info = "github.com/denisbilli/envlockup/v1/recipients", 32 bytes)
input   = for each #envlockup:recipient line, in file order:
            uint32 big-endian byte length of the line (UTF-8, without the line break) || the line
mac     = base64url without padding of HMAC-SHA-256(mac_key, input)
```

The lines are taken exactly as they are in the file, so adding, removing,
reordering or editing one (its label included) changes the MAC, and only someone
with the data key can compute the new one. `init`, `add`, `remove` and `keygen`
rewrite it. Values are not covered: setting a value leaves the line alone, so
everyday changes add no merge conflicts.

Two `add`s on different branches each rewrite the MAC, so they conflict on that
line. After resolving the conflict, someone who can decrypt the file checks the
list with `envlockup recipients` and signs it with `envlockup recipients --accept`,
which shows every key and asks for confirmation. The same command signs a list
that was edited by hand.

This does not stop someone who replaces the data key altogether (see the threat
model): they can compute a MAC for any list under their own key.

### Adding and removing recipients

`add` unwraps the data key, wraps it for the new recipient, appends one line and
rewrites the MAC. Existing values and existing recipient lines do not change,
byte for byte.

`remove` generates a new data key, re-encrypts every value and re-wraps it for
**every remaining line**, so the old key no longer opens the current file. The CLI
lists everyone who will be able to read the file and asks for confirmation
(`--yes` when there is no terminal). A selector that matches several recipients
(for example `@user`, whose GitHub keys share that label) removes all of them.

`remove` cannot take back what the removed person already decrypted, or old
versions of the file in git history; those secrets must be rotated at their
source. The CLI says so on every `remove`.

### Domain separation

Every string envlockup feeds into a KDF or a signature is namespaced with
`github.com/denisbilli/envlockup`, an identifier the project controls:

| Use | String |
|-----|--------|
| Value keys (HKDF info) | `github.com/denisbilli/envlockup/v1/value` |
| Recipient list MAC key (HKDF info) | `github.com/denisbilli/envlockup/v1/recipients` |
| ssh-agent message (hashed into the SSHSIG blob) | `github.com/denisbilli/envlockup/v1/agent-identity` |
| ssh-agent secret (HKDF info) | `github.com/denisbilli/envlockup/v1/agent-identity` |
| SSHSIG namespace | `github.com/denisbilli/envlockup` |

The age stanzas use age's own labels. Changing any of these strings is a new
format version.

## Private keys

Lookup order:

1. An explicit key: the CLI's `-i`, or the API's `privateKey` / `private_key` /
   `identity` option.
2. `ENVLOCKUP_PRIVATE_KEY`: the key text. CI systems often flatten multi-line
   secrets, so a value without newlines has its literal `\n` sequences turned
   into newlines.
3. `ENVLOCKUP_IDENTITY`: a key file path.
4. ssh-agent (Node.js only), when the file has an `ssh-agent` recipient and an
   agent is reachable.
5. `~/.ssh/id_ed25519`.

When 1, 2 or 3 is set, nothing else is tried, so a misconfigured server fails
instead of quietly falling back to someone's personal key. `config()` and `run`
remove `ENVLOCKUP_PRIVATE_KEY` and `ENVLOCKUP_SSH_PASSPHRASE` from the environment once
the file is decrypted, so the application and its children never see them.

An age identity file may hold other lines (as `age-keygen` writes it); the first
line starting with `AGE-SECRET-KEY-1` is used.

OpenSSH private keys are parsed directly (`openssh-key-v1`). Encrypted keys use
bcrypt-pbkdf with aes256-ctr, the `ssh-keygen` default; the passphrase comes from
`ENVLOCKUP_SSH_PASSPHRASE` or an interactive prompt. The public part of an encrypted
key can be read without the passphrase, so `init` never needs it.

The Ed25519 seed is turned into an X25519 scalar as age does:
`SHA-512(seed)[:32]`.

### ssh-agent identities

An ssh-agent can sign with a key but never reveals it and cannot decrypt, so it
cannot open an `ssh-ed25519` stanza. envlockup derives an X25519 age identity from a
signature instead:

```
data      = SSHSIG signed-data blob (as in `ssh-keygen -Y sign`):
            "SSHSIG" || string("github.com/denisbilli/envlockup") || string("") || string("sha512")
                     || string(SHA-512("github.com/denisbilli/envlockup/v1/agent-identity"))
signature = agent.sign(ssh_key, data)            # Ed25519, or RSA with rsa-sha2-512
secret    = HKDF-SHA-256(ikm = raw signature, salt = ssh_key, info = "github.com/denisbilli/envlockup/v1/agent-identity")
recipient = X25519(secret, basepoint)            # shared as age1...
```

- **Determinism.** This works only because Ed25519 (RFC 8032) and RSA PKCS#1 v1.5
  signatures are deterministic. Before a recipient is handed out (`init --agent`,
  `add --agent`, `pubkey --agent`) envlockup signs twice and refuses the key if the
  results differ. ECDSA and FIDO `sk-` keys are refused up front.
- **Validation.** Every signature is verified against the public key before use,
  so an agent returning garbage can't produce a silently different identity.
- **Domain separation.** The SSHSIG framing starts with the raw bytes `SSHSIG`,
  which cannot be the start of the data signed during SSH user authentication
  (a length-prefixed session identifier), and the namespace
  `github.com/denisbilli/envlockup` keeps it apart from other SSHSIG uses such as
  git commit signing. The test suite checks that
  `ssh-keygen -Y sign -n github.com/denisbilli/envlockup` produces the same signature.
- **One identity per key.** The message is fixed, not per file, so a key has the
  same `age1...` recipient in every project; `pubkey --agent` can be shared once.
- **No proof of binding.** Nothing proves to a teammate that an `ssh-agent` line's
  `age1...` key really derives from the SSH key printed next to it: the line must
  come from its owner over a channel you trust, like any public key.
- **Synchronous loading.** `config()` must be synchronous, and agent I/O is not,
  so it runs a short-lived child process (`agent-helper.js`) that talks to the
  agent and returns the derived secret over a pipe.

## Implementations

- **Node.js** (`envlockup` on npm, `src/`): the CLI and the library. Creates and edits
  files, and reads them with every key type, ssh-agent included.
- **Python** (`envlockup` on PyPI, imported as `envlockup`; `python/`): reads
  files only, with age keys and `ssh-ed25519` key files. No ssh-agent yet. It
  uses the `cryptography` package for X25519, ChaCha20-Poly1305 and OpenSSH keys;
  the dotenv parser is a hand translation of dotenv's regex, since JavaScript and
  Python disagree on what `\s`, `\w`, `^`, `$` and `.` match. `python -m envlockup
  run` replaces its own process with the command on POSIX systems (same PID,
  signals go straight to it).

Both run the shared vectors in `test/vectors.json`, generated by
`scripts/make-vectors.mjs` (`npm run vectors`): parsing cases checked against the
real `dotenv` package (hand-written edge cases plus random lines), sealed files for
every recipient type, and files that must be rejected. The keys in it are test
keys. A new implementation should pass them before reading real files.

## Threat model

See [THREAT_MODEL.md](THREAT_MODEL.md).

## Planned

- ssh-agent support in the Python package.
- `ssh-rsa` key files (age's RSA-OAEP stanza).
- A `diff` git driver so `git diff` can show decrypted changes locally.
