# envseal design (format v1)

## Goals

1. Secrets stay in a `.env`-shaped file that can be committed, diffed and merged.
2. Decryption uses keys developers already have (SSH ed25519), with no daemon,
   no service and no account.
3. Any dotenv user can switch with a one-line change.
4. No new cryptography: only well-reviewed constructions, testable against a
   reference implementation.

Non-goals: protecting secrets inside a running process, access control finer than
"can decrypt the whole file", secret rotation, audit logs.

## File format

An envseal file is a valid dotenv file. All envseal metadata lives in comment lines
starting with `#envseal:`, so any dotenv parser still reads it (seeing encrypted
values as opaque strings).

```
#envseal:v1 <free text>
#envseal:recipient ssh-ed25519 <base64 SSH public key> <tag> <ephemeral share> <wrapped data key> [label]
#envseal:recipient X25519 <age1... recipient> <ephemeral share> <wrapped data key> [label]
#envseal:recipient ssh-agent <age1... recipient> <ssh key type> <base64 SSH public key> <ephemeral share> <wrapped data key> [label]
NAME=envseal:v1:<base64url(salt[16] || ciphertext || tag[16])>
OTHER=plain value
```

- `#envseal:v1` marks the file and its format version. An implementation must
  reject `#envseal:` lines it does not understand, rather than ignore them.
- There is one `#envseal:recipient` line per public key that can decrypt the file.
  The line carries the public key itself, so that the recipient set can be
  re-wrapped (on `add` and `remove`) without knowing anyone's private key.
- Values may be encrypted (`envseal:v1:` prefix) or plain. Plain values are written
  in dotenv syntax.

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
than 16. `test/interop.test.js` builds real age files with envseal's stanzas and
decrypts them with the `age` CLI, and the other way around.

### Encrypting a value

```
salt  = random(16)
key   = HKDF-SHA-256(ikm = data_key, salt = salt, info = "envseal.org/v1/value")
aad   = "envseal:v1:" || NAME
value = "envseal:v1:" || base64url(salt || ChaCha20-Poly1305(key, nonce = 0, value, aad))
```

- Each value gets a fresh key, so the zero nonce is never reused under one key.
- The variable name is authenticated: a ciphertext moved from `PORT` to `API_KEY`
  fails to decrypt instead of silently becoming the API key.
- Values are independent, so two people setting different variables at the same
  time produce a clean git merge.

### Adding and removing recipients

`add` unwraps the data key and wraps it for the new recipient. Existing values do
not change.

`remove` generates a new data key, re-encrypts every value and re-wraps it for the
remaining recipients, so the old key no longer opens the current file. It cannot
take back what the removed person already decrypted, or old versions of the file
in git history; those secrets must be rotated at their source. The CLI says so on
every `remove`.

## Private keys

Lookup order: `ENVSEAL_PRIVATE_KEY` (key text), then `ENVSEAL_IDENTITY` / `-i`
(path), then `~/.ssh/id_ed25519`.

OpenSSH private keys are parsed directly (`openssh-key-v1`). Encrypted keys use
bcrypt-pbkdf with aes256-ctr, the `ssh-keygen` default; the passphrase comes from
`ENVSEAL_SSH_PASSPHRASE` or an interactive prompt. The public part of an encrypted
key can be read without the passphrase, so `init` never needs it.

The Ed25519 seed is turned into an X25519 scalar as age does:
`SHA-512(seed)[:32]`.

### ssh-agent identities

An ssh-agent can sign with a key but never reveals it and cannot decrypt, so it
cannot open an `ssh-ed25519` stanza. envseal derives an X25519 age identity from a
signature instead:

```
data      = SSHSIG signed-data blob (as in `ssh-keygen -Y sign`):
            "SSHSIG" || string("envseal.org") || string("") || string("sha512")
                     || string(SHA-512("envseal.org/v1/agent-identity"))
signature = agent.sign(ssh_key, data)            # Ed25519, or RSA with rsa-sha2-512
secret    = HKDF-SHA-256(ikm = raw signature, salt = ssh_key, info = "envseal.org/v1/agent-identity")
recipient = X25519(secret, basepoint)            # shared as age1...
```

- **Determinism.** This works only because Ed25519 (RFC 8032) and RSA PKCS#1 v1.5
  signatures are deterministic. Before a recipient is handed out (`init --agent`,
  `add --agent`, `pubkey --agent`) envseal signs twice and refuses the key if the
  results differ. ECDSA and FIDO `sk-` keys are refused up front.
- **Validation.** Every signature is verified against the public key before use,
  so an agent returning garbage can't produce a silently different identity.
- **Domain separation.** The SSHSIG framing starts with the raw bytes `SSHSIG`,
  which cannot be the start of the data signed during SSH user authentication
  (a length-prefixed session identifier), and the namespace `envseal.org` keeps it
  apart from other SSHSIG uses such as git commit signing. The test suite checks
  that `ssh-keygen -Y sign -n envseal.org` produces the same signature.
- **One identity per key.** The message is fixed, not per file, so a key has the
  same `age1...` recipient in every project; `pubkey --agent` can be shared once.
- **No proof of binding.** Nothing proves to a teammate that an `ssh-agent` line's
  `age1...` key really derives from the SSH key printed next to it: the line must
  come from its owner over a channel you trust, like any public key.
- **Synchronous loading.** `config()` must be synchronous, and agent I/O is not,
  so it runs a short-lived child process (`agent-helper.js`) that talks to the
  agent and returns the derived secret over a pipe.

## Threat model

**Protected against**: anyone who obtains the file but none of the recipients'
private keys: a public or leaked repository, a fork, CI logs that print the file,
backups, a laptop's synced folders, a copy sent over chat. They learn the variable
names, the number of variables, the approximate length of each value, and the
recipients' public keys and labels.

**Not protected against**:

- **A running process.** Decrypted values are normal environment variables, and the
  operating system lets the process owner (and root) read them.
- **Write access to the file.** Someone who can push to the repository can
  replace recipient lines and values with ones they chose. Values you have already
  set would then fail to decrypt, so `unlock` checks every value and errors out.
  A new value set afterwards on a tampered file, though, could be readable by the
  attacker. Review changes to `#envseal:` lines; if someone can change your code,
  they can also just print your secrets.
- **A compromised developer machine.** The SSH key is the key to everything it can
  decrypt, as with any key-based scheme.
- **Other users of your agent.** Any process that can talk to your agent can
  derive your envseal identity, offline and for good, not just while it has
  access. That includes root on a server you forwarded your agent to (`ssh -A`).
  Agents that confirm each signature (`ssh-add -c`, 1Password's prompts) help.
- **Lost keys.** If every recipient loses their private key, the values are gone.
  Keep at least two recipients (e.g. your laptop and a backup key stored offline).

## Planned

- `ssh-rsa` key files (age's RSA-OAEP stanza).
- A `diff` git driver so `git diff` can show decrypted changes locally.
