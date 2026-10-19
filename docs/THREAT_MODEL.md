# envlockup threat model

What envlockup protects, against whom, and what it leaves to you. The file format
and the cryptography are described in [DESIGN.md](DESIGN.md).

**Protected against**: anyone who obtains the file but none of the recipients'
private keys: a public or leaked repository, a fork, CI logs that print the file,
backups, a laptop's synced folders, a copy sent over chat. They learn the variable
names, the comments, the number of variables, the approximate length of each value,
and the recipients' public keys and labels.

**Not protected against**:

- **A running process.** Decrypted values are normal environment variables, and the
  operating system lets the process owner (and root) read them.
- **Write access to the file.** Encryption hides values; it does not say who wrote
  them, and nothing authenticates the file as a whole. Someone who can change the
  file, without any private key, can:
  - replace an encrypted value with a plaintext one (`DATABASE_URL=` pointing at
    their server), or delete a variable;
  - put back an older ciphertext of the same variable (say, a revoked API key), or
    the whole file from an older commit;
  - wrap a data key of their own for every recipient (public keys are public) and
    replace every value: the file decrypts cleanly to values they chose, and new
    values set on it afterwards are readable by them.

  What *is* caught: a value moved to another variable, a modified ciphertext,
  values left under a different data key (the file then fails as a whole), a
  recipient line added, removed or edited, and a plaintext definition after an
  encrypted one of the same name. dotenv would let the last one win; envlockup
  refuses to read the file, and `encrypt` refuses to encrypt that value, until
  one of the two lines is removed (`set` replaces both). `envlockup check` in a
  pre-commit hook or CI also catches a plaintext value that replaced an
  encrypted one.
  Review changes to `#envlockup:` lines and values like code; if someone can change
  your code, they can also just print your secrets.
- **A compromised developer machine.** The SSH key is the key to everything it can
  decrypt, as with any key-based scheme.
- **Other users of your agent.** Any process that can talk to your agent can
  derive your envlockup identity, offline and for good, not just while it has
  access. That includes root on a server you forwarded your agent to (`ssh -A`).
  Agents that confirm each signature (`ssh-add -c`, 1Password's prompts) help.
- **Lost keys.** If every recipient loses their private key, the values are gone.
  Keep at least two recipients (e.g. your laptop and a backup key stored offline).

## Removing someone

`envlockup remove` generates a new data key, re-encrypts every value with it and
wraps it for the remaining recipients. What that does and doesn't achieve:

1. The removed key cannot open the file **as it is after the commit**.
2. Anyone removed can still read every value they could read before, and every
   older version of the file: git history, forks, clones, CI caches, backups.
   **Removing someone is not revoking their access to secrets they already had;
   rotating those secrets at their source is.**
3. Until the commit with the new data key reaches every branch, the old key still
   opens those branches.
4. Adding a removed person back later gives them every value in the file at that
   time, as for anyone added.

Off-boarding checklist:

1. `envlockup remove <who>` and commit.
2. Rotate each secret at its provider (database password, API keys, signing
   keys...).
3. `envlockup set` the new values and commit.
4. Merge into every long-lived branch, or check that none still carries the old
   recipient list.
