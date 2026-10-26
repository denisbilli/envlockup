# envlockup for .NET

Read [envlockup](https://github.com/denisbilli/envlockup) files from C# and any
.NET language, without Node.js. envlockup files are `.env` files whose values are
encrypted, so they can be committed; they are decrypted with your SSH key or a
dedicated age key.

```sh
dotnet add package Envlockup
```

It runs on .NET 8 and later, and on anything that supports .NET Standard 2.0
(.NET Framework 4.6.2 and later). It only reads files: create and edit them
with the envlockup CLI from npm (`npx envlockup init`, `npx envlockup set NAME`, ...).

## Usage

At the very start of the program, before anything reads configuration:

```csharp
using Envlockup;

Env.Config(); // loads .env into the environment, decrypting it

var builder = WebApplication.CreateBuilder(args);
```

ASP.NET Core reads environment variables into `IConfiguration`, so
`builder.Configuration["DATABASE_URL"]` returns the decrypted value. Use `__` for
sections, as usual: `ConnectionStrings__Default=...` in the file becomes
`ConnectionStrings:Default`.

Variables already in the environment win, as with dotenv; pass
`overrideExisting: true` to change that. A missing file is ignored; a file that
cannot be decrypted throws, because starting without secrets is worse. .NET cannot
set an environment variable to the empty string, so empty values are left out of
the environment (they are in the dictionary `Config` returns).

Other options:

```csharp
Env.Config(Path.Combine(AppContext.BaseDirectory, ".env"));  // explicit path (default: $ENVLOCKUP_FILE or ./.env)
var values = Env.Load(".env");                               // a dictionary, environment untouched
Env.Load(".env", identity: "/etc/app/key", passphrase: "...");
```

Or, without touching the code, run the app through the npm CLI:
`npx envlockup run -- dotnet MyApp.dll`.

## Keys

The private key is looked for in this order:

1. `ENVLOCKUP_PRIVATE_KEY`: the key itself. For servers and CI, create one with
   `npx envlockup keygen` and store the printed `AGE-SECRET-KEY-1...`.
2. `ENVLOCKUP_IDENTITY`: path to a key file.
3. `~/.ssh/id_ed25519`.

When 1 or 2 is set, nothing else is tried. A passphrase-protected SSH key is
unlocked with `ENVLOCKUP_SSH_PASSPHRASE` (or the `passphrase` argument).
`Config()` removes `ENVLOCKUP_PRIVATE_KEY` and `ENVLOCKUP_SSH_PASSPHRASE` from the
environment once the file is decrypted.

ssh-agent is not supported by the .NET package yet.

## Errors

Every error is an `EnvlockupException`. The specific ones are
`NoKeyException`, `PassphraseRequiredException`, `NotARecipientException` (the
file isn't encrypted for your key), `RecipientListException` (the recipient list
was changed without the key), `DecryptException` and `EnvlockupFormatException`.

## Compatibility

Files are parsed exactly like Node's `dotenv` package (and the envlockup CLI). The
test suite runs the same vectors as the Node and Python implementations
(`test/vectors.json` in the repository), generated with the real `dotenv` package.

The file format is described in
[docs/DESIGN.md](https://github.com/denisbilli/envlockup/blob/main/docs/DESIGN.md), and
what it protects against in
[docs/THREAT_MODEL.md](https://github.com/denisbilli/envlockup/blob/main/docs/THREAT_MODEL.md).
