using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Envlockup.Internal;

namespace Envlockup
{
    /// <summary>
    /// Read envlockup files: .env files whose values are encrypted for SSH or age keys.
    /// </summary>
    /// <remarks>
    /// <code>Envlockup.Env.Config(); // like DotNetEnv's Env.Load(), decrypting as it goes</code>
    /// The private key is looked for in this order:
    /// <list type="number">
    /// <item><c>ENVLOCKUP_PRIVATE_KEY</c>: the key itself (CI and servers: store it as a single secret)</item>
    /// <item><c>ENVLOCKUP_IDENTITY</c>: path to a key file</item>
    /// <item><c>~/.ssh/id_ed25519</c>: your SSH key</item>
    /// </list>
    /// 1 and 2 are "explicit": when set, nothing else is tried. A passphrase-protected
    /// SSH key is unlocked with <c>ENVLOCKUP_SSH_PASSPHRASE</c>. ssh-agent is not supported
    /// by the .NET package yet. Files are created and edited with the envlockup CLI from npm.
    /// </remarks>
    public static class Env
    {
        // Removed from the environment once the file is decrypted, so the rest of the
        // application (and anything it starts) never sees the key.
        private static readonly string[] SecretEnvVars = { "ENVLOCKUP_PRIVATE_KEY", "ENVLOCKUP_SSH_PASSPHRASE" };

        // Tests point this at a temporary folder; Windows has no environment variable for it.
        internal static string? HomeDirectory;

        private static string DefaultPath()
        {
            var file = Environment.GetEnvironmentVariable("ENVLOCKUP_FILE");
            return string.IsNullOrEmpty(file) ? ".env" : file!;
        }

        // Kept as written: File.ReadAllText would drop a byte order mark, which dotenv and
        // the other envlockup implementations keep.
        private static string ReadText(string path) => new UTF8Encoding(false).GetString(File.ReadAllBytes(path));

        /// <summary>(key text, where it came from), or null.</summary>
        private static (string Text, string Source)? FindIdentity(string? privateKey, string? identityPath)
        {
            if (!string.IsNullOrEmpty(privateKey)) return (privateKey!, "privateKey argument");
            if (!string.IsNullOrEmpty(identityPath)) return (ReadText(identityPath!), identityPath!);
            var inline = (Environment.GetEnvironmentVariable("ENVLOCKUP_PRIVATE_KEY") ?? "").Trim();
            if (inline.Length > 0)
            {
                // CI systems often flatten multi-line secrets; accept literal "\n".
                return (inline.Contains("\n") ? inline : inline.Replace("\\n", "\n"), "ENVLOCKUP_PRIVATE_KEY");
            }
            var file = Environment.GetEnvironmentVariable("ENVLOCKUP_IDENTITY");
            if (!string.IsNullOrEmpty(file)) return (ReadText(file!), file!);
            var home = HomeDirectory ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var fallback = Path.Combine(string.IsNullOrEmpty(home) ? "~" : home, ".ssh", "id_ed25519");
            return File.Exists(fallback) ? (ReadText(fallback), fallback) : null;
        }

        /// <summary>Decrypt a file and return its variables, without touching the environment.</summary>
        /// <param name="path">The file; defaults to <c>$ENVLOCKUP_FILE</c> or <c>.env</c> in the current directory.</param>
        /// <param name="privateKey">The private key itself, instead of the default lookup.</param>
        /// <param name="identity">Path to a private key file, instead of the default lookup.</param>
        /// <param name="passphrase">Passphrase of an encrypted SSH key; defaults to <c>$ENVLOCKUP_SSH_PASSPHRASE</c>.</param>
        /// <remarks>The private key is only needed when the file has encrypted values.</remarks>
        /// <exception cref="EnvlockupException">The file cannot be read or decrypted.</exception>
        public static IReadOnlyDictionary<string, string> Load(
            string? path = null, string? privateKey = null, string? identity = null, string? passphrase = null)
        {
            var file = path ?? DefaultPath();
            var sealedFile = new SealedFile(ReadText(file));
            if (sealedFile.HasEncryptedValues)
            {
                var found = FindIdentity(privateKey, identity);
                if (found == null)
                {
                    var hint = sealedFile.AgentRecipients > 0 ? " ssh-agent is not supported by the .NET package yet." : "";
                    throw new NoKeyException(
                        $"{file} contains encrypted values but no private key was found. "
                        + $"Use ~/.ssh/id_ed25519, or set ENVLOCKUP_PRIVATE_KEY or ENVLOCKUP_IDENTITY.{hint}");
                }
                var key = Keys.ParseIdentity(
                    found.Value.Text, found.Value.Source,
                    passphrase ?? Environment.GetEnvironmentVariable("ENVLOCKUP_SSH_PASSPHRASE"));
                sealedFile.Unlock(key);
            }
            return sealedFile.DecryptAll();
        }

        /// <summary>Load the file into the process environment (or <paramref name="target"/>) and return its variables.</summary>
        /// <param name="path">The file; defaults to <c>$ENVLOCKUP_FILE</c> or <c>.env</c> in the current directory.</param>
        /// <param name="overrideExisting">Replace variables that are already set; by default they win, as in dotenv.</param>
        /// <param name="privateKey">The private key itself, instead of the default lookup.</param>
        /// <param name="identity">Path to a private key file, instead of the default lookup.</param>
        /// <param name="passphrase">Passphrase of an encrypted SSH key; defaults to <c>$ENVLOCKUP_SSH_PASSPHRASE</c>.</param>
        /// <param name="target">Where to put the variables instead of the process environment.</param>
        /// <remarks>
        /// A missing file returns an empty dictionary; a file that cannot be decrypted throws,
        /// because silently starting without secrets is worse. .NET cannot set an environment
        /// variable to the empty string, so empty values are only in the returned dictionary.
        /// </remarks>
        /// <exception cref="EnvlockupException">The file cannot be read or decrypted.</exception>
        public static IReadOnlyDictionary<string, string> Config(
            string? path = null,
            bool overrideExisting = false,
            string? privateKey = null,
            string? identity = null,
            string? passphrase = null,
            IDictionary<string, string>? target = null)
        {
            var file = path ?? DefaultPath();
            if (!File.Exists(file)) return new Dictionary<string, string>();
            var parsed = Load(file, privateKey, identity, passphrase);
            foreach (var entry in parsed)
            {
                if (target != null)
                {
                    if (overrideExisting || !target.ContainsKey(entry.Key)) target[entry.Key] = entry.Value;
                }
                else if (overrideExisting || Environment.GetEnvironmentVariable(entry.Key) == null)
                {
                    Environment.SetEnvironmentVariable(entry.Key, entry.Value);
                }
            }
            // The key has done its job; don't leave it around for the rest of the app.
            foreach (var name in SecretEnvVars) Environment.SetEnvironmentVariable(name, null);
            return parsed;
        }
    }
}
