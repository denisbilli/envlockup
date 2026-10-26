// Reading an envlockup file (see docs/DESIGN.md in the repository):
//
//   #envlockup:v1 ...
//   #envlockup:recipient <type> <public key> <stanza args...> <wrapped key> [label]
//   API_KEY=envlockup:v1:<base64url(salt || ciphertext || tag)>
//   PORT=3000
//
// Writing (set, add, remove, ...) is done with the envlockup CLI from npm.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Envlockup.Internal
{
    internal sealed class SealedFile
    {
        private const string Header = "#envlockup:";
        private const string VersionLine = "#envlockup:v1";
        private const string RecipientLine = "#envlockup:recipient ";
        private const string MacLine = "#envlockup:mac ";
        private const string ValuePrefix = "envlockup:v1:";
        private static readonly byte[] ValueInfo = Encoding.ASCII.GetBytes("github.com/denisbilli/envlockup/v1/value");
        private static readonly byte[] RecipientsInfo = Encoding.ASCII.GetBytes("github.com/denisbilli/envlockup/v1/recipients");

        // Per recipient type: how many tokens the public key takes, the stanza it uses
        // and how many stanza arguments follow.
        private static readonly Dictionary<string, (int KeyTokens, string StanzaType, int Args)> LineLayout =
            new Dictionary<string, (int, string, int)>(StringComparer.Ordinal)
            {
                ["ssh-ed25519"] = (1, "ssh-ed25519", 2),
                ["X25519"] = (1, "X25519", 1),
                ["ssh-agent"] = (3, "X25519", 1),
            };

        private static readonly Regex Whitespace = new Regex(Dotenv.S + "+", RegexOptions.CultureInvariant);

        private readonly List<Stanza> _stanzas = new List<Stanza>();
        private readonly List<string> _recipientLines = new List<string>();
        private readonly string? _mac;
        private readonly List<KeyValuePair<string, string>> _entries;
        private byte[]? _dataKey;

        public SealedFile(string text)
        {
            var lines = Dotenv.SplitLines(text);
            Sealed = lines.Any(IsVersionLine);
            var macs = lines.Where(l => l.StartsWith(MacLine, StringComparison.Ordinal))
                .Select(l => l.Substring(MacLine.Length).Trim(Dotenv.WhitespaceChars))
                .ToList();
            if (macs.Count > 1) throw new EnvlockupFormatException("envlockup file has more than one #envlockup:mac line");
            _mac = macs.FirstOrDefault();
            foreach (var line in lines)
            {
                if (line.StartsWith(RecipientLine, StringComparison.Ordinal))
                {
                    _stanzas.Add(ParseRecipientLine(line));
                    _recipientLines.Add(line);
                    if (line.Substring(RecipientLine.Length).TrimStart(Dotenv.WhitespaceChars).StartsWith("ssh-agent ", StringComparison.Ordinal))
                    {
                        AgentRecipients++;
                    }
                }
                else if (line.StartsWith(Header, StringComparison.Ordinal) && !IsVersionLine(line)
                    && !line.StartsWith(MacLine, StringComparison.Ordinal))
                {
                    throw new EnvlockupFormatException($"unsupported envlockup header line (is envlockup up to date?): {line}");
                }
            }
            if (Sealed && _stanzas.Count == 0) throw new EnvlockupFormatException("envlockup file has no recipients");
            _entries = Dotenv.ParseEntries(lines);
        }

        public bool Sealed { get; }

        public int AgentRecipients { get; }

        public bool HasEncryptedValues => _entries.Any(e => IsEncryptedValue(e.Value));

        private static bool IsEncryptedValue(string value) => value.StartsWith(ValuePrefix, StringComparison.Ordinal);

        private static bool IsVersionLine(string line) =>
            line == VersionLine || line.StartsWith(VersionLine + " ", StringComparison.Ordinal);

        /// <summary>Validate the public key on a recipient line, as the Node implementation does.</summary>
        private static void CheckRecipient(string kind, string[] tokens)
        {
            if (kind == "X25519")
            {
                if (!tokens[0].StartsWith("age1", StringComparison.Ordinal)) throw new FormatException("not an age recipient");
                Keys.DecodeAgeRecipient(tokens[0]);
            }
            else if (kind == "ssh-ed25519")
            {
                Keys.Ed25519FromWire(Crypto.Unb64(tokens[0].TrimEnd('=')));
            }
            else
            {
                Keys.DecodeAgeRecipient(tokens[0]);
                if (Keys.SshKeyType(Crypto.Unb64(tokens[2].TrimEnd('='))) != tokens[1]) throw new FormatException("SSH key type mismatch");
            }
        }

        private static Stanza ParseRecipientLine(string line)
        {
            var parts = Whitespace.Split(line.Substring(RecipientLine.Length).Trim(Dotenv.WhitespaceChars));
            if (!LineLayout.TryGetValue(parts[0], out var layout) || parts.Length < 2 + layout.KeyTokens + layout.Args)
            {
                throw new EnvlockupFormatException($"malformed envlockup recipient line: {line}");
            }
            var keyEnd = 1 + layout.KeyTokens;
            var stanzaEnd = keyEnd + layout.Args;
            try
            {
                CheckRecipient(parts[0], parts.Skip(1).Take(layout.KeyTokens).ToArray());
                return new Stanza(layout.StanzaType, parts.Skip(keyEnd).Take(layout.Args).ToArray(), Crypto.Unb64(parts[stanzaEnd]));
            }
            catch (FormatException err)
            {
                throw new EnvlockupFormatException($"malformed envlockup recipient line ({err.Message}): {line}");
            }
        }

        /// <summary>HMAC over the recipient lines as they appear in the file, each prefixed with its length.</summary>
        private string RecipientsMac(byte[] dataKey)
        {
            using var mac = new HMACSHA256(Crypto.Hkdf(dataKey, new byte[0], RecipientsInfo));
            var input = new List<byte>();
            foreach (var line in _recipientLines)
            {
                var raw = Encoding.UTF8.GetBytes(line);
                input.AddRange(SshReader.Encode(raw));
            }
            return Crypto.B64Url(mac.ComputeHash(input.ToArray()));
        }

        private static string DecryptValue(byte[] dataKey, string name, string value)
        {
            byte[] raw;
            try
            {
                // Strict: unpadded base64url in its canonical form only, as in every implementation.
                raw = Crypto.Unb64Url(value.Substring(ValuePrefix.Length));
            }
            catch (FormatException)
            {
                raw = new byte[0];
            }
            if (raw.Length < 32) throw new DecryptException($"{name}: malformed encrypted value");
            var key = Crypto.Hkdf(dataKey, raw.Take(16).ToArray(), ValueInfo);
            var plain = Crypto.OpenSealed(key, raw.Skip(16).ToArray(), Encoding.UTF8.GetBytes(ValuePrefix + name));
            if (plain == null)
            {
                throw new DecryptException(
                    $"{name}: cannot decrypt. The value was changed or moved from another variable, or it was "
                    + "encrypted before the data key changed on another branch (a `remove` merged with a `set`). "
                    + $"Set it again with `envlockup set {name}`.");
            }
            return Encoding.UTF8.GetString(plain);
        }

        /// <summary>
        /// Recover the data key with <paramref name="identity"/>, check that every value
        /// decrypts and that the recipient list is the one last signed with the data key.
        /// </summary>
        public void Unlock(Identity identity)
        {
            // Anyone can write a stanza for a public key, so a key that unwraps but does
            // not decrypt the values may be a forgery placed before the real stanza.
            EnvlockupException? failure = null;
            RecipientListException? listFailure = null;
            foreach (var stanza in _stanzas)
            {
                var key = identity.Unwrap(stanza);
                if (key == null) continue;
                try
                {
                    if (key.Length != 32) throw new EnvlockupFormatException("malformed data key");
                    foreach (var entry in _entries)
                    {
                        if (IsEncryptedValue(entry.Value)) DecryptValue(key, entry.Key, entry.Value);
                    }
                }
                catch (Exception err) when (err is EnvlockupFormatException || err is DecryptException)
                {
                    failure ??= (EnvlockupException)err;
                    continue;
                }
                var expected = Encoding.ASCII.GetBytes(RecipientsMac(key));
                if (_mac == null || !Crypto.FixedTimeEquals(Encoding.UTF8.GetBytes(_mac), expected))
                {
                    listFailure ??= new RecipientListException(missing: _mac == null);
                    continue;
                }
                _dataKey = key;
                return;
            }
            if (listFailure != null) throw listFailure;
            if (failure != null) throw failure;
            throw new NotARecipientException(identity.Fingerprint);
        }

        /// <summary>Names defined in plaintext after an encrypted definition of the same name.</summary>
        private List<string> PlaintextOverrides()
        {
            var encrypted = new HashSet<string>(StringComparer.Ordinal);
            var found = new List<string>();
            foreach (var entry in _entries)
            {
                if (IsEncryptedValue(entry.Value)) encrypted.Add(entry.Key);
                else if (encrypted.Contains(entry.Key) && !found.Contains(entry.Key)) found.Add(entry.Key);
            }
            return found;
        }

        /// <summary>
        /// All variables, decrypted. Later definitions win, as in dotenv, except that a
        /// plaintext definition after an encrypted one is refused: it needs no key to write.
        /// </summary>
        public Dictionary<string, string> DecryptAll()
        {
            foreach (var name in PlaintextOverrides())
            {
                throw new EnvlockupFormatException(
                    $"{name} is encrypted, then set again in plaintext further down the file. "
                    + "Anyone who can edit the file can add such a line, so it is not used. "
                    + $"Delete the line you don't want, or run `envlockup set {name}`.");
            }
            var output = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var entry in _entries)
            {
                var value = entry.Value;
                if (IsEncryptedValue(value))
                {
                    if (_dataKey == null) throw new DecryptException("the file is locked: a private key is needed to read encrypted values");
                    value = DecryptValue(_dataKey, entry.Key, value);
                }
                output[entry.Key] = value;
            }
            return output;
        }
    }
}
