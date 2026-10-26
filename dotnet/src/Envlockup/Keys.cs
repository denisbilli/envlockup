// Identities (private keys that can decrypt a file) and the age v1 stanzas
// they open (https://age-encryption.org/v1):
//
//   ssh-ed25519  an OpenSSH ed25519 key file, as in age
//   X25519       a native age key (AGE-SECRET-KEY-1...), for CI and servers;
//                also what an ssh-agent recipient line wraps for

using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc7748;

namespace Envlockup.Internal
{
    internal sealed class Stanza
    {
        public Stanza(string type, string[] args, byte[] body)
        {
            Type = type;
            Args = args;
            Body = body;
        }

        public string Type { get; }
        public string[] Args { get; }
        public byte[] Body { get; }
    }

    internal static class Crypto
    {
        /// <summary>HKDF-SHA256 (RFC 5869). An empty salt is equivalent to HashLen zero bytes.</summary>
        public static byte[] Hkdf(byte[] ikm, byte[] salt, byte[] info, int length = 32)
        {
            byte[] prk;
            using (var extract = new HMACSHA256(salt)) prk = extract.ComputeHash(ikm);
            var output = new byte[length];
            var previous = new byte[0];
            using var expand = new HMACSHA256(prk);
            for (int i = 1, done = 0; done < length; i++)
            {
                previous = expand.ComputeHash(Concat(previous, info, new[] { (byte)i }));
                var n = Math.Min(previous.Length, length - done);
                Buffer.BlockCopy(previous, 0, output, done, n);
                done += n;
            }
            return output;
        }

        /// <summary>ChaCha20-Poly1305 with a zero nonce. Null when the tag doesn't match.</summary>
        public static byte[]? OpenSealed(byte[] key, byte[] ciphertext, byte[]? aad = null)
        {
            if (ciphertext.Length < 16) return null;
            var cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
            cipher.Init(false, new AeadParameters(new KeyParameter(key), 128, new byte[12], aad));
            var plain = new byte[cipher.GetOutputSize(ciphertext.Length)];
            try
            {
                var n = cipher.ProcessBytes(ciphertext, 0, ciphertext.Length, plain, 0);
                cipher.DoFinal(plain, n);
            }
            catch (InvalidCipherTextException)
            {
                return null;
            }
            return plain;
        }

        /// <summary>X25519(scalar, point). Rejects the all-zero output, as required by age.</summary>
        public static byte[] X25519Exchange(byte[] scalar, byte[] point)
        {
            if (point.Length != 32) throw new FormatException("X25519 point must be 32 bytes");
            var shared = new byte[32];
            X25519.ScalarMult(scalar, 0, point, 0, shared, 0);
            if (shared.All(b => b == 0)) throw new FormatException("invalid X25519 point (low order)");
            return shared;
        }

        public static byte[] X25519Base(byte[] scalar)
        {
            var point = new byte[32];
            X25519.ScalarMultBase(scalar, 0, point, 0);
            return point;
        }

        public static byte[] Sha256(byte[] data)
        {
            using var sha = SHA256.Create();
            return sha.ComputeHash(data);
        }

        public static byte[] Concat(params byte[][] parts)
        {
            var output = new byte[parts.Sum(p => p.Length)];
            var offset = 0;
            foreach (var part in parts)
            {
                Buffer.BlockCopy(part, 0, output, offset, part.Length);
                offset += part.Length;
            }
            return output;
        }

        public static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            var diff = 0;
            for (var i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }

        public static string B64(byte[] data) => Convert.ToBase64String(data).TrimEnd('=');

        private static readonly Regex Base64Chars = new Regex(@"\A[A-Za-z0-9+/]*\z", RegexOptions.CultureInvariant);

        /// <summary>Strict unpadded base64: only the canonical encoding of the bytes is accepted.</summary>
        public static byte[] Unb64(string s)
        {
            if (!Base64Chars.IsMatch(s) || s.Length % 4 == 1) throw new FormatException("invalid base64");
            var raw = Convert.FromBase64String(s + new string('=', (4 - s.Length % 4) % 4));
            if (B64(raw) != s) throw new FormatException("invalid base64");
            return raw;
        }

        /// <summary>Strict unpadded base64url, as <see cref="Unb64"/>.</summary>
        public static byte[] Unb64Url(string s)
        {
            if (s.IndexOf('+') >= 0 || s.IndexOf('/') >= 0) throw new FormatException("invalid base64url");
            return Unb64(s.Replace('-', '+').Replace('_', '/'));
        }

        public static string B64Url(byte[] data) => B64(data).Replace('+', '-').Replace('/', '_');
    }

    /// <summary>The SSH wire format.</summary>
    internal sealed class SshReader
    {
        private readonly byte[] _buffer;
        private int _position;

        public SshReader(byte[] buffer, int offset = 0)
        {
            _buffer = buffer;
            _position = offset;
        }

        public uint U32()
        {
            if (_position + 4 > _buffer.Length) throw new FormatException("truncated SSH key");
            var v = (uint)(_buffer[_position] << 24 | _buffer[_position + 1] << 16 | _buffer[_position + 2] << 8 | _buffer[_position + 3]);
            _position += 4;
            return v;
        }

        public byte[] String()
        {
            var n = U32();
            if (n > (uint)(_buffer.Length - _position)) throw new FormatException("truncated SSH key");
            var v = new byte[n];
            Buffer.BlockCopy(_buffer, _position, v, 0, (int)n);
            _position += (int)n;
            return v;
        }

        public string Text() => Encoding.UTF8.GetString(String());

        public bool Done => _position == _buffer.Length;

        public static byte[] Encode(byte[] data)
        {
            var output = new byte[4 + data.Length];
            output[0] = (byte)(data.Length >> 24);
            output[1] = (byte)(data.Length >> 16);
            output[2] = (byte)(data.Length >> 8);
            output[3] = (byte)data.Length;
            Buffer.BlockCopy(data, 0, output, 4, data.Length);
            return output;
        }
    }

    internal static class Keys
    {
        public static readonly byte[] X25519Label = Encoding.ASCII.GetBytes("age-encryption.org/v1/X25519");
        public static readonly byte[] SshEd25519Label = Encoding.ASCII.GetBytes("age-encryption.org/v1/ssh-ed25519");

        public static string SshKeyType(byte[] wire) => new SshReader(wire).Text();

        public static byte[] Ed25519FromWire(byte[] wire)
        {
            var r = new SshReader(wire);
            var keyType = r.Text();
            if (keyType != "ssh-ed25519") throw new FormatException($"unsupported SSH key type {keyType} (only ssh-ed25519 is supported)");
            var key = r.String();
            if (key.Length != 32 || !r.Done) throw new FormatException("malformed ssh-ed25519 key");
            if (!IsEd25519Point(key)) throw new FormatException("malformed ssh-ed25519 key (not a point on the curve)");
            return key;
        }

        private static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
        private static readonly BigInteger D = Mod(-121665 * BigInteger.ModPow(121666, P - 2, P));

        private static BigInteger Mod(BigInteger x) => (x % P + P) % P;

        /// <summary>Whether 32 bytes decode to a point on the Ed25519 curve (RFC 8032, 5.1.3).</summary>
        public static bool IsEd25519Point(byte[] publicKey)
        {
            if (publicKey.Length != 32) return false;
            var little = new byte[33]; // trailing zero: unsigned
            Buffer.BlockCopy(publicKey, 0, little, 0, 32);
            little[31] &= 0x7f;
            var y = new BigInteger(little);
            if (y >= P) return false;
            var x2 = Mod((y * y - 1) * BigInteger.ModPow(Mod(D * y * y + 1), P - 2, P));
            if (x2.IsZero) return publicKey[31] >> 7 == 0;
            return BigInteger.ModPow(x2, (P - 1) / 2, P).IsOne;
        }

        public static byte[] DecodeAgeRecipient(string s)
        {
            var (hrp, data) = Bech32.Decode(s);
            if (hrp != "age" || data.Length != 32) throw new FormatException("invalid age recipient");
            return data;
        }

        /// <summary>Matches `ssh-keygen -l` for SSH keys, and the Node CLI for age keys.</summary>
        public static string Fingerprint(byte[] material) => "SHA256:" + Crypto.B64(Crypto.Sha256(material));

        private static readonly Regex OpenSsh = new Regex(
            "-----BEGIN OPENSSH PRIVATE KEY-----([\\s\\S]*?)-----END OPENSSH PRIVATE KEY-----", RegexOptions.CultureInvariant);

        private static readonly byte[] Magic = Encoding.ASCII.GetBytes("openssh-key-v1\0");

        private static string? FindAgeSecret(string text)
        {
            foreach (var line in Regex.Split(text, "\r?\n"))
            {
                var trimmed = line.Trim(Dotenv.WhitespaceChars);
                if (trimmed.StartsWith("AGE-SECRET-KEY-1", StringComparison.Ordinal)) return trimmed;
            }
            return null;
        }

        /// <summary>An OpenSSH ed25519 key file, or an age identity (AGE-SECRET-KEY-1..., optionally in an age-keygen file).</summary>
        public static Identity ParseIdentity(string text, string source, string? passphrase = null)
        {
            var age = FindAgeSecret(text);
            if (age != null)
            {
                string hrp;
                byte[] data;
                try
                {
                    (hrp, data) = Bech32.Decode(age);
                }
                catch (FormatException)
                {
                    (hrp, data) = ("", new byte[0]);
                }
                if (hrp != "age-secret-key-" || data.Length != 32) throw new EnvlockupException($"{source}: invalid age secret key");
                return new X25519Identity(data);
            }
            return ParseOpenSsh(text, source, passphrase);
        }

        private static Identity ParseOpenSsh(string text, string source, string? passphrase)
        {
            var m = OpenSsh.Match(text);
            if (!m.Success) throw new EnvlockupException($"{source} is not an OpenSSH private key");
            try
            {
                byte[] raw;
                try
                {
                    raw = Convert.FromBase64String(Regex.Replace(m.Groups[1].Value, "\\s+", ""));
                }
                catch (FormatException)
                {
                    throw new FormatException("invalid base64");
                }
                if (raw.Length < Magic.Length || !raw.Take(Magic.Length).SequenceEqual(Magic))
                {
                    throw new EnvlockupException($"{source} is not an OpenSSH private key");
                }
                var r = new SshReader(raw, Magic.Length);
                var cipher = r.Text();
                var kdf = r.Text();
                var kdfOptions = r.String();
                if (r.U32() != 1) throw new EnvlockupException($"{source} contains more than one key");
                var publicKey = Ed25519FromWire(r.String());
                var sealedKey = r.String();
                var encrypted = cipher != "none";
                if (encrypted && (cipher != "aes256-ctr" || kdf != "bcrypt"))
                {
                    throw new EnvlockupException($"{source} uses unsupported encryption {cipher}/{kdf}");
                }

                var plain = sealedKey;
                if (encrypted)
                {
                    if (string.IsNullOrEmpty(passphrase)) throw new PassphraseRequiredException(source);
                    var opts = new SshReader(kdfOptions);
                    var salt = opts.String();
                    var rounds = opts.U32();
                    if (rounds < 1 || rounds > 1 << 20) throw new FormatException($"bcrypt rounds {rounds}");
                    var derived = BcryptPbkdf.Derive(Encoding.UTF8.GetBytes(passphrase), salt, (int)rounds, 48);
                    plain = Aes256Ctr(derived.Take(32).ToArray(), derived.Skip(32).ToArray(), sealedKey);
                }
                var p = new SshReader(plain);
                if (p.U32() != p.U32())
                {
                    throw new EnvlockupException(encrypted ? $"wrong passphrase for {source}" : $"{source} is corrupted");
                }
                if (p.Text() != "ssh-ed25519") throw new EnvlockupException($"{source} is not an ssh-ed25519 key");
                var pub = p.String();
                var priv = p.String();
                if (!pub.SequenceEqual(publicKey) || priv.Length != 64) throw new EnvlockupException($"{source} is corrupted");
                return new SshEd25519Identity(publicKey, priv.Take(32).ToArray());
            }
            catch (Exception err) when (err is FormatException || err is ArgumentException)
            {
                throw new EnvlockupException($"{source} is corrupted ({err.Message})");
            }
        }

        private static byte[] Aes256Ctr(byte[] key, byte[] iv, byte[] data)
        {
            using var aes = Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.Key = key;
            using var encryptor = aes.CreateEncryptor();
            var counter = (byte[])iv.Clone();
            var stream = new byte[16];
            var output = new byte[data.Length];
            for (var offset = 0; offset < data.Length; offset += 16)
            {
                encryptor.TransformBlock(counter, 0, 16, stream, 0);
                for (var i = 0; i < 16 && offset + i < data.Length; i++) output[offset + i] = (byte)(data[offset + i] ^ stream[i]);
                for (var i = 15; i >= 0 && ++counter[i] == 0; i--) { }
            }
            return output;
        }
    }

    internal abstract class Identity
    {
        protected Identity(string fingerprint)
        {
            Fingerprint = fingerprint;
        }

        public string Fingerprint { get; }

        /// <summary>The file key wrapped in the stanza, or null when the stanza is not for this key.</summary>
        public abstract byte[]? Unwrap(Stanza stanza);
    }

    internal sealed class X25519Identity : Identity
    {
        private readonly byte[] _secret;
        private readonly byte[] _public;

        public X25519Identity(byte[] secret) : this(secret, Crypto.X25519Base(secret)) { }

        private X25519Identity(byte[] secret, byte[] publicKey) : base(Keys.Fingerprint(publicKey))
        {
            _secret = secret;
            _public = publicKey;
        }

        public override byte[]? Unwrap(Stanza stanza)
        {
            if (stanza.Type != "X25519" || stanza.Args.Length != 1) return null;
            try
            {
                var share = Crypto.Unb64(stanza.Args[0]);
                var shared = Crypto.X25519Exchange(_secret, share);
                var key = Crypto.Hkdf(shared, Crypto.Concat(share, _public), Keys.X25519Label);
                return Crypto.OpenSealed(key, stanza.Body);
            }
            catch (FormatException)
            {
                return null;
            }
        }
    }

    internal sealed class SshEd25519Identity : Identity
    {
        private readonly byte[] _wire;
        private readonly byte[] _secret;
        private readonly byte[] _ours;
        private readonly string _tag;

        public SshEd25519Identity(byte[] publicKey, byte[] seed) : base(Keys.Fingerprint(Wire(publicKey)))
        {
            _wire = Wire(publicKey);
            // age's X25519 scalar for an Ed25519 seed. Its public half equals the
            // Ed25519 public key mapped to Curve25519, which the stanza is wrapped for.
            using (var sha = SHA512.Create()) _secret = sha.ComputeHash(seed).Take(32).ToArray();
            _ours = Crypto.X25519Base(_secret);
            _tag = Crypto.B64(Crypto.Sha256(_wire).Take(4).ToArray());
        }

        private static byte[] Wire(byte[] publicKey) =>
            Crypto.Concat(SshReader.Encode(Encoding.ASCII.GetBytes("ssh-ed25519")), SshReader.Encode(publicKey));

        public override byte[]? Unwrap(Stanza stanza)
        {
            if (stanza.Type != "ssh-ed25519" || stanza.Args.Length != 2 || stanza.Args[0] != _tag) return null;
            try
            {
                var share = Crypto.Unb64(stanza.Args[1]);
                var tweak = Crypto.Hkdf(new byte[0], _wire, Keys.SshEd25519Label);
                var shared = Crypto.X25519Exchange(tweak, Crypto.X25519Exchange(_secret, share));
                var key = Crypto.Hkdf(shared, Crypto.Concat(share, _ours), Keys.SshEd25519Label);
                return Crypto.OpenSealed(key, stanza.Body);
            }
            catch (FormatException)
            {
                return null;
            }
        }
    }
}
