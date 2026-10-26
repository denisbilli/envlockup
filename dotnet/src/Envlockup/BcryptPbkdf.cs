// bcrypt_pbkdf, the KDF of passphrase-protected OpenSSH keys. A port of OpenBSD's
// bcrypt_pbkdf.c (Ted Unangst, ISC license) and of the parts of blowfish.c it
// uses (Niels Provos, BSD license), by way of the bcrypt-pbkdf npm package.

using System;
using System.Security.Cryptography;

namespace Envlockup.Internal
{
    internal static partial class BcryptPbkdf
    {
        private const int Blocks = 8;
        private const int HashSize = 32;

        // "OxychromaticBlowfishSwatDynamite"
        private static readonly byte[] Magic =
        {
            79, 120, 121, 99, 104, 114, 111, 109, 97, 116, 105, 99, 66, 108, 111, 119,
            102, 105, 115, 104, 83, 119, 97, 116, 68, 121, 110, 97, 109, 105, 116, 101,
        };

        private sealed class Blowfish
        {
            private readonly uint[] _p = (uint[])InitialP.Clone();
            private readonly uint[] _s = (uint[])InitialS.Clone();

            private uint F(uint x) =>
                ((_s[x >> 24] + _s[256 + ((x >> 16) & 0xff)]) ^ _s[512 + ((x >> 8) & 0xff)]) + _s[768 + (x & 0xff)];

            public void Encipher(ref uint l, ref uint r)
            {
                l ^= _p[0];
                for (var i = 1; i < 16; i += 2)
                {
                    r ^= F(l) ^ _p[i];
                    l ^= F(r) ^ _p[i + 1];
                }
                var t = l;
                l = r ^ _p[17];
                r = t;
            }

            private static uint StreamToWord(byte[] data, ref int j)
            {
                uint word = 0;
                for (var i = 0; i < 4; i++, j++)
                {
                    if (j >= data.Length) j = 0;
                    word = (word << 8) | data[j];
                }
                return word;
            }

            public void Expand0State(byte[] key)
            {
                var j = 0;
                for (var i = 0; i < 18; i++) _p[i] ^= StreamToWord(key, ref j);
                uint l = 0, r = 0;
                for (var i = 0; i < 18; i += 2)
                {
                    Encipher(ref l, ref r);
                    _p[i] = l;
                    _p[i + 1] = r;
                }
                for (var i = 0; i < 1024; i += 2)
                {
                    Encipher(ref l, ref r);
                    _s[i] = l;
                    _s[i + 1] = r;
                }
            }

            public void ExpandState(byte[] data, byte[] key)
            {
                var j = 0;
                for (var i = 0; i < 18; i++) _p[i] ^= StreamToWord(key, ref j);
                j = 0;
                uint l = 0, r = 0;
                for (var i = 0; i < 18; i += 2)
                {
                    l ^= StreamToWord(data, ref j);
                    r ^= StreamToWord(data, ref j);
                    Encipher(ref l, ref r);
                    _p[i] = l;
                    _p[i + 1] = r;
                }
                for (var i = 0; i < 1024; i += 2)
                {
                    l ^= StreamToWord(data, ref j);
                    r ^= StreamToWord(data, ref j);
                    Encipher(ref l, ref r);
                    _s[i] = l;
                    _s[i + 1] = r;
                }
            }
        }

        private static byte[] Hash(byte[] sha2pass, byte[] sha2salt)
        {
            var state = new Blowfish();
            state.ExpandState(sha2salt, sha2pass);
            for (var i = 0; i < 64; i++)
            {
                state.Expand0State(sha2salt);
                state.Expand0State(sha2pass);
            }
            var cdata = new uint[Blocks];
            for (var i = 0; i < Blocks; i++)
            {
                cdata[i] = (uint)(Magic[4 * i] << 24 | Magic[4 * i + 1] << 16 | Magic[4 * i + 2] << 8 | Magic[4 * i + 3]);
            }
            for (var i = 0; i < 64; i++)
            {
                for (var b = 0; b < Blocks; b += 2) state.Encipher(ref cdata[b], ref cdata[b + 1]);
            }
            var output = new byte[HashSize];
            for (var i = 0; i < Blocks; i++)
            {
                output[4 * i + 3] = (byte)(cdata[i] >> 24);
                output[4 * i + 2] = (byte)(cdata[i] >> 16);
                output[4 * i + 1] = (byte)(cdata[i] >> 8);
                output[4 * i + 0] = (byte)cdata[i];
            }
            return output;
        }

        public static byte[] Derive(byte[] password, byte[] salt, int rounds, int keyLength)
        {
            if (rounds < 1 || password.Length == 0 || salt.Length == 0 || keyLength == 0
                || keyLength > HashSize * HashSize || salt.Length > 1 << 20)
            {
                throw new ArgumentException("invalid bcrypt_pbkdf parameters");
            }
            using var sha512 = SHA512.Create();
            var key = new byte[keyLength];
            var stride = (keyLength + HashSize - 1) / HashSize;
            var amount = (keyLength + stride - 1) / stride;
            var countSalt = new byte[salt.Length + 4];
            Buffer.BlockCopy(salt, 0, countSalt, 0, salt.Length);
            var sha2pass = sha512.ComputeHash(password);
            var remaining = keyLength;
            for (var count = 1; remaining > 0; count++)
            {
                countSalt[salt.Length + 0] = (byte)(count >> 24);
                countSalt[salt.Length + 1] = (byte)(count >> 16);
                countSalt[salt.Length + 2] = (byte)(count >> 8);
                countSalt[salt.Length + 3] = (byte)count;
                var tmp = Hash(sha2pass, sha512.ComputeHash(countSalt));
                var output = (byte[])tmp.Clone();
                for (var i = 1; i < rounds; i++)
                {
                    tmp = Hash(sha2pass, sha512.ComputeHash(tmp));
                    for (var b = 0; b < output.Length; b++) output[b] ^= tmp[b];
                }
                amount = Math.Min(amount, remaining);
                int k;
                for (k = 0; k < amount; k++)
                {
                    var dest = k * stride + (count - 1);
                    if (dest >= keyLength) break;
                    key[dest] = output[k];
                }
                remaining -= k;
            }
            return key;
        }
    }
}
