// Bech32 (BIP 173) as used by age for `age1...` recipients and
// `AGE-SECRET-KEY-1...` identities. age does not enforce the 90 character limit.

using System;
using System.Collections.Generic;

namespace Envlockup.Internal
{
    internal static class Bech32
    {
        private const string Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        private static readonly uint[] Generator = { 0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3 };

        private static uint Polymod(List<int> values)
        {
            uint chk = 1;
            foreach (var v in values)
            {
                var top = chk >> 25;
                chk = ((chk & 0x1FFFFFF) << 5) ^ (uint)v;
                for (var i = 0; i < 5; i++)
                {
                    if (((top >> i) & 1) != 0) chk ^= Generator[i];
                }
            }
            return chk;
        }

        private static byte[] ConvertBits(List<int> data, int count, int from, int to)
        {
            int acc = 0, bits = 0, maxv = (1 << to) - 1;
            var output = new List<byte>();
            for (var i = 0; i < count; i++)
            {
                acc = (acc << from) | data[i];
                bits += from;
                while (bits >= to)
                {
                    bits -= to;
                    output.Add((byte)((acc >> bits) & maxv));
                }
                acc &= (1 << bits) - 1;
            }
            if (bits >= from || ((acc << (to - bits)) & maxv) != 0) throw new FormatException("invalid bech32 padding");
            return output.ToArray();
        }

        public static (string Hrp, byte[] Data) Decode(string s)
        {
            var lower = s.ToLowerInvariant();
            if (s != lower && s != s.ToUpperInvariant()) throw new FormatException("mixed-case bech32 string");
            var pos = lower.LastIndexOf('1');
            if (pos < 1 || pos + 7 > lower.Length) throw new FormatException("invalid bech32 string");
            var hrp = lower.Substring(0, pos);
            var values = new List<int>();
            foreach (var c in hrp) values.Add(c >> 5);
            values.Add(0);
            foreach (var c in hrp) values.Add(c & 31);
            var words = new List<int>();
            for (var i = pos + 1; i < lower.Length; i++)
            {
                var v = Charset.IndexOf(lower[i]);
                if (v == -1) throw new FormatException("invalid bech32 character");
                words.Add(v);
            }
            values.AddRange(words);
            if (Polymod(values) != 1) throw new FormatException("invalid bech32 checksum");
            return (hrp, ConvertBits(words, words.Count - 6, 5, 8));
        }
    }
}
