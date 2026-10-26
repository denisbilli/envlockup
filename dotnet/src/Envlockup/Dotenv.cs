// A port of the dotenv 16/17 parser (lib/main.js), so that a file means the same
// thing to .NET as to Node's dotenv and to envlockup.
//
// The JavaScript regex is translated by hand, because JavaScript and .NET
// disagree on what \s, \w, ^, $ and . match:
//
//   \s  JavaScript's whitespace set (includes U+FEFF, excludes U+001C-U+001F and U+0085)
//   \w  ASCII letters, digits and _
//   ^ $ with the m flag, line starts/ends at \n, \r, U+2028 and U+2029
//   .   anything but those four line terminators
//
// The shared test vectors (test/vectors.json) check this against dotenv itself.

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Envlockup.Internal
{
    internal static class Dotenv
    {
        // JavaScript's String.prototype.trim() and \s.
        internal static readonly char[] WhitespaceChars =
            "\t\n\u000b\u000c\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
                .ToCharArray();

        internal const string S = "[\t\n\u000b\u000c\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]";
        private const string Bol = "(?<![^\n\r\u2028\u2029])"; // start of input, or just after a line terminator
        private const string Eol = "(?![^\n\r\u2028\u2029])"; // end of input, or just before a line terminator
        private const string Dot = "[^\n\r\u2028\u2029]";

        // dotenv: /(?:^|^)\s*(?:export\s+)?([\w.-]+)(?:\s*=\s*?|:\s+?)(\s*'(?:\\'|[^'])*'|\s*"(?:\\"|[^"])*"|\s*`(?:\\`|[^`])*`|[^#\r\n]+)?\s*(?:#.*)?(?:$|$)/mg
        private static readonly Regex Line = new Regex(
            Bol
            + S + "*"
            + "(?:export" + S + "+)?"
            + "([A-Za-z0-9_.-]+)"
            + "(?:" + S + "*=" + S + "*?|:" + S + "+?)"
            + "("
            + S + @"*'(?:\\'|[^'])*'|"
            + S + @"*""(?:\\""|[^""])*""|"
            + S + @"*`(?:\\`|[^`])*`|"
            + @"[^#\r\n]+"
            + ")?"
            + S + "*"
            + "(?:#" + Dot + "*)?"
            + Eol,
            RegexOptions.CultureInvariant);

        // dotenv: value.replace(/^(['"`])([\s\S]*)\1$/mg, '$2')
        private static readonly Regex Quoted = new Regex(Bol + @"(['""`])([\s\S]*)\1" + Eol, RegexOptions.CultureInvariant);

        private static readonly Regex LineBreak = new Regex(@"\r\n?|\n", RegexOptions.CultureInvariant);

        public static List<string> SplitLines(string text)
        {
            var lines = new List<string>(LineBreak.Split(text));
            if (lines.Count > 0 && lines[lines.Count - 1].Length == 0) lines.RemoveAt(lines.Count - 1);
            return lines;
        }

        private static string Unquote(string raw)
        {
            var value = raw.Trim(WhitespaceChars);
            var quote = value.Length > 0 ? value[0] : '\0';
            value = Quoted.Replace(value, "$2");
            if (quote == '"') value = value.Replace("\\n", "\n").Replace("\\r", "\r");
            return value;
        }

        /// <summary>(name, value) pairs in file order. Later definitions win, as in dotenv.</summary>
        public static List<KeyValuePair<string, string>> ParseEntries(IList<string> lines)
        {
            var text = string.Join("\n", lines);
            var entries = new List<KeyValuePair<string, string>>();
            foreach (Match m in Line.Matches(text))
            {
                entries.Add(new KeyValuePair<string, string>(m.Groups[1].Value, Unquote(m.Groups[2].Success ? m.Groups[2].Value : "")));
            }
            return entries;
        }

        public static Dictionary<string, string> Parse(string text)
        {
            var result = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var entry in ParseEntries(SplitLines(text))) result[entry.Key] = entry.Value;
            return result;
        }
    }
}
