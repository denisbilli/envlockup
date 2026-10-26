// The vectors in test/vectors.json come from the Node implementation and the
// real dotenv package (see scripts/make-vectors.mjs).

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Envlockup.Internal;
using Xunit;

namespace Envlockup.Tests
{
    internal static class Vectors
    {
        public static readonly JsonElement Root = Load();

        private static JsonElement Load()
        {
            for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
            {
                var path = Path.Combine(dir.FullName, "test", "vectors.json");
                if (File.Exists(path)) return JsonDocument.Parse(File.ReadAllText(path)).RootElement;
            }
            throw new FileNotFoundException("test/vectors.json");
        }

        public static JsonElement Key(string name) => Root.GetProperty("keys").GetProperty(name);

        public static JsonElement SealedFile => Root.GetProperty("files")[0];

        public static Dictionary<string, string> Dict(JsonElement obj) =>
            obj.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetString()!);

        public static Identity Identity(string name)
        {
            var key = Key(name);
            var passphrase = key.TryGetProperty("passphrase", out var p) ? p.GetString() : null;
            return Keys.ParseIdentity(key.GetProperty("private").GetString()!, name, passphrase);
        }

        public static IEnumerable<object[]> Cases(string section) =>
            Enumerable.Range(0, Root.GetProperty(section).GetArrayLength()).Select(i => new object[] { i });
    }

    public class VectorTests
    {
        private static readonly Dictionary<string, Type> Errors = new Dictionary<string, Type>
        {
            ["not_a_recipient"] = typeof(NotARecipientException),
            ["decrypt"] = typeof(DecryptException),
            ["format"] = typeof(EnvlockupFormatException),
            ["recipients"] = typeof(RecipientListException),
        };

        public static IEnumerable<object[]> ParseCases => Vectors.Cases("parse");
        public static IEnumerable<object[]> FileCases => Vectors.Cases("files");
        public static IEnumerable<object[]> ErrorCases => Vectors.Cases("errors");

        [Theory]
        [MemberData(nameof(ParseCases))]
        public void ParsesLikeDotenv(int index)
        {
            var c = Vectors.Root.GetProperty("parse")[index];
            Assert.Equal(Vectors.Dict(c.GetProperty("expected")), Dotenv.Parse(c.GetProperty("text").GetString()!));
        }

        [Theory]
        [MemberData(nameof(FileCases))]
        public void Decrypts(int index)
        {
            var file = Vectors.Root.GetProperty("files")[index];
            var text = file.GetProperty("text").GetString()!;
            var expected = Vectors.Dict(file.GetProperty("expected"));
            var keys = file.GetProperty("keys").EnumerateArray().Select(k => k.GetString()!).ToList();
            if (keys.Count == 0) Assert.Equal(expected, new SealedFile(text).DecryptAll());
            foreach (var name in keys)
            {
                var sealedFile = new SealedFile(text);
                sealedFile.Unlock(Vectors.Identity(name));
                Assert.Equal(expected, sealedFile.DecryptAll());
            }
        }

        [Theory]
        [MemberData(nameof(ErrorCases))]
        public void Rejects(int index)
        {
            var c = Vectors.Root.GetProperty("errors")[index];
            var err = Assert.ThrowsAny<EnvlockupException>(() =>
            {
                var sealedFile = new SealedFile(c.GetProperty("text").GetString()!);
                sealedFile.Unlock(Vectors.Identity(c.GetProperty("key").GetString()!));
                sealedFile.DecryptAll();
            });
            Assert.True(
                Errors[c.GetProperty("error").GetString()!] == err.GetType(),
                $"{c.GetProperty("name").GetString()}: {err.GetType().Name}: {err.Message}");
        }
    }
}
