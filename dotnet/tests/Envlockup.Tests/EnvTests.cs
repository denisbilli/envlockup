using System;
using System.Collections.Generic;
using System.IO;
using Xunit;

namespace Envlockup.Tests
{
    // These tests change the process environment, so they don't run in parallel.
    [CollectionDefinition("environment", DisableParallelization = true)]
    public class EnvironmentCollection { }

    [Collection("environment")]
    public sealed class EnvTests : IDisposable
    {
        private static readonly string[] Variables =
            { "ENVLOCKUP_PRIVATE_KEY", "ENVLOCKUP_IDENTITY", "ENVLOCKUP_SSH_PASSPHRASE", "ENVLOCKUP_FILE" };

        private readonly string _dir = Path.Combine(Path.GetTempPath(), "envlockup-" + Guid.NewGuid().ToString("N"));
        private readonly string _envFile;
        private readonly Dictionary<string, string> _expected = Vectors.Dict(Vectors.SealedFile.GetProperty("expected"));

        public EnvTests()
        {
            foreach (var name in Variables) Environment.SetEnvironmentVariable(name, null);
            Directory.CreateDirectory(_dir);
            Env.HomeDirectory = _dir; // no ~/.ssh/id_ed25519
            _envFile = Path.Combine(_dir, ".env");
            File.WriteAllText(_envFile, Vectors.SealedFile.GetProperty("text").GetString());
        }

        public void Dispose()
        {
            foreach (var name in Variables) Environment.SetEnvironmentVariable(name, null);
            Env.HomeDirectory = null;
            Directory.Delete(_dir, recursive: true);
        }

        private static string Private(string key) => Vectors.Key(key).GetProperty("private").GetString()!;

        [Fact]
        public void LoadsWithInlineKey()
        {
            Environment.SetEnvironmentVariable("ENVLOCKUP_PRIVATE_KEY", Private("age"));
            Assert.Equal(_expected, Env.Load(_envFile));
        }

        [Fact]
        public void InlineKeyWithFlattenedNewlines()
        {
            Environment.SetEnvironmentVariable("ENVLOCKUP_PRIVATE_KEY", Private("ssh").Trim().Replace("\n", "\\n"));
            Assert.Equal(_expected, Env.Load(_envFile));
        }

        [Fact]
        public void PrivateKeyArgument()
        {
            Assert.Equal(_expected, Env.Load(_envFile, privateKey: Private("ssh")));
        }

        [Fact]
        public void IdentityFileAndPassphrase()
        {
            var key = Path.Combine(_dir, "key");
            File.WriteAllText(key, Private("ssh_passphrase"));
            Environment.SetEnvironmentVariable("ENVLOCKUP_IDENTITY", key);
            var required = Assert.Throws<PassphraseRequiredException>(() => Env.Load(_envFile));
            Assert.Equal(key, required.Source);
            var wrong = Assert.ThrowsAny<EnvlockupException>(() => Env.Load(_envFile, passphrase: "nope"));
            Assert.Contains("wrong passphrase", wrong.Message);
            Environment.SetEnvironmentVariable(
                "ENVLOCKUP_SSH_PASSPHRASE", Vectors.Key("ssh_passphrase").GetProperty("passphrase").GetString());
            Assert.Equal(_expected, Env.Load(_envFile));
        }

        [Fact]
        public void DefaultSshKey()
        {
            Directory.CreateDirectory(Path.Combine(_dir, ".ssh"));
            File.WriteAllText(Path.Combine(_dir, ".ssh", "id_ed25519"), Private("ssh"));
            Assert.Equal(_expected, Env.Load(_envFile));
        }

        [Fact]
        public void ExplicitKeyWinsOverDefault()
        {
            Directory.CreateDirectory(Path.Combine(_dir, ".ssh"));
            File.WriteAllText(Path.Combine(_dir, ".ssh", "id_ed25519"), Private("ssh"));
            Environment.SetEnvironmentVariable("ENVLOCKUP_PRIVATE_KEY", Private("outsider_age"));
            var err = Assert.Throws<NotARecipientException>(() => Env.Load(_envFile));
            Assert.StartsWith("SHA256:", err.Fingerprint);
        }

        [Fact]
        public void NoKey()
        {
            var err = Assert.Throws<NoKeyException>(() => Env.Load(_envFile));
            Assert.Contains("ssh-agent is not supported", err.Message);
        }

        [Fact]
        public void PlainFileNeedsNoKey()
        {
            var plain = Path.Combine(_dir, "plain.env");
            File.WriteAllText(plain, "A=1\nB='two'\n");
            Assert.Equal(new Dictionary<string, string> { ["A"] = "1", ["B"] = "two" }, Env.Load(plain));
        }

        [Fact]
        public void ConfigIntoDictionary()
        {
            Environment.SetEnvironmentVariable("ENVLOCKUP_PRIVATE_KEY", Private("age"));
            Environment.SetEnvironmentVariable("ENVLOCKUP_SSH_PASSPHRASE", "unused");
            var target = new Dictionary<string, string> { ["EMPTY"] = "already set" };
            Assert.Equal(_expected, Env.Config(_envFile, target: target));
            Assert.Equal("already set", target["EMPTY"]);
            Assert.Equal(_expected["DATABASE_URL"], target["DATABASE_URL"]);
            Assert.Null(Environment.GetEnvironmentVariable("ENVLOCKUP_PRIVATE_KEY"));
            Assert.Null(Environment.GetEnvironmentVariable("ENVLOCKUP_SSH_PASSPHRASE"));

            Environment.SetEnvironmentVariable("ENVLOCKUP_PRIVATE_KEY", Private("age"));
            Env.Config(_envFile, overrideExisting: true, target: target);
            Assert.Equal("", target["EMPTY"]);
        }

        [Fact]
        public void ConfigIntoProcessEnvironment()
        {
            Environment.SetEnvironmentVariable("ENVLOCKUP_PRIVATE_KEY", Private("age"));
            Environment.SetEnvironmentVariable("UNICODE", "from parent");
            try
            {
                Env.Config(_envFile);
                Assert.Equal("from parent", Environment.GetEnvironmentVariable("UNICODE"));
                Assert.Equal(_expected["MULTILINE"], Environment.GetEnvironmentVariable("MULTILINE"));

                Environment.SetEnvironmentVariable("ENVLOCKUP_PRIVATE_KEY", Private("age"));
                Env.Config(_envFile, overrideExisting: true);
                Assert.Equal(_expected["UNICODE"], Environment.GetEnvironmentVariable("UNICODE"));
            }
            finally
            {
                foreach (var name in _expected.Keys) Environment.SetEnvironmentVariable(name, null);
            }
        }

        [Fact]
        public void ConfigDefaultPathAndMissingFile()
        {
            Environment.SetEnvironmentVariable("ENVLOCKUP_FILE", _envFile);
            Environment.SetEnvironmentVariable("ENVLOCKUP_PRIVATE_KEY", Private("age"));
            Assert.Equal(_expected, Env.Config(target: new Dictionary<string, string>()));
            Assert.Empty(Env.Config(Path.Combine(_dir, "missing.env"), target: new Dictionary<string, string>()));
        }
    }
}
