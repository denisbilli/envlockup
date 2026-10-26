using System;

namespace Envlockup
{
    /// <summary>Base class for every envlockup error.</summary>
    public class EnvlockupException : Exception
    {
        /// <summary>Creates an error with a message.</summary>
        public EnvlockupException(string message) : base(message) { }
    }

    /// <summary>The file's envlockup lines are malformed, or from a newer version.</summary>
    public class EnvlockupFormatException : EnvlockupException
    {
        /// <summary>Creates an error with a message.</summary>
        public EnvlockupFormatException(string message) : base(message) { }
    }

    /// <summary>A value does not decrypt: it was changed, or moved from another variable.</summary>
    public class DecryptException : EnvlockupException
    {
        /// <summary>Creates an error with a message.</summary>
        public DecryptException(string message) : base(message) { }
    }

    /// <summary>The recipient lines are not the ones last signed by someone who could decrypt the file.</summary>
    public class RecipientListException : EnvlockupException
    {
        /// <summary>Creates the error; <paramref name="missing"/> means the file has no <c>#envlockup:mac</c> line.</summary>
        public RecipientListException(bool missing = false)
            : base(
                (missing
                    ? "the file has no #envlockup:mac line, so nobody can tell whether its recipient list was changed. "
                    : "the recipient list was changed by someone who could not decrypt the file "
                      + "(a #envlockup:recipient line was added, removed or edited). ")
                + "Compare `envlockup recipients` with a version you trust; "
                + "if every key is one you expect, run `envlockup recipients --accept`.")
        {
            Missing = missing;
        }

        /// <summary>Whether the file has no <c>#envlockup:mac</c> line at all.</summary>
        public bool Missing { get; }
    }

    /// <summary>The private key is not one the file is encrypted for.</summary>
    public class NotARecipientException : EnvlockupException
    {
        /// <summary>Creates the error for the key with this fingerprint.</summary>
        public NotARecipientException(string fingerprint)
            : base(
                $"this file is not encrypted for your key ({fingerprint}). "
                + "Run `npx envlockup pubkey` and send the line it prints to someone who can open the file, "
                + "so they can run `npx envlockup add` with it.")
        {
            Fingerprint = fingerprint;
        }

        /// <summary>The fingerprint of the key that was tried.</summary>
        public string Fingerprint { get; }
    }

    /// <summary>The file has encrypted values and no private key was found.</summary>
    public class NoKeyException : EnvlockupException
    {
        /// <summary>Creates an error with a message.</summary>
        public NoKeyException(string message) : base(message) { }
    }

    /// <summary>The SSH key is protected by a passphrase and none was given.</summary>
    public class PassphraseRequiredException : EnvlockupException
    {
        /// <summary>Creates the error for the key read from <paramref name="source"/>.</summary>
        public PassphraseRequiredException(string source)
            : base($"the SSH key {source} is protected by a passphrase: set ENVLOCKUP_SSH_PASSPHRASE")
        {
            Source = source;
        }

        /// <summary>Where the key was read from.</summary>
        public new string Source { get; }
    }
}
