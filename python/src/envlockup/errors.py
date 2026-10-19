from __future__ import annotations


class EnvlockupError(Exception):
    """Base class for every envlockup error."""


class FormatError(EnvlockupError):
    """The file's envlockup lines are malformed, or from a newer version."""


class DecryptError(EnvlockupError):
    """A value does not decrypt: it was changed, or moved from another variable."""


class NotARecipientError(EnvlockupError):
    """The private key is not one the file is encrypted for."""

    def __init__(self, fingerprint: str) -> None:
        super().__init__(
            f"this file is not encrypted for your key ({fingerprint}). "
            "Ask someone who can open it to run `envlockup add` with your public key."
        )
        self.fingerprint = fingerprint


class NoKeyError(EnvlockupError):
    """The file has encrypted values and no private key was found."""


class PassphraseRequiredError(EnvlockupError):
    """The SSH key is protected by a passphrase and none was given."""

    def __init__(self, source: str) -> None:
        super().__init__(f"the SSH key {source} is protected by a passphrase: set ENVLOCKUP_SSH_PASSPHRASE")
        self.source = source
