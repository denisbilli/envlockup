from __future__ import annotations


class EnvsealError(Exception):
    """Base class for every envseal error."""


class FormatError(EnvsealError):
    """The file's envseal lines are malformed, or from a newer version."""


class DecryptError(EnvsealError):
    """A value does not decrypt: it was changed, or moved from another variable."""


class NotARecipientError(EnvsealError):
    """The private key is not one the file is encrypted for."""

    def __init__(self, fingerprint: str) -> None:
        super().__init__(
            f"this file is not encrypted for your key ({fingerprint}). "
            "Ask someone who can open it to run `envseal add` with your public key."
        )
        self.fingerprint = fingerprint


class NoKeyError(EnvsealError):
    """The file has encrypted values and no private key was found."""


class PassphraseRequiredError(EnvsealError):
    """The SSH key is protected by a passphrase and none was given."""

    def __init__(self, source: str) -> None:
        super().__init__(f"the SSH key {source} is protected by a passphrase: set ENVSEAL_SSH_PASSPHRASE")
        self.source = source
