from __future__ import annotations


class EnvlockupError(Exception):
    """Base class for every envlockup error."""


class FormatError(EnvlockupError):
    """The file's envlockup lines are malformed, or from a newer version."""


class DecryptError(EnvlockupError):
    """A value does not decrypt: it was changed, or moved from another variable."""


class RecipientListError(EnvlockupError):
    """The recipient lines are not the ones last signed by someone who could decrypt the file."""

    def __init__(self, missing: bool = False) -> None:
        super().__init__(
            (
                "the file has no #envlockup:mac line, so nobody can tell whether its recipient list was changed. "
                if missing
                else "the recipient list was changed by someone who could not decrypt the file "
                "(a #envlockup:recipient line was added, removed or edited). "
            )
            + "Compare `envlockup recipients` with a version you trust; "
            "if every key is one you expect, run `envlockup recipients --accept`."
        )
        self.missing = missing


class NotARecipientError(EnvlockupError):
    """The private key is not one the file is encrypted for."""

    def __init__(self, fingerprint: str) -> None:
        super().__init__(
            f"this file is not encrypted for your key ({fingerprint}). "
            "Run `npx envlockup pubkey` and send the line it prints to someone who can open the file, "
            "so they can run `npx envlockup add` with it."
        )
        self.fingerprint = fingerprint


class NoKeyError(EnvlockupError):
    """The file has encrypted values and no private key was found."""


class PassphraseRequiredError(EnvlockupError):
    """The SSH key is protected by a passphrase and none was given."""

    def __init__(self, source: str) -> None:
        super().__init__(f"the SSH key {source} is protected by a passphrase: set ENVLOCKUP_SSH_PASSPHRASE")
        self.source = source
