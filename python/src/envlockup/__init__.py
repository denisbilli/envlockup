"""Read envlockup files: .env files whose values are encrypted for SSH or age keys.

    import envlockup
    envlockup.config()          # like python-dotenv's load_dotenv(), decrypting as it goes

The private key is looked for in this order:

    1. ENVLOCKUP_PRIVATE_KEY  the key itself (CI and servers: store it as a single secret)
    2. ENVLOCKUP_IDENTITY     path to a key file
    3. ~/.ssh/id_ed25519    your SSH key

1 and 2 are "explicit": when set, nothing else is tried. A passphrase-protected
SSH key is unlocked with ENVLOCKUP_SSH_PASSPHRASE. ssh-agent is not supported yet
by the Python package.

Files are created and edited with the envlockup CLI from npm.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import MutableMapping

from ._keys import Identity, parse_identity
from ._vault import SealedFile
from .errors import (
    DecryptError,
    EnvlockupError,
    FormatError,
    NoKeyError,
    NotARecipientError,
    PassphraseRequiredError,
)

__version__ = "0.1.0"
__all__ = [
    "config",
    "load",
    "DecryptError",
    "EnvlockupError",
    "FormatError",
    "NoKeyError",
    "NotARecipientError",
    "PassphraseRequiredError",
]

# Removed from the environment once the file is decrypted, so the rest of the
# application (and anything it starts) never sees the key.
SECRET_ENV_VARS = ("ENVLOCKUP_PRIVATE_KEY", "ENVLOCKUP_SSH_PASSPHRASE")


def _default_path() -> Path:
    return Path(os.environ.get("ENVLOCKUP_FILE") or ".env")


def _find_identity(private_key: str | None, identity_path: str | os.PathLike[str] | None) -> tuple[str, str] | None:
    """(key text, where it came from), or None."""
    if private_key:
        return private_key, "private_key argument"
    if identity_path:
        return Path(identity_path).read_text(encoding="utf-8"), str(identity_path)
    inline = os.environ.get("ENVLOCKUP_PRIVATE_KEY", "").strip()
    if inline:
        # CI systems often flatten multi-line secrets; accept literal "\n".
        return (inline if "\n" in inline else inline.replace("\\n", "\n")), "ENVLOCKUP_PRIVATE_KEY"
    file = os.environ.get("ENVLOCKUP_IDENTITY")
    if file:
        return Path(file).read_text(encoding="utf-8"), file
    default = Path.home() / ".ssh" / "id_ed25519"
    if default.is_file():
        return default.read_text(encoding="utf-8"), str(default)
    return None


def load(
    path: str | os.PathLike[str] | None = None,
    *,
    private_key: str | None = None,
    identity: str | os.PathLike[str] | None = None,
    passphrase: str | None = None,
) -> dict[str, str]:
    """Decrypt a file and return its variables, without touching os.environ.

    `path` defaults to $ENVLOCKUP_FILE or .env in the current directory. Pass
    `private_key` (key text) or `identity` (key file path) to skip the default
    lookup. The private key is only needed when the file has encrypted values.
    """
    file = Path(path) if path is not None else _default_path()
    sealed = SealedFile(file.read_text(encoding="utf-8", errors="replace"))
    if sealed.has_encrypted_values:
        found = _find_identity(private_key, identity)
        if found is None:
            hint = " ssh-agent is not supported by the Python package yet." if sealed.agent_recipients else ""
            raise NoKeyError(
                f"{file} contains encrypted values but no private key was found. "
                f"Use ~/.ssh/id_ed25519, or set ENVLOCKUP_PRIVATE_KEY or ENVLOCKUP_IDENTITY.{hint}"
            )
        text, source = found
        key: Identity = parse_identity(text, source, passphrase or os.environ.get("ENVLOCKUP_SSH_PASSPHRASE"))
        sealed.unlock(key)
    return sealed.decrypt_all()


def config(
    path: str | os.PathLike[str] | None = None,
    *,
    override: bool = False,
    private_key: str | None = None,
    identity: str | os.PathLike[str] | None = None,
    passphrase: str | None = None,
    environ: MutableMapping[str, str] | None = None,
) -> dict[str, str]:
    """Load the file into os.environ (or `environ`) and return its variables.

    Variables already set are kept unless `override` is true, as in dotenv. A
    missing file returns {}; a file that cannot be decrypted raises, because
    silently starting without secrets is worse.
    """
    file = Path(path) if path is not None else _default_path()
    if not file.is_file():
        return {}
    parsed = load(file, private_key=private_key, identity=identity, passphrase=passphrase)
    target = os.environ if environ is None else environ
    for name, value in parsed.items():
        if override or name not in target:
            target[name] = value
    # The key has done its job; don't leave it around for the rest of the app.
    for name in SECRET_ENV_VARS:
        os.environ.pop(name, None)
    return parsed
