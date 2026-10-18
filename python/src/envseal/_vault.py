# Reading an envseal file (see docs/DESIGN.md in the repository):
#
#   #envseal:v1 ...
#   #envseal:recipient <type> <public key> <stanza args...> <wrapped key> [label]
#   API_KEY=envseal:v1:<base64url(salt || ciphertext || tag)>
#   PORT=3000
#
# Writing (set, add, remove, ...) is done with the envseal CLI from npm.

from __future__ import annotations

import base64
import re

from cryptography.exceptions import InvalidTag

from ._dotenv import parse_entries, split_lines
from ._keys import (
    Identity,
    Stanza,
    decode_age_recipient,
    ed25519_from_wire,
    hkdf,
    open_sealed,
    ssh_key_type,
    unb64,
)
from .errors import DecryptError, FormatError, NotARecipientError

HEADER = "#envseal:"
VERSION_LINE = "#envseal:v1"
RECIPIENT_LINE = "#envseal:recipient "
VALUE_PREFIX = "envseal:v1:"
VALUE_INFO = b"github.com/denisbilli/envseal/v1/value"

# Per recipient type: how many tokens the public key takes, the stanza it uses
# and how many stanza arguments follow.
_LINE_LAYOUT = {
    "ssh-ed25519": (1, "ssh-ed25519", 2),
    "X25519": (1, "X25519", 1),
    "ssh-agent": (3, "X25519", 1),
}
_WS = re.compile(r"[\s﻿]+")


def is_encrypted_value(value: str) -> bool:
    return value.startswith(VALUE_PREFIX)


def _check_recipient(kind: str, tokens: list[str]) -> None:
    """Validate the public key on a recipient line, as the Node implementation does."""
    if kind == "X25519":
        if not tokens[0].startswith("age1"):
            raise ValueError("not an age recipient")
        decode_age_recipient(tokens[0])
    elif kind == "ssh-ed25519":
        ed25519_from_wire(unb64(tokens[0].rstrip("=")))
    else:
        decode_age_recipient(tokens[0])
        if ssh_key_type(unb64(tokens[2].rstrip("="))) != tokens[1]:
            raise ValueError("SSH key type mismatch")


def _parse_recipient_line(line: str) -> Stanza:
    parts = _WS.split(line[len(RECIPIENT_LINE) :].strip())
    layout = _LINE_LAYOUT.get(parts[0])
    if not layout or len(parts) < 2 + layout[0] + layout[2]:
        raise FormatError(f"malformed envseal recipient line: {line}")
    key_tokens, stanza_type, n_args = layout
    key_end = 1 + key_tokens
    stanza_end = key_end + n_args
    try:
        _check_recipient(parts[0], parts[1:key_end])
        return Stanza(stanza_type, parts[key_end:stanza_end], unb64(parts[stanza_end]))
    except (ValueError, UnicodeDecodeError) as err:
        raise FormatError(f"malformed envseal recipient line ({err}): {line}") from None


def _value_aad(name: str) -> bytes:
    return (VALUE_PREFIX + name).encode()


def _decrypt_value(data_key: bytes, name: str, value: str) -> str:
    encoded = value[len(VALUE_PREFIX) :]
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except ValueError:
        raw = b""
    if len(raw) < 32:
        raise DecryptError(f"{name}: malformed encrypted value")
    key = hkdf(data_key, raw[:16], VALUE_INFO)
    try:
        return open_sealed(key, raw[16:], _value_aad(name)).decode("utf-8", errors="replace")
    except InvalidTag:
        raise DecryptError(
            f"{name}: cannot decrypt (the value was changed, or moved from another variable). "
            f"Set it again with `envseal set {name}`."
        ) from None


class SealedFile:
    """A parsed envseal (or plain dotenv) file."""

    def __init__(self, text: str) -> None:
        lines = split_lines(text)
        self.sealed = any(line == VERSION_LINE or line.startswith(VERSION_LINE + " ") for line in lines)
        self.stanzas: list[Stanza] = []
        self.agent_recipients = 0
        for line in lines:
            if line.startswith(RECIPIENT_LINE):
                self.stanzas.append(_parse_recipient_line(line))
                if line[len(RECIPIENT_LINE) :].lstrip().startswith("ssh-agent "):
                    self.agent_recipients += 1
            elif line.startswith(HEADER) and not line.startswith(VERSION_LINE):
                raise FormatError(f"unsupported envseal header line (is envseal up to date?): {line}")
        if self.sealed and not self.stanzas:
            raise FormatError("envseal file has no recipients")
        self.entries = parse_entries(lines)
        self._data_key: bytes | None = None

    @property
    def has_encrypted_values(self) -> bool:
        return any(is_encrypted_value(v) for _, v in self.entries)

    def unlock(self, identity: Identity) -> None:
        """Recover the data key with `identity` and check that every value decrypts."""
        for stanza in self.stanzas:
            key = identity.unwrap(stanza)
            if key is not None:
                if len(key) != 32:
                    raise FormatError("malformed data key")
                self._data_key = key
                self.decrypt_all()
                return
        raise NotARecipientError(identity.fingerprint)

    def decrypt_all(self) -> dict[str, str]:
        """All variables, decrypted. Later definitions win, as in dotenv."""
        out: dict[str, str] = {}
        for name, value in self.entries:
            if is_encrypted_value(value):
                if self._data_key is None:
                    raise DecryptError("the file is locked: a private key is needed to read encrypted values")
                value = _decrypt_value(self._data_key, name, value)
            out[name] = value
        return out
