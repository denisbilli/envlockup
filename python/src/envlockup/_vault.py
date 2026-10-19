# Reading an envlockup file (see docs/DESIGN.md in the repository):
#
#   #envlockup:v1 ...
#   #envlockup:recipient <type> <public key> <stanza args...> <wrapped key> [label]
#   API_KEY=envlockup:v1:<base64url(salt || ciphertext || tag)>
#   PORT=3000
#
# Writing (set, add, remove, ...) is done with the envlockup CLI from npm.

from __future__ import annotations

import base64
import hashlib
import hmac
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
from .errors import DecryptError, FormatError, NotARecipientError, RecipientListError

HEADER = "#envlockup:"
VERSION_LINE = "#envlockup:v1"
RECIPIENT_LINE = "#envlockup:recipient "
MAC_LINE = "#envlockup:mac "
VALUE_PREFIX = "envlockup:v1:"
VALUE_INFO = b"github.com/denisbilli/envlockup/v1/value"
RECIPIENTS_INFO = b"github.com/denisbilli/envlockup/v1/recipients"

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


def _is_version_line(line: str) -> bool:
    return line == VERSION_LINE or line.startswith(VERSION_LINE + " ")


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
        raise FormatError(f"malformed envlockup recipient line: {line}")
    key_tokens, stanza_type, n_args = layout
    key_end = 1 + key_tokens
    stanza_end = key_end + n_args
    try:
        _check_recipient(parts[0], parts[1:key_end])
        return Stanza(stanza_type, parts[key_end:stanza_end], unb64(parts[stanza_end]))
    except (ValueError, UnicodeDecodeError) as err:
        raise FormatError(f"malformed envlockup recipient line ({err}): {line}") from None


def _recipients_mac(data_key: bytes, lines: list[str]) -> str:
    """HMAC over the recipient lines as they appear in the file, each prefixed with its length."""
    mac = hmac.new(hkdf(data_key, b"", RECIPIENTS_INFO), digestmod=hashlib.sha256)
    for line in lines:
        raw = line.encode("utf-8")
        mac.update(len(raw).to_bytes(4, "big"))
        mac.update(raw)
    return base64.urlsafe_b64encode(mac.digest()).rstrip(b"=").decode()


def _value_aad(name: str) -> bytes:
    return (VALUE_PREFIX + name).encode()


def _decrypt_value(data_key: bytes, name: str, value: str) -> str:
    encoded = value[len(VALUE_PREFIX) :]
    raw = b""
    # Strict: unpadded base64url in its canonical form only, as in every implementation.
    if re.fullmatch(r"[A-Za-z0-9_-]*", encoded) and len(encoded) % 4 != 1:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != encoded:
            raw = b""
    if len(raw) < 32:
        raise DecryptError(f"{name}: malformed encrypted value")
    key = hkdf(data_key, raw[:16], VALUE_INFO)
    try:
        return open_sealed(key, raw[16:], _value_aad(name)).decode("utf-8", errors="replace")
    except InvalidTag:
        raise DecryptError(
            f"{name}: cannot decrypt (the value was changed, or moved from another variable). "
            f"Set it again with `envlockup set {name}`."
        ) from None


class SealedFile:
    """A parsed envlockup (or plain dotenv) file."""

    def __init__(self, text: str) -> None:
        lines = split_lines(text)
        self.sealed = any(_is_version_line(line) for line in lines)
        self.stanzas: list[Stanza] = []
        self.agent_recipients = 0
        self._recipient_lines: list[str] = []
        macs = [line[len(MAC_LINE) :].strip() for line in lines if line.startswith(MAC_LINE)]
        if len(macs) > 1:
            raise FormatError("envlockup file has more than one #envlockup:mac line")
        self._mac = macs[0] if macs else None
        for line in lines:
            if line.startswith(RECIPIENT_LINE):
                self.stanzas.append(_parse_recipient_line(line))
                self._recipient_lines.append(line)
                if line[len(RECIPIENT_LINE) :].lstrip().startswith("ssh-agent "):
                    self.agent_recipients += 1
            elif line.startswith(HEADER) and not _is_version_line(line) and not line.startswith(MAC_LINE):
                raise FormatError(f"unsupported envlockup header line (is envlockup up to date?): {line}")
        if self.sealed and not self.stanzas:
            raise FormatError("envlockup file has no recipients")
        self.entries = parse_entries(lines)
        self._data_key: bytes | None = None

    @property
    def has_encrypted_values(self) -> bool:
        return any(is_encrypted_value(v) for _, v in self.entries)

    def unlock(self, identity: Identity) -> None:
        """Recover the data key with `identity`, check that every value decrypts and
        that the recipient list is the one last signed with the data key."""
        # Anyone can write a stanza for a public key, so a key that unwraps but does
        # not decrypt the values may be a forgery placed before the real stanza.
        failure: Exception | None = None
        list_failure: RecipientListError | None = None
        for stanza in self.stanzas:
            key = identity.unwrap(stanza)
            if key is None:
                continue
            try:
                if len(key) != 32:
                    raise FormatError("malformed data key")
                for name, value in self.entries:
                    if is_encrypted_value(value):
                        _decrypt_value(key, name, value)
            except (FormatError, DecryptError) as err:
                failure = failure or err
                continue
            expected = _recipients_mac(key, self._recipient_lines)
            if self._mac is None or not hmac.compare_digest(self._mac.encode(), expected.encode()):
                list_failure = list_failure or RecipientListError(missing=self._mac is None)
                continue
            self._data_key = key
            return
        if list_failure is not None:
            raise list_failure
        if failure is not None:
            raise failure
        raise NotARecipientError(identity.fingerprint)

    def plaintext_overrides(self) -> list[str]:
        """Names defined in plaintext after an encrypted definition of the same name."""
        encrypted: set[str] = set()
        found: list[str] = []
        for name, value in self.entries:
            if is_encrypted_value(value):
                encrypted.add(name)
            elif name in encrypted and name not in found:
                found.append(name)
        return found

    def decrypt_all(self) -> dict[str, str]:
        """All variables, decrypted. Later definitions win, as in dotenv, except that a
        plaintext definition after an encrypted one is refused: it needs no key to write."""
        for name in self.plaintext_overrides():
            raise FormatError(
                f"{name} is encrypted, then set again in plaintext further down the file. "
                "Anyone who can edit the file can add such a line, so it is not used. "
                f"Delete the line you don't want, or run `envlockup set {name}`."
            )
        out: dict[str, str] = {}
        for name, value in self.entries:
            if is_encrypted_value(value):
                if self._data_key is None:
                    raise DecryptError("the file is locked: a private key is needed to read encrypted values")
                value = _decrypt_value(self._data_key, name, value)
            out[name] = value
        return out
