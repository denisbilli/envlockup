# Identities (private keys that can decrypt a file) and the age v1 stanzas
# they open (https://age-encryption.org/v1):
#
#   ssh-ed25519  an OpenSSH ed25519 key file, as in age
#   X25519       a native age key (AGE-SECRET-KEY-1...), for CI and servers;
#                also what an ssh-agent recipient line wraps for

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from . import _bech32
from .errors import EnvlockupError, PassphraseRequiredError

X25519_LABEL = b"age-encryption.org/v1/X25519"
SSH_ED25519_LABEL = b"age-encryption.org/v1/ssh-ed25519"
_ZERO_NONCE = bytes(12)


# --- Primitives ---------------------------------------------------------------------


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 (RFC 5869). An empty salt is equivalent to HashLen zero bytes."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, prev, i = b"", b"", 1
    while len(out) < length:
        prev = hmac.new(prk, prev + info + bytes([i]), hashlib.sha256).digest()
        out += prev
        i += 1
    return out[:length]


def open_sealed(key: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
    """ChaCha20-Poly1305 with a zero nonce. Raises InvalidTag."""
    if len(ciphertext) < 16:
        raise InvalidTag()
    return ChaCha20Poly1305(key).decrypt(_ZERO_NONCE, ciphertext, aad)


def _x25519(scalar: bytes, point: bytes) -> bytes:
    """X25519(scalar, point). Rejects the all-zero output, as required by age."""
    if len(point) != 32:
        raise ValueError("X25519 point must be 32 bytes")
    shared = X25519PrivateKey.from_private_bytes(scalar).exchange(X25519PublicKey.from_public_bytes(point))
    if shared == bytes(32):
        raise ValueError("invalid X25519 point (low order)")
    return shared


def _x25519_base(scalar: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(scalar).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode().rstrip("=")


def unb64(s: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9+/]*", s):
        raise ValueError("invalid base64")
    return base64.b64decode(s + "=" * (-len(s) % 4))


# --- SSH wire format --------------------------------------------------------------


class _Reader:
    def __init__(self, buf: bytes) -> None:
        self.buf = buf
        self.pos = 0

    def u32(self) -> int:
        if self.pos + 4 > len(self.buf):
            raise ValueError("truncated SSH key")
        (v,) = struct.unpack_from(">I", self.buf, self.pos)
        self.pos += 4
        return v

    def string(self) -> bytes:
        n = self.u32()
        if self.pos + n > len(self.buf):
            raise ValueError("truncated SSH key")
        v = self.buf[self.pos : self.pos + n]
        self.pos += n
        return v

    @property
    def done(self) -> bool:
        return self.pos == len(self.buf)


def _ssh_string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def ssh_key_type(wire: bytes) -> str:
    return _Reader(wire).string().decode()


def ed25519_from_wire(wire: bytes) -> bytes:
    r = _Reader(wire)
    key_type = r.string().decode()
    if key_type != "ssh-ed25519":
        raise ValueError(f"unsupported SSH key type {key_type} (only ssh-ed25519 is supported)")
    key = r.string()
    if len(key) != 32 or not r.done:
        raise ValueError("malformed ssh-ed25519 key")
    return key


def decode_age_recipient(s: str) -> bytes:
    hrp, data = _bech32.decode(s)
    if hrp != "age" or len(data) != 32:
        raise ValueError("invalid age recipient")
    return data


def fingerprint(material: bytes) -> str:
    """Matches `ssh-keygen -l` for SSH keys, and the Node CLI for age keys."""
    return "SHA256:" + b64(hashlib.sha256(material).digest())


# --- Identities -------------------------------------------------------------------


@dataclass
class Stanza:
    type: str
    args: list[str]
    body: bytes


class Identity:
    fingerprint: str

    def unwrap(self, stanza: Stanza) -> bytes | None:
        raise NotImplementedError


class X25519Identity(Identity):
    def __init__(self, secret: bytes) -> None:
        self._secret = secret
        self._public = _x25519_base(secret)
        self.fingerprint = fingerprint(self._public)

    def unwrap(self, stanza: Stanza) -> bytes | None:
        if stanza.type != "X25519" or len(stanza.args) != 1:
            return None
        try:
            share = unb64(stanza.args[0])
            shared = _x25519(self._secret, share)
            key = hkdf(shared, share + self._public, X25519_LABEL)
            return open_sealed(key, stanza.body)
        except (ValueError, InvalidTag):
            return None


class SSHEd25519Identity(Identity):
    def __init__(self, public_key: bytes, seed: bytes) -> None:
        self._wire = _ssh_string(b"ssh-ed25519") + _ssh_string(public_key)
        # age's X25519 scalar for an Ed25519 seed. Its public half equals the
        # Ed25519 public key mapped to Curve25519, which the stanza is wrapped for.
        self._secret = hashlib.sha512(seed).digest()[:32]
        self._ours = _x25519_base(self._secret)
        self._tag = b64(hashlib.sha256(self._wire).digest()[:4])
        self.fingerprint = fingerprint(self._wire)

    def unwrap(self, stanza: Stanza) -> bytes | None:
        if stanza.type != "ssh-ed25519" or len(stanza.args) != 2 or stanza.args[0] != self._tag:
            return None
        try:
            share = unb64(stanza.args[1])
            tweak = hkdf(b"", self._wire, SSH_ED25519_LABEL)
            shared = _x25519(tweak, _x25519(self._secret, share))
            key = hkdf(shared, share + self._ours, SSH_ED25519_LABEL)
            return open_sealed(key, stanza.body)
        except (ValueError, InvalidTag):
            return None


_OPENSSH = re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]*?)-----END OPENSSH PRIVATE KEY-----")
_MAGIC = b"openssh-key-v1\0"


def _find_age_secret(text: str) -> str | None:
    for line in re.split(r"\r?\n", text):
        if line.strip().startswith("AGE-SECRET-KEY-1"):
            return line.strip()
    return None


def is_encrypted_ssh_key(text: str) -> bool:
    if _find_age_secret(text):
        return False
    m = _OPENSSH.search(text)
    if not m:
        return False
    raw = base64.b64decode(re.sub(r"\s+", "", m.group(1)))
    return raw.startswith(_MAGIC) and _Reader(raw[len(_MAGIC) :]).string() != b"none"


def parse_identity(text: str, source: str, passphrase: str | None = None) -> Identity:
    """An OpenSSH ed25519 key file, or an age identity (AGE-SECRET-KEY-1..., optionally in an age-keygen file)."""
    age = _find_age_secret(text)
    if age:
        try:
            hrp, data = _bech32.decode(age)
        except ValueError:
            hrp, data = "", b""
        if hrp != "age-secret-key-" or len(data) != 32:
            raise EnvlockupError(f"{source}: invalid age secret key")
        return X25519Identity(data)

    m = _OPENSSH.search(text)
    if not m:
        raise EnvlockupError(f"{source} is not an OpenSSH private key")
    encrypted = is_encrypted_ssh_key(text)
    if encrypted and not passphrase:
        raise PassphraseRequiredError(source)
    try:
        key = serialization.load_ssh_private_key(
            m.group(0).encode(), password=passphrase.encode() if encrypted and passphrase else None
        )
    except ValueError as err:
        raise EnvlockupError(f"wrong passphrase for {source}" if encrypted else f"{source} is corrupted ({err})") from None
    except Exception as err:  # unsupported cipher or key format
        raise EnvlockupError(f"{source}: {err}") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise EnvlockupError(f"{source} is not an ssh-ed25519 key")
    raw = serialization.PrivateFormat.Raw
    seed = key.private_bytes(serialization.Encoding.Raw, raw, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return SSHEd25519Identity(public, seed)
