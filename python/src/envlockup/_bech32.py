# Bech32 (BIP 173) as used by age for `age1...` recipients and
# `AGE-SECRET-KEY-1...` identities. age does not enforce the 90 character limit.

from __future__ import annotations

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GENERATOR = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _polymod(values: list[int]) -> int:
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= _GENERATOR[i]
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convert_bits(data: list[int], frm: int, to: int) -> bytes:
    acc = bits = 0
    out = []
    maxv = (1 << to) - 1
    for value in data:
        acc = (acc << frm) | value
        bits += frm
        while bits >= to:
            bits -= to
            out.append((acc >> bits) & maxv)
    if bits >= frm or ((acc << (to - bits)) & maxv) != 0:
        raise ValueError("invalid bech32 padding")
    return bytes(out)


def decode(s: str) -> tuple[str, bytes]:
    if s != s.lower() and s != s.upper():
        raise ValueError("mixed-case bech32 string")
    lower = s.lower()
    pos = lower.rfind("1")
    if pos < 1 or pos + 7 > len(lower):
        raise ValueError("invalid bech32 string")
    hrp = lower[:pos]
    words = []
    for c in lower[pos + 1 :]:
        v = _CHARSET.find(c)
        if v == -1:
            raise ValueError("invalid bech32 character")
        words.append(v)
    if _polymod(_hrp_expand(hrp) + words) != 1:
        raise ValueError("invalid bech32 checksum")
    return hrp, _convert_bits(words[:-6], 5, 8)
