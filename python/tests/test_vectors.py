# The vectors in test/vectors.json come from the Node implementation and the
# real dotenv package (see scripts/make-vectors.mjs).

from __future__ import annotations

import json
from pathlib import Path

import pytest

from envlockup import DecryptError, FormatError, NotARecipientError
from envlockup._dotenv import format_value, parse
from envlockup._keys import parse_identity
from envlockup._vault import SealedFile

VECTORS = json.loads((Path(__file__).parents[2] / "test" / "vectors.json").read_text(encoding="utf-8"))
ERRORS = {"not_a_recipient": NotARecipientError, "decrypt": DecryptError, "format": FormatError}


def identity(name: str):
    key = VECTORS["keys"][name]
    return parse_identity(key["private"], name, key.get("passphrase"))


@pytest.mark.parametrize("case", VECTORS["parse"], ids=lambda c: json.dumps(c["text"])[:60])
def test_parses_like_dotenv(case):
    assert parse(case["text"]) == case["expected"]


@pytest.mark.parametrize("file", VECTORS["files"], ids=lambda f: f["name"])
def test_decrypts(file):
    if not file["keys"]:
        assert SealedFile(file["text"]).decrypt_all() == file["expected"]
    for name in file["keys"]:
        sealed = SealedFile(file["text"])
        sealed.unlock(identity(name))
        assert sealed.decrypt_all() == file["expected"], name


@pytest.mark.parametrize("case", VECTORS["errors"], ids=lambda c: c["name"])
def test_rejects(case):
    with pytest.raises(ERRORS[case["error"]]):
        sealed = SealedFile(case["text"])
        sealed.unlock(identity(case["key"]))
        sealed.decrypt_all()


_VALUES = sorted({v for case in VECTORS["parse"] for v in case["expected"].values()})


@pytest.mark.parametrize("value", _VALUES, ids=lambda v: json.dumps(v)[:40])
def test_format_value_round_trips(value):
    # What `decrypt` prints must read back as the same value.
    unrepresentable = all(q in value for q in "'\"`") or (
        "\r" in value and ('"' in value or "\\n" in value or "\\r" in value)
    )
    if unrepresentable:
        with pytest.raises(ValueError):
            format_value(value)
    else:
        assert parse(f"K={format_value(value)}") == {"K": value}
