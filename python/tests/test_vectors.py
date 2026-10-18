# The vectors in test/vectors.json come from the Node implementation and the
# real dotenv package (see scripts/make-vectors.mjs).

from __future__ import annotations

import json
from pathlib import Path

import pytest

from envseal import DecryptError, FormatError, NotARecipientError
from envseal._dotenv import parse
from envseal._keys import parse_identity
from envseal._vault import SealedFile

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
        SealedFile(case["text"]).unlock(identity(case["key"]))
