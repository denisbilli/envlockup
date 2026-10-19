# A port of the dotenv 16/17 parser (lib/main.js), so that a file means the same
# thing to Python as to Node's dotenv and to envlockup. python-dotenv parses
# differently and is not used.
#
# The JavaScript regex is translated by hand, because JavaScript and Python
# disagree on what \s, \w, ^, $ and . match:
#
#   \s  JavaScript's whitespace set (includes U+FEFF, excludes U+001C-U+001F and U+0085)
#   \w  ASCII letters, digits and _
#   ^ $ with the m flag, line starts/ends at \n, \r, U+2028 and U+2029
#   .   anything but those four line terminators
#
# The shared test vectors (test/vectors.json) check this against dotenv itself.

from __future__ import annotations

import re

_WS_CHARS = "\t\n\x0b\x0c\r \xa0 " + "".join(chr(c) for c in range(0x2000, 0x200B)) + "    　﻿"
_S = "[\t\n\x0b\x0c\r \xa0  -     　﻿]"
_BOL = "(?<![^\n\r  ])"  # start of input, or just after a line terminator
_EOL = "(?![^\n\r  ])"  # end of input, or just before a line terminator
_DOT = "[^\n\r\u2028\u2029]"

# dotenv: /(?:^|^)\s*(?:export\s+)?([\w.-]+)(?:\s*=\s*?|:\s+?)(\s*'(?:\\'|[^'])*'|\s*"(?:\\"|[^"])*"|\s*`(?:\\`|[^`])*`|[^#\r\n]+)?\s*(?:#.*)?(?:$|$)/mg
_LINE = re.compile(
    _BOL
    + _S + "*"
    + "(?:export" + _S + "+)?"
    + "([A-Za-z0-9_.-]+)"
    + "(?:" + _S + "*=" + _S + "*?|:" + _S + "+?)"
    + "("
    + _S + r"*'(?:\\'|[^'])*'|"
    + _S + r'*"(?:\\"|[^"])*"|'
    + _S + r"*`(?:\\`|[^`])*`|"
    + r"[^#\r\n]+"
    + ")?"
    + _S + "*"
    + "(?:#" + _DOT + "*)?"
    + _EOL
)

# dotenv: value.replace(/^(['"`])([\s\S]*)\1$/mg, '$2')
_QUOTED = re.compile(_BOL + r"(['\"`])([\s\S]*)\1" + _EOL)


def split_lines(text: str) -> list[str]:
    lines = re.split(r"\r\n?|\n", text)
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def _unquote(raw: str) -> str:
    value = raw.strip(_WS_CHARS)
    quote = value[:1]
    value = _QUOTED.sub(r"\2", value)
    if quote == '"':
        value = value.replace("\\n", "\n").replace("\\r", "\r")
    return value


def parse_entries(lines: list[str]) -> list[tuple[str, str]]:
    """(name, value) pairs in file order. Later definitions win, as in dotenv."""
    text = "\n".join(lines)
    return [(m.group(1), _unquote(m.group(2) or "")) for m in _LINE.finditer(text)]


def parse(text: str) -> dict[str, str]:
    return dict(parse_entries(split_lines(text)))


_BARE = re.compile(r"[A-Za-z0-9_./:@%+,=~-]*")


def format_value(value: str) -> str:
    """Serialize a value so that dotenv (and this parser) read it back unchanged.

    Same rules as formatValue in the Node implementation. Raises ValueError for
    the rare values dotenv's syntax cannot represent.
    """
    if _BARE.fullmatch(value):
        return value
    # dotenv turns every \r\n or \r into \n before parsing; only the \r escape inside double quotes survives.
    if "\r" in value:
        if '"' not in value and not re.search(r"\\[nr]", value):
            return '"' + value.replace("\r", "\\r") + '"'
        raise ValueError("this value cannot be written as a dotenv value (it has a carriage return and a \" or \\n)")
    if "'" not in value:
        return f"'{value}'"
    if '"' not in value and not re.search(r"\\[nr]", value):
        return f'"{value}"'
    if "`" not in value:
        return f"`{value}`"
    raise ValueError("this value cannot be written as a dotenv value (it mixes ', \" and `)")
