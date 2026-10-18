// A dotenv parser that keeps the original text, so that editing one variable
// leaves every other line (comments, blank lines, order) untouched.
//
// Values are read with the exact algorithm of dotenv 16/17 (same regex, same
// unquoting), so a file means the same thing to envseal and to dotenv. That
// includes dotenv's quirks: an unquoted value ends at the first `#`, and in
// double quotes only `\n` and `\r` are unescaped. test/dotenv-compat.test.js
// checks this against the real dotenv package.

export interface Entry {
  name: string;
  value: string;
  /** First and last line index (inclusive) the entry occupies. */
  start: number;
  end: number;
}

// Verbatim from dotenv's lib/main.js.
const LINE =
  /(?:^|^)\s*(?:export\s+)?([\w.-]+)(?:\s*=\s*?|:\s+?)(\s*'(?:\\'|[^'])*'|\s*"(?:\\"|[^"])*"|\s*`(?:\\`|[^`])*`|[^#\r\n]+)?\s*(?:#.*)?(?:$|$)/gm;

function unquote(raw: string): string {
  let value = raw.trim();
  const quote = value[0];
  value = value.replace(/^(['"`])([\s\S]*)\1$/gm, "$2");
  if (quote === '"') value = value.replace(/\\n/g, "\n").replace(/\\r/g, "\r");
  return value;
}

export function parseEntries(lines: string[]): Entry[] {
  const text = lines.join("\n");
  // Offsets of the start of each line, to map matches back to line numbers.
  const lineStarts = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === "\n") lineStarts.push(i + 1);
  const lineAt = (offset: number) => {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStarts[mid]! <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo;
  };

  const entries: Entry[] = [];
  for (const m of text.matchAll(LINE)) {
    const matched = m[0];
    const first = matched.search(/\S/);
    const last = matched.trimEnd().length - 1;
    entries.push({
      name: m[1]!,
      value: unquote(m[2] ?? ""),
      start: lineAt(m.index + first),
      end: lineAt(m.index + last),
    });
  }
  return entries;
}

/**
 * Serialize a value so that dotenv (and this parser) read it back unchanged.
 * Throws for the rare values dotenv's syntax cannot represent.
 */
export function formatValue(value: string): string {
  if (/^[A-Za-z0-9_./:@%+,=~-]*$/.test(value)) return value;
  // dotenv turns every \r\n or \r into \n before parsing; only the \r escape inside double quotes survives.
  if (value.includes("\r")) {
    if (!value.includes('"') && !/\\[nr]/.test(value)) return `"${value.replace(/\r/g, "\\r")}"`;
    throw new Error("this value cannot be written as a plain dotenv value (it has a carriage return and a \" or \\n); store it encrypted");
  }
  if (!value.includes("'")) return `'${value}'`;
  if (!value.includes('"') && !/\\[nr]/.test(value)) return `"${value}"`;
  if (!value.includes("`")) return `\`${value}\``;
  throw new Error("this value cannot be written as a plain dotenv value (it mixes ', \" and `); store it encrypted");
}

export function splitLines(text: string): string[] {
  const lines = text.split(/\r\n?|\n/);
  if (lines.length && lines[lines.length - 1] === "") lines.pop();
  return lines;
}
