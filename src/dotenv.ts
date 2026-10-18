// A small dotenv parser that keeps the original text, so that editing one
// variable leaves every other line (comments, blank lines, order) untouched.

export interface Entry {
  name: string;
  value: string;
  /** First and last line index (inclusive) the entry occupies. */
  start: number;
  end: number;
}

const ASSIGNMENT = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s?(.*)$/;

function parseDoubleQuoted(body: string): string {
  return body.replace(/\\([nrt"\\])/g, (_, c: string) => ({ n: "\n", r: "\r", t: "\t" })[c] ?? c);
}

export function parseEntries(lines: string[]): Entry[] {
  const entries: Entry[] = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i]!.match(ASSIGNMENT);
    if (!m) continue;
    const name = m[1]!;
    let rest = m[2]!.trimStart();
    const start = i;
    const quote = rest[0];
    let value: string;
    if (quote === '"' || quote === "'" || quote === "`") {
      // Find the closing quote, possibly on a later line (multi-line values).
      let text = rest.slice(1);
      let close = findClose(text, quote);
      while (close === -1 && i + 1 < lines.length) {
        text += "\n" + lines[++i];
        close = findClose(text, quote);
      }
      if (close === -1) {
        // Unterminated quote: treat the first line as a bare value, like dotenv.
        i = start;
        value = rest.trim();
      } else {
        const body = text.slice(0, close);
        value = quote === '"' ? parseDoubleQuoted(body) : body;
      }
    } else {
      const hash = rest.search(/\s#/);
      value = (hash === -1 ? rest : rest.slice(0, hash)).trim();
    }
    entries.push({ name, value, start, end: i });
  }
  return entries;
}

function findClose(text: string, quote: string): number {
  for (let j = 0; j < text.length; j++) {
    if (text[j] === "\\" && quote === '"') j++;
    else if (text[j] === quote) return j;
  }
  return -1;
}

/** Serialize a value so that dotenv (and this parser) read it back unchanged. */
export function formatValue(value: string): string {
  if (/^[A-Za-z0-9_./:@%+,=~-]*$/.test(value)) return value;
  if (!value.includes("'") && !value.includes("\n")) return `'${value}'`;
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\r/g, "\\r")}"`;
}

export function splitLines(text: string): string[] {
  const lines = text.split(/\r?\n/);
  if (lines.length && lines[lines.length - 1] === "") lines.pop();
  return lines;
}
