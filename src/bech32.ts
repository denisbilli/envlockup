// Bech32 (BIP 173) as used by age for `age1...` recipients and
// `AGE-SECRET-KEY-1...` identities. age does not enforce the 90 character limit.

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values: number[]): number {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GENERATOR[i]!;
  }
  return chk >>> 0;
}

function hrpExpand(hrp: string): number[] {
  const out: number[] = [];
  for (const c of hrp) out.push(c.charCodeAt(0) >> 5);
  out.push(0);
  for (const c of hrp) out.push(c.charCodeAt(0) & 31);
  return out;
}

function convertBits(data: Iterable<number>, from: number, to: number, pad: boolean): number[] {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  const maxv = (1 << to) - 1;
  for (const value of data) {
    acc = (acc << from) | value;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & maxv);
  } else if (bits >= from || ((acc << (to - bits)) & maxv) !== 0) {
    throw new Error("invalid bech32 padding");
  }
  return out;
}

export function encode(hrp: string, data: Uint8Array, upper = false): string {
  const words = convertBits(data, 8, 5, true);
  const chk = polymod([...hrpExpand(hrp), ...words, 0, 0, 0, 0, 0, 0]) ^ 1;
  for (let i = 0; i < 6; i++) words.push((chk >> (5 * (5 - i))) & 31);
  const s = `${hrp}1${words.map((w) => CHARSET[w]).join("")}`;
  return upper ? s.toUpperCase() : s;
}

export function decode(s: string): { hrp: string; data: Buffer } {
  if (s !== s.toLowerCase() && s !== s.toUpperCase()) throw new Error("mixed-case bech32 string");
  const lower = s.toLowerCase();
  const pos = lower.lastIndexOf("1");
  if (pos < 1 || pos + 7 > lower.length) throw new Error("invalid bech32 string");
  const hrp = lower.slice(0, pos);
  const words: number[] = [];
  for (const c of lower.slice(pos + 1)) {
    const v = CHARSET.indexOf(c);
    if (v === -1) throw new Error("invalid bech32 character");
    words.push(v);
  }
  if (polymod([...hrpExpand(hrp), ...words]) !== 1) throw new Error("invalid bech32 checksum");
  return { hrp, data: Buffer.from(convertBits(words.slice(0, -6), 5, 8, false)) };
}
