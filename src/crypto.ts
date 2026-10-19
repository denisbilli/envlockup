// Low-level primitives, built only on node:crypto.
//
// The key-wrapping constructions (X25519 and ssh-ed25519 stanzas) follow the
// age v1 specification byte for byte (https://age-encryption.org/v1), so they
// can be checked against the reference implementation. See test/interop.test.js.

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  randomBytes,
} from "node:crypto";

export const X25519_LABEL = "age-encryption.org/v1/X25519";
export const SSH_ED25519_LABEL = "age-encryption.org/v1/ssh-ed25519";

/** HKDF-SHA256 (RFC 5869). An empty salt is equivalent to HashLen zero bytes. */
export function hkdf(ikm: Uint8Array, salt: Uint8Array, info: string, length: number): Buffer {
  const prk = createHmac("sha256", salt).update(ikm).digest();
  const blocks: Buffer[] = [];
  let prev = Buffer.alloc(0);
  for (let i = 1, n = 0; n < length; i++) {
    prev = createHmac("sha256", prk).update(prev).update(info).update(Buffer.from([i])).digest();
    blocks.push(prev);
    n += prev.length;
  }
  return Buffer.concat(blocks).subarray(0, length);
}

export function hmacSha256(key: Uint8Array, ...data: Uint8Array[]): Buffer {
  const mac = createHmac("sha256", key);
  for (const d of data) mac.update(d);
  return mac.digest();
}

export function sha256(data: Uint8Array): Buffer {
  return createHash("sha256").update(data).digest();
}

export function sha512(data: Uint8Array): Buffer {
  return createHash("sha512").update(data).digest();
}

export { randomBytes };

// --- X25519 -----------------------------------------------------------------

const PKCS8_X25519 = Buffer.from("302e020100300506032b656e04220420", "hex");
const SPKI_X25519 = Buffer.from("302a300506032b656e032100", "hex");

function x25519PrivateKey(scalar: Uint8Array) {
  if (scalar.length !== 32) throw new Error("X25519 scalar must be 32 bytes");
  return createPrivateKey({ key: Buffer.concat([PKCS8_X25519, scalar]), format: "der", type: "pkcs8" });
}

/** X25519(scalar, point). Rejects the all-zero output, as required by age. */
export function x25519(scalar: Uint8Array, point: Uint8Array): Buffer {
  if (point.length !== 32) throw new Error("X25519 point must be 32 bytes");
  let shared: Buffer;
  try {
    const publicKey = createPublicKey({ key: Buffer.concat([SPKI_X25519, point]), format: "der", type: "spki" });
    shared = diffieHellman({ privateKey: x25519PrivateKey(scalar), publicKey });
  } catch {
    throw new Error("invalid X25519 point");
  }
  if (shared.every((b) => b === 0)) throw new Error("invalid X25519 point (low order)");
  return shared;
}

/** X25519(scalar, basepoint). */
export function x25519Base(scalar: Uint8Array): Buffer {
  const der = createPublicKey(x25519PrivateKey(scalar)).export({ format: "der", type: "spki" });
  return Buffer.from(der.subarray(SPKI_X25519.length));
}

// --- Ed25519 -> X25519 --------------------------------------------------------

const P = 2n ** 255n - 19n;

function modPow(base: bigint, exp: bigint): bigint {
  let result = 1n;
  base %= P;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % P;
    base = (base * base) % P;
    exp >>= 1n;
  }
  return result;
}

const D = (P - ((121665n * modPow(121666n, P - 2n)) % P)) % P; // -121665/121666

/** Whether 32 bytes decode to a point on the Ed25519 curve (RFC 8032, 5.1.3). */
export function isEd25519Point(publicKey: Uint8Array): boolean {
  if (publicKey.length !== 32) return false;
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(i === 31 ? publicKey[i]! & 0x7f : publicKey[i]!);
  if (y >= P) return false;
  const y2 = (y * y) % P;
  const x2 = (((y2 - 1n + P) % P) * modPow((D * y2 + 1n) % P, P - 2n)) % P;
  if (x2 === 0n) return publicKey[31]! >> 7 === 0;
  return modPow(x2, (P - 1n) / 2n) === 1n;
}

/** Birational map from an Ed25519 public key to its Curve25519 u-coordinate. */
export function ed25519PublicToX25519(publicKey: Uint8Array): Buffer {
  if (publicKey.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(i === 31 ? publicKey[i]! & 0x7f : publicKey[i]!);
  if (y >= P || y === 1n) throw new Error("invalid Ed25519 public key");
  const u = ((1n + y) * modPow((1n - y + P) % P, P - 2n)) % P;
  const out = Buffer.alloc(32);
  let v = u;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** The X25519 scalar age derives from an Ed25519 seed: SHA-512(seed)[:32]. */
export function ed25519SeedToX25519(seed: Uint8Array): Buffer {
  if (seed.length !== 32) throw new Error("Ed25519 seed must be 32 bytes");
  return sha512(seed).subarray(0, 32);
}

// --- ChaCha20-Poly1305 --------------------------------------------------------

const ZERO_NONCE = Buffer.alloc(12);

/** ChaCha20-Poly1305 with a zero nonce. Each key must encrypt exactly one message. */
export function seal(key: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Buffer {
  const cipher = createCipheriv("chacha20-poly1305", key, ZERO_NONCE, { authTagLength: 16 });
  if (aad) cipher.setAAD(aad, { plaintextLength: plaintext.length });
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

export function open(key: Uint8Array, ciphertext: Uint8Array, aad?: Uint8Array): Buffer {
  if (ciphertext.length < 16) throw new Error("ciphertext too short");
  const body = ciphertext.subarray(0, ciphertext.length - 16);
  const decipher = createDecipheriv("chacha20-poly1305", key, ZERO_NONCE, { authTagLength: 16 });
  decipher.setAuthTag(ciphertext.subarray(ciphertext.length - 16));
  if (aad) decipher.setAAD(aad, { plaintextLength: body.length });
  try {
    return Buffer.concat([decipher.update(body), decipher.final()]);
  } catch {
    throw new Error("decryption failed");
  }
}
