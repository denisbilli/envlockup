// ssh-agent support.
//
// An agent can sign but not decrypt, so an agent key cannot open an age
// ssh-ed25519 stanza. Instead we ask the agent to sign a fixed, envlockup-specific
// message and derive an X25519 age identity from the signature:
//
//   message   = SSHSIG blob, namespace "github.com/denisbilli/envlockup",
//               over "github.com/denisbilli/envlockup/v1/agent-identity"
//   signature = agent.sign(key, message)       // Ed25519, or RSA with rsa-sha2-512
//   secret    = HKDF-SHA-256(ikm = signature, salt = ssh_key, info = "github.com/denisbilli/envlockup/v1/agent-identity")
//
// This only works because these signatures are deterministic, which we check by
// signing twice before handing out a recipient. The derived `age1...` public key
// can be shared and wrapped for by anyone; deriving the secret needs the agent.
//
// The SSHSIG framing (as used by `ssh-keygen -Y sign`) keeps these signatures
// apart from SSH authentication and from other signing namespaces such as git.

import { connect } from "node:net";
import { createPublicKey, verify } from "node:crypto";
import { hkdf, sha512, x25519Base } from "./crypto.js";
import { type Identity, type Recipient, fingerprint, sshKeyType, x25519Identity } from "./keys.js";

export const AGENT_NAMESPACE = "github.com/denisbilli/envlockup";
const AGENT_MESSAGE = "github.com/denisbilli/envlockup/v1/agent-identity";
const AGENT_INFO = "github.com/denisbilli/envlockup/v1/agent-identity";

const SSH_AGENT_FAILURE = 5;
const SSH_AGENTC_REQUEST_IDENTITIES = 11;
const SSH_AGENT_IDENTITIES_ANSWER = 12;
const SSH_AGENTC_SIGN_REQUEST = 13;
const SSH_AGENT_SIGN_RESPONSE = 14;
const SSH_AGENT_RSA_SHA2_512 = 4;

/** Key types whose agent signatures are deterministic. */
const SUPPORTED_TYPES = new Set(["ssh-ed25519", "ssh-rsa"]);

export interface AgentKey {
  wire: Buffer;
  comment: string;
}

function sshString(data: Uint8Array | string): Buffer {
  const buf = typeof data === "string" ? Buffer.from(data) : Buffer.from(data);
  const len = Buffer.alloc(4);
  len.writeUInt32BE(buf.length);
  return Buffer.concat([len, buf]);
}

function readString(buf: Buffer, pos: number): [Buffer, number] {
  if (pos + 4 > buf.length) throw new Error("malformed ssh-agent response");
  const len = buf.readUInt32BE(pos);
  if (pos + 4 + len > buf.length) throw new Error("malformed ssh-agent response");
  return [buf.subarray(pos + 4, pos + 4 + len), pos + 4 + len];
}

export function agentSocket(env: Record<string, string | undefined> = process.env): string | null {
  if (env.SSH_AUTH_SOCK) return env.SSH_AUTH_SOCK;
  // OpenSSH for Windows (and 1Password on Windows) listen on this named pipe.
  return process.platform === "win32" ? "\\\\.\\pipe\\openssh-ssh-agent" : null;
}

/** A minimal ssh-agent client (draft-miller-ssh-agent): list keys and sign. */
export class AgentClient {
  constructor(private readonly socketPath: string) {}

  private request(type: number, payload: Buffer = Buffer.alloc(0)): Promise<{ type: number; body: Buffer }> {
    return new Promise((resolve, reject) => {
      const sock = connect(this.socketPath);
      const chunks: Buffer[] = [];
      let settled = false;
      const finish = (err: Error | null, value?: { type: number; body: Buffer }) => {
        if (settled) return;
        settled = true;
        sock.destroy();
        if (err) reject(err);
        else resolve(value!);
      };
      sock.setTimeout(30_000, () => finish(new Error("ssh-agent did not answer")));
      sock.on("error", (err) => finish(new Error(`cannot reach ssh-agent at ${this.socketPath}: ${err.message}`)));
      sock.on("connect", () => {
        const msg = Buffer.concat([Buffer.from([type]), payload]);
        const len = Buffer.alloc(4);
        len.writeUInt32BE(msg.length);
        sock.write(Buffer.concat([len, msg]));
      });
      sock.on("data", (chunk) => {
        chunks.push(chunk);
        const buf = Buffer.concat(chunks);
        if (buf.length >= 4 && buf.length >= 4 + buf.readUInt32BE(0)) {
          const len = buf.readUInt32BE(0);
          if (len < 1) return finish(new Error("malformed ssh-agent response"));
          finish(null, { type: buf[4]!, body: buf.subarray(5, 4 + len) });
        }
      });
      sock.on("end", () => finish(new Error("ssh-agent closed the connection")));
    });
  }

  async keys(): Promise<AgentKey[]> {
    const res = await this.request(SSH_AGENTC_REQUEST_IDENTITIES);
    if (res.type !== SSH_AGENT_IDENTITIES_ANSWER) throw new Error("ssh-agent refused to list keys");
    const count = res.body.readUInt32BE(0);
    const keys: AgentKey[] = [];
    let pos = 4;
    for (let i = 0; i < count; i++) {
      const [wire, next] = readString(res.body, pos);
      const [comment, after] = readString(res.body, next);
      keys.push({ wire: Buffer.from(wire), comment: comment.toString() });
      pos = after;
    }
    return keys;
  }

  async sign(wire: Buffer, data: Buffer, flags = 0): Promise<Buffer> {
    const res = await this.request(SSH_AGENTC_SIGN_REQUEST, Buffer.concat([sshString(wire), sshString(data), uint32(flags)]));
    if (res.type === SSH_AGENT_FAILURE) throw new Error("ssh-agent refused to sign (was the request denied?)");
    if (res.type !== SSH_AGENT_SIGN_RESPONSE) throw new Error("unexpected ssh-agent response");
    return Buffer.from(readString(res.body, 0)[0]);
  }
}

function uint32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
}

/** The SSHSIG "signed data" structure for the envlockup namespace. */
export function signedData(): Buffer {
  return Buffer.concat([
    Buffer.from("SSHSIG"),
    sshString(AGENT_NAMESPACE),
    sshString(""),
    sshString("sha512"),
    sshString(sha512(Buffer.from(AGENT_MESSAGE))),
  ]);
}

function publicKeyObject(wire: Buffer) {
  const type = sshKeyType(wire);
  if (type === "ssh-ed25519") {
    const [, pos] = readString(wire, 0);
    const [raw] = readString(wire, pos);
    return createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]), format: "der", type: "spki" });
  }
  // ssh-rsa: string type, mpint e, mpint n
  const [, p1] = readString(wire, 0);
  const [e, p2] = readString(wire, p1);
  const [n] = readString(wire, p2);
  const strip = (b: Buffer) => (b[0] === 0 ? b.subarray(1) : b).toString("base64url");
  return createPublicKey({ key: { kty: "RSA", e: strip(e), n: strip(n) }, format: "jwk" });
}

/** Check an agent signature and turn it into the 32-byte X25519 secret. */
export function deriveSecret(wire: Buffer, signature: Buffer): Buffer {
  const keyType = sshKeyType(wire);
  const [sigType, pos] = readString(signature, 0);
  const [sig] = readString(signature, pos);
  const expected = keyType === "ssh-ed25519" ? "ssh-ed25519" : "rsa-sha2-512";
  if (sigType.toString() !== expected) throw new Error(`ssh-agent returned a ${sigType} signature, expected ${expected}`);
  const ok = verify(keyType === "ssh-ed25519" ? null : "sha512", signedData(), publicKeyObject(wire), sig);
  if (!ok) throw new Error("ssh-agent returned an invalid signature");
  return hkdf(sig, wire, AGENT_INFO, 32);
}

function signFlags(wire: Buffer): number {
  return sshKeyType(wire) === "ssh-rsa" ? SSH_AGENT_RSA_SHA2_512 : 0;
}

export function isSupportedAgentKey(key: AgentKey): boolean {
  return SUPPORTED_TYPES.has(sshKeyType(key.wire));
}

/** The age identity an agent key stands for. */
export async function agentIdentity(client: AgentClient, key: AgentKey): Promise<Identity & { recipient: AgentRecipient }> {
  const signature = await client.sign(key.wire, signedData(), signFlags(key.wire));
  return x25519Identity(deriveSecret(key.wire, signature), key.comment, key.wire) as Identity & { recipient: AgentRecipient };
}

type AgentRecipient = Extract<Recipient, { type: "ssh-agent" }>;

/**
 * The shareable recipient for an agent key. Signs twice to make sure the agent's
 * signatures are deterministic: otherwise the key could never be derived again.
 */
export async function agentRecipient(client: AgentClient, key: AgentKey): Promise<Recipient> {
  if (!isSupportedAgentKey(key)) {
    throw new Error(`${sshKeyType(key.wire)} agent keys are not supported (their signatures are not deterministic); use ssh-ed25519 or ssh-rsa`);
  }
  const first = await agentIdentity(client, key);
  const second = await agentIdentity(client, key);
  if (!first.recipient.publicKey.equals(second.recipient.publicKey)) {
    throw new Error(`the ssh-agent key ${fingerprint(first.recipient)} does not produce deterministic signatures, so envlockup cannot use it`);
  }
  return first.recipient;
}

/** Pick an agent key by fingerprint, comment or public key; or the only one there is. */
export function selectAgentKey(keys: AgentKey[], selector?: string, preferred?: Buffer): AgentKey {
  const usable = keys.filter(isSupportedAgentKey);
  const fp = (k: AgentKey) => fingerprint({ type: "ssh-agent", wire: k.wire, publicKey: Buffer.alloc(32), label: "" });
  if (selector) {
    const matches = usable.filter((k) => fp(k) === selector || fp(k) === `SHA256:${selector}` || k.comment === selector);
    if (matches.length === 1) return matches[0]!;
    throw new Error(matches.length ? `"${selector}" matches more than one agent key` : `no ssh-agent key matches "${selector}"`);
  }
  const pref = preferred && usable.find((k) => k.wire.equals(preferred));
  if (pref) return pref;
  if (usable.length === 1) return usable[0]!;
  if (usable.length === 0) throw new Error("ssh-agent has no ssh-ed25519 or ssh-rsa keys. Add one with `ssh-add`.");
  const list = usable.map((k) => `  ${fp(k)}  ${k.comment}`).join("\n");
  throw new Error(`ssh-agent has several keys; choose one with --key:\n${list}`);
}

/** Find the agent secret for one of `recipients`, if the agent holds a matching key. */
export async function agentSecretFor(
  client: AgentClient,
  recipients: Recipient[],
): Promise<{ secret: Buffer; wire: Buffer; comment: string } | null> {
  const wanted = recipients.filter((r): r is AgentRecipient => r.type === "ssh-agent");
  if (wanted.length === 0) return null;
  const keys = await client.keys();
  for (const r of wanted) {
    const key = keys.find((k) => k.wire.equals(r.wire));
    if (!key) continue;
    const signature = await client.sign(key.wire, signedData(), signFlags(key.wire));
    const secret = deriveSecret(key.wire, signature);
    if (x25519Base(secret).equals(r.publicKey)) {
      return { secret, wire: key.wire, comment: key.comment };
    }
  }
  return null;
}

export async function agentIdentityFor(client: AgentClient, recipients: Recipient[]): Promise<Identity | null> {
  const found = await agentSecretFor(client, recipients);
  return found && x25519Identity(found.secret, found.comment, found.wire);
}
