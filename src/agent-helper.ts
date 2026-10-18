// Runs in a child process so that the synchronous config() can talk to
// ssh-agent: reads the file's recipients on stdin, prints the derived secret.
import { AgentClient, agentSecretFor, agentSocket } from "./agent.js";
import { parseRecipient } from "./keys.js";

async function main() {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  const recipients = (JSON.parse(Buffer.concat(chunks).toString()) as string[]).map((r) => parseRecipient(r));
  const socket = agentSocket();
  if (!socket) return process.stdout.write("{}");
  const found = await agentSecretFor(new AgentClient(socket), recipients);
  process.stdout.write(JSON.stringify(found ? { secret: found.secret.toString("hex"), wire: found.wire.toString("base64"), comment: found.comment } : {}));
}

main().catch((err: Error) => {
  process.stderr.write(err.message);
  process.exit(1);
});
