import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createDb, type Db } from "../src/db.js";
import { issueToken, principalFromToken } from "../src/auth.js";
import { createServer } from "../src/server.js";

export async function freshDb() {
  return createDb();
}

/** Connects a real MCP client to the server as the given user, over an in-memory transport. */
export async function connectAs(db: Db, userId: string) {
  const token = await issueToken(userId);
  const server = createServer(db, () => principalFromToken(db, token));
  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  await server.connect(serverT);
  const client = new Client({ name: "test", version: "1.0.0" });
  await client.connect(clientT);
  return {
    async call(name: string, args: Record<string, unknown> = {}) {
      const r = (await client.callTool({ name, arguments: args })) as { isError?: boolean; content: { text: string }[] };
      const text = r.content[0]?.text ?? "";
      return { isError: !!r.isError, text, json: r.isError ? undefined : JSON.parse(text) };
    },
    client,
  };
}
