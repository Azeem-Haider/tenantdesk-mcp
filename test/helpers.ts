import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createDb } from "../src/db.js";
import { createApp, type App } from "../src/app.js";
import { issueToken } from "../src/auth.js";
import { FakePayments } from "../src/payments.js";
import { createServer } from "../src/server.js";

export const TEST_ENV = { NODE_ENV: "test", LOG_LEVEL: "silent" } as NodeJS.ProcessEnv;

/** A fresh app on its own in-memory Postgres with demo data and fake Stripe. */
export async function testApp(overrides: Partial<App> & { env?: NodeJS.ProcessEnv } = {}) {
  const db = overrides.db ?? (await createDb());
  const payments = new FakePayments();
  const app = await createApp({ payments, ...overrides, db, env: { ...TEST_ENV, ...overrides.env } });
  return Object.assign(app, { payments: app.payments as FakePayments });
}

/** Connects a real MCP client to the server as the given user, over an in-memory transport. */
export async function connectAs(app: App, userId: string, scopes?: string[]) {
  const token = await issueToken(userId, { scopes });
  const server = createServer(app, () => app.auth.principalFromToken(token));
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
