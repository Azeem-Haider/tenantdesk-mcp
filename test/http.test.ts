import { test } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createDb } from "../src/db.js";
import { issueToken } from "../src/auth.js";
import { startHttp } from "../src/http.js";

test("HTTP transport: no token is rejected with 401, a valid token works and stays in its tenant", async () => {
  const db = await createDb();
  const http = await startHttp(db, 0);
  const url = `http://localhost:${(http.address() as AddressInfo).port}/mcp`;
  try {
    const noAuth = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    assert.equal(noAuth.status, 401);

    const token = await issueToken("u_dev");
    const client = new Client({ name: "http-test", version: "1.0.0" });
    await client.connect(new StreamableHTTPClientTransport(new URL(url), {
      requestInit: { headers: { authorization: `Bearer ${token}` } },
    }));
    const tools = await client.listTools();
    assert.ok(tools.tools.some((t) => t.name === "confirm_refund"));
    const r = (await client.callTool({ name: "list_customers", arguments: {} })) as { content: { text: string }[] };
    const ids = JSON.parse(r.content[0].text).map((c: { id: string }) => c.id).sort();
    assert.deepEqual(ids, ["c_bright_1", "c_bright_2"]);
    await client.close();
  } finally {
    http.close();
  }
});
