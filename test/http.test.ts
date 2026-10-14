import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import type { AddressInfo } from "node:net";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { issueToken } from "../src/auth.js";
import { startHttp } from "../src/http.js";
import { MemoryRateLimiter } from "../src/ratelimit.js";
import { testApp } from "./helpers.js";

async function serve(overrides: Parameters<typeof testApp>[0] = {}) {
  const app = await testApp(overrides);
  const http = await startHttp(app, 0);
  const base = `http://localhost:${(http.address() as AddressInfo).port}`;
  return { app, base, close: () => new Promise<void>((r) => http.close(() => r())) };
}

const auth = async (user: string) => ({ authorization: `Bearer ${await issueToken(user)}` });

test("MCP over HTTP: no token gets 401 with OAuth metadata pointer; a valid token stays in its tenant", async () => {
  const { base, close } = await serve();
  try {
    const noAuth = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    assert.equal(noAuth.status, 401);
    assert.match(noAuth.headers.get("www-authenticate") ?? "", /resource_metadata=".*\/\.well-known\/oauth-protected-resource"/);

    const client = new Client({ name: "http-test", version: "1.0.0" });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: await auth("u_dev") } }));
    const tools = await client.listTools();
    assert.ok(tools.tools.some((t) => t.name === "confirm_refund"));
    const r = (await client.callTool({ name: "list_customers", arguments: {} })) as { content: { text: string }[] };
    const ids = JSON.parse(r.content[0].text).map((c: { id: string }) => c.id).sort();
    assert.deepEqual(ids, ["c_bright_1", "c_bright_2"]);
    await client.close();
  } finally {
    await close();
  }
});

test("publishes OAuth protected resource metadata (RFC 9728) for MCP clients", async () => {
  const { base, close } = await serve({ env: { OIDC_ISSUER: "https://idp.example.com", PUBLIC_URL: "https://mcp.example.com" } });
  try {
    const r = await fetch(`${base}/.well-known/oauth-protected-resource`);
    const meta = await r.json();
    assert.equal(meta.resource, "https://mcp.example.com/mcp");
    assert.deepEqual(meta.authorization_servers, ["https://idp.example.com"]);
    assert.ok(meta.scopes_supported.includes("tenantdesk:refunds"));
  } finally {
    await close();
  }
});

test("health, readiness and Prometheus metrics endpoints", async () => {
  const { base, close } = await serve();
  try {
    assert.equal((await fetch(`${base}/healthz`)).status, 200);
    assert.equal((await fetch(`${base}/readyz`)).status, 200);
    await fetch(`${base}/api/invoices/inv_a1`, { headers: await auth("u_ana") });
    const metrics = await (await fetch(`${base}/metrics`)).text();
    assert.match(metrics, /tenantdesk_http_requests_total\{route="\/api",status="200"\} 1/);
  } finally {
    await close();
  }
});

test("per-tenant rate limit returns 429 with Retry-After, and other tenants are unaffected", async () => {
  const { base, close } = await serve({ limiter: new MemoryRateLimiter(2) });
  try {
    const ana = await auth("u_ana");
    const statuses = [];
    for (let i = 0; i < 3; i++) statuses.push((await fetch(`${base}/api/invoices/inv_a1`, { headers: ana })).status);
    assert.deepEqual(statuses, [200, 200, 429]);
    const limited = await fetch(`${base}/api/invoices/inv_a1`, { headers: ana });
    assert.ok(Number(limited.headers.get("retry-after")) >= 1);
    assert.equal((await fetch(`${base}/api/invoices/inv_b1`, { headers: await auth("u_dev") })).status, 200);
  } finally {
    await close();
  }
});

test("audit log export: admins get their own tenant's trail as NDJSON, agents are refused", async () => {
  const { base, close } = await serve();
  try {
    await fetch(`${base}/api/customers/export`, { headers: await auth("u_dev") }); // a Brightside event
    await fetch(`${base}/api/customers/export`, { headers: await auth("u_ana") });
    const r = await fetch(`${base}/api/audit-log`, { headers: await auth("u_ana") });
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("content-type"), "application/x-ndjson");
    const rows = (await r.text()).trim().split("\n").map((l) => JSON.parse(l));
    assert.ok(rows.length >= 1);
    assert.ok(rows.every((row) => ["u_ana", "u_ben", "u_cara"].includes(row.user_id)), "no Brightside entries");
    assert.ok(rows.every((row) => row.request_id), "each entry carries the request id");
    assert.equal((await fetch(`${base}/api/audit-log`, { headers: await auth("u_ben") })).status, 403);
  } finally {
    await close();
  }
});

test("hardening: request id echoed, oversized bodies 413, GET /mcp 405, bad JSON 400", async () => {
  const { base, close } = await serve({ env: { MAX_BODY_BYTES: "2048" } });
  try {
    const h = await fetch(`${base}/healthz`, { headers: { "x-request-id": "req-abc-123" } });
    assert.equal(h.headers.get("x-request-id"), "req-abc-123");
    assert.equal(h.headers.get("x-content-type-options"), "nosniff");

    const headers = { ...(await auth("u_ana")), "content-type": "application/json", accept: "application/json, text/event-stream" };
    const big = await fetch(`${base}/mcp`, { method: "POST", headers, body: "x".repeat(5000) });
    assert.equal(big.status, 413);
    assert.equal((await fetch(`${base}/mcp`, { headers })).status, 405);
    assert.equal((await fetch(`${base}/mcp`, { method: "POST", headers, body: "{not json" })).status, 400);
  } finally {
    await close();
  }
});

test("Stripe webhook: bad signatures rejected, valid ones applied once, rotated secrets accepted", async () => {
  const { app, base, close } = await serve({ env: { STRIPE_WEBHOOK_SECRET: "whsec_test_new" } });
  const sign = (raw: string, secret: string, t = Math.floor(Date.now() / 1000)) =>
    `t=${t},v1=${createHmac("sha256", secret).update(`${t}.${raw}`).digest("hex")}`;
  try {
    const raw = JSON.stringify({ id: "evt_1", type: "invoice.paid", data: { object: { metadata: { invoice_id: "inv_a2" } } } });
    const bad = await fetch(`${base}/webhooks/stripe`, { method: "POST", body: raw, headers: { "stripe-signature": sign(raw, "wrong") } });
    assert.equal(bad.status, 400);
    const stale = await fetch(`${base}/webhooks/stripe`, {
      method: "POST",
      body: raw,
      headers: { "stripe-signature": sign(raw, "whsec_test_new", Math.floor(Date.now() / 1000) - 3600) },
    });
    assert.equal(stale.status, 400, "outside the 5-minute replay window");

    // During rotation Stripe sends one signature per active secret.
    const t = Math.floor(Date.now() / 1000);
    const both = `${sign(raw, "whsec_test_old", t)},v1=${sign(raw, "whsec_test_new", t).split("v1=")[1]}`;
    assert.equal((await fetch(`${base}/webhooks/stripe`, { method: "POST", body: raw, headers: { "stripe-signature": both } })).status, 200);
    const st = await app.db.query<{ status: string }>("select status from invoices where id = 'inv_a2'");
    assert.equal(st.rows[0].status, "paid");
  } finally {
    await close();
  }
});
