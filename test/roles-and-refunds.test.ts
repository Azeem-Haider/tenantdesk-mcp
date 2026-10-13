import { test } from "node:test";
import assert from "node:assert/strict";
import { connectAs, freshDb } from "./helpers.js";

test("a viewer can read but cannot create tickets", async () => {
  const db = await freshDb();
  const cara = await connectAs(db, "u_cara");
  assert.equal((await cara.call("list_customers")).isError, false);
  const r = await cara.call("create_ticket", { customer_id: "c_acme_1", subject: "Hello", body: "test" });
  assert.equal(r.isError, true);
  assert.match(r.text, /denied/);
});

test("an agent can create tickets but cannot start refunds", async () => {
  const db = await freshDb();
  const ben = await connectAs(db, "u_ben");
  const t = await ben.call("create_ticket", { customer_id: "c_acme_2", subject: "Follow up", body: "Call back Monday" });
  assert.equal(t.isError, false);
  const r = await ben.call("request_refund", { invoice_id: "inv_a1", amount_cents: 1000, reason: "goodwill credit" });
  assert.equal(r.isError, true);
  assert.match(r.text, /denied/);
});

test("refunds need two steps; nothing moves until confirm", async () => {
  const db = await freshDb();
  const ana = await connectAs(db, "u_ana");
  const req = await ana.call("request_refund", { invoice_id: "inv_a1", amount_cents: 2000, reason: "double charge" });
  assert.equal(req.isError, false);
  const before = await db.query<{ refunded_cents: number }>("select refunded_cents from invoices where id = 'inv_a1'");
  assert.equal(before.rows[0].refunded_cents, 0);

  const ok = await ana.call("confirm_refund", { confirmation_id: req.json.confirmation_id });
  assert.equal(ok.isError, false);
  assert.equal(ok.json.invoice_refunded_total_cents, 2000);

  const again = await ana.call("confirm_refund", { confirmation_id: req.json.confirmation_id });
  assert.equal(again.isError, true, "a confirmation can only be used once");
});

test("refunds above the limit or above the invoice balance are refused", async () => {
  const db = await freshDb();
  const ana = await connectAs(db, "u_ana");
  const tooBig = await ana.call("request_refund", { invoice_id: "inv_a1", amount_cents: 60000, reason: "test limit" });
  assert.equal(tooBig.isError, true);
  const overBalance = await ana.call("request_refund", { invoice_id: "inv_a3", amount_cents: 5000, reason: "more than paid" });
  assert.equal(overBalance.isError, true);
  const unpaid = await ana.call("request_refund", { invoice_id: "inv_a2", amount_cents: 1000, reason: "not paid yet" });
  assert.equal(unpaid.isError, true);
});

test("another admin, even in the same tenant, cannot confirm someone else's refund", async () => {
  const db = await freshDb();
  await db.query("insert into users values ('u_zoe', 't_acme', 'zoe@acme.test', 'admin')");
  const ana = await connectAs(db, "u_ana");
  const zoe = await connectAs(db, "u_zoe");
  const req = await ana.call("request_refund", { invoice_id: "inv_a4", amount_cents: 1500, reason: "service issue" });
  const r = await zoe.call("confirm_refund", { confirmation_id: req.json.confirmation_id });
  assert.equal(r.isError, true);
});

test("every tool call is written to the audit log, including denied ones", async () => {
  const db = await freshDb();
  const cara = await connectAs(db, "u_cara");
  await cara.call("list_customers");
  await cara.call("create_ticket", { customer_id: "c_acme_1", subject: "Hello", body: "test" });
  const log = await db.query<{ tool: string; outcome: string; tenant_id: string }>(
    "select tool, outcome, tenant_id from audit_log where user_id = 'u_cara' order by id",
  );
  assert.deepEqual(
    log.rows.map((r) => [r.tool, r.outcome, r.tenant_id]),
    [["list_customers", "ok", "t_acme"], ["create_ticket", "denied", "t_acme"]],
  );
});

test("a token for a deleted user stops working immediately", async () => {
  const db = await freshDb();
  const eli = await connectAs(db, "u_eli");
  await db.query("delete from tickets where created_by = 'u_eli'");
  await db.query("delete from users where id = 'u_eli'");
  const r = await eli.call("list_customers");
  assert.equal(r.isError, true);
  assert.match(r.text, /unauthenticated/);
});
