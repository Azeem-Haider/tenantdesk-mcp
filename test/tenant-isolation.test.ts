import { test } from "node:test";
import assert from "node:assert/strict";
import { connectAs, freshDb } from "./helpers.js";

test("an Acme user only ever sees Acme customers", async () => {
  const db = await freshDb();
  const ana = await connectAs(db, "u_ana");
  const r = await ana.call("list_customers");
  assert.equal(r.isError, false);
  const ids = r.json.map((c: { id: string }) => c.id);
  assert.deepEqual(ids.sort(), ["c_acme_1", "c_acme_2", "c_acme_3"]);
});

test("asking for another tenant's customer by id returns not found, not the record", async () => {
  const db = await freshDb();
  const ana = await connectAs(db, "u_ana");
  const r = await ana.call("get_customer", { customer_id: "c_bright_1" });
  assert.equal(r.isError, true);
  assert.match(r.text, /not found/);
  assert.doesNotMatch(r.text, /Sam Okafor/);
});

test("the not-found answer is identical for other tenants' ids and ids that don't exist", async () => {
  const db = await freshDb();
  const ana = await connectAs(db, "u_ana");
  const foreign = await ana.call("get_customer", { customer_id: "c_bright_1" });
  const missing = await ana.call("get_customer", { customer_id: "c_does_not_exist" });
  assert.equal(foreign.text, missing.text);
});

test("injected tenant arguments are ignored: the schema has no tenant field to spoof", async () => {
  const db = await freshDb();
  const ana = await connectAs(db, "u_ana");
  const r = await ana.call("list_customers", { tenant_id: "t_bright" } as Record<string, unknown>);
  const ids = (r.json ?? []).map((c: { id: string }) => c.id);
  assert.ok(!ids.includes("c_bright_1"), "must never return Brightside data");
});

test("invoice search and ticket history stay inside the tenant", async () => {
  const db = await freshDb();
  const dev = await connectAs(db, "u_dev");
  const inv = await dev.call("search_invoices", {});
  assert.ok(inv.json.every((i: { id: string }) => i.id.startsWith("inv_b")));
  const tickets = await dev.call("get_ticket_history", { customer_id: "c_acme_1" });
  assert.equal(tickets.isError, true);
});

test("a refund cannot be prepared against another tenant's invoice", async () => {
  const db = await freshDb();
  const ana = await connectAs(db, "u_ana");
  const r = await ana.call("request_refund", { invoice_id: "inv_b1", amount_cents: 1000, reason: "cross-tenant probe" });
  assert.equal(r.isError, true);
  assert.match(r.text, /not found/);
});
