import { test } from "node:test";
import assert from "node:assert/strict";
import { APP_ROLE, createPostgresDb, migrate, seedDemo, type Db } from "../src/db.js";
import { connectAs, testApp } from "./helpers.js";

/**
 * Runs against a real Postgres server when TEST_DATABASE_URL is set (CI starts one).
 * Covers what PGlite can't: a connection pool, concurrent writers and real role permissions.
 */
const url = process.env.TEST_DATABASE_URL;

async function freshPostgres(): Promise<Db> {
  const db = await createPostgresDb(url!, 5);
  await db.query("drop schema public cascade");
  await db.query("create schema public");
  await migrate(db);
  await migrate(db); // re-running migrations is a no-op
  await seedDemo(db);
  return db;
}

test("real Postgres: migrations, RLS and tenant isolation through the MCP tools", { skip: !url && "TEST_DATABASE_URL not set" }, async () => {
  const db = await freshPostgres();
  try {
    const app = await testApp({ db });
    const ana = await connectAs(app, "u_ana");
    const ids = (await ana.call("list_customers")).json.map((c: { id: string }) => c.id).sort();
    assert.deepEqual(ids, ["c_acme_1", "c_acme_2", "c_acme_3"]);
    assert.match((await ana.call("get_customer", { customer_id: "c_bright_1" })).text, /not found/);

    const unfiltered = await db.transaction(async (tx) => {
      await tx.query(`set local role ${APP_ROLE}`);
      await tx.query("select set_config('app.tenant_id', 't_bright', true)");
      return (await tx.query<{ n: number }>("select count(*)::int as n from invoices")).rows[0].n;
    });
    assert.equal(unfiltered, 2);
  } finally {
    await db.close();
  }
});

test("real Postgres: ten concurrent retries with one idempotency key create exactly one ticket", { skip: !url && "TEST_DATABASE_URL not set" }, async () => {
  const db = await freshPostgres();
  try {
    const app = await testApp({ db });
    const ben = await connectAs(app, "u_ben");
    const args = { customer_id: "c_acme_1", subject: "Concurrent retry", body: "same request", idempotency_key: "concurrent-0001" };
    const results = await Promise.all(Array.from({ length: 10 }, () => ben.call("create_ticket", args)));
    assert.ok(results.every((r) => !r.isError), results.map((r) => r.text).join("\n"));
    assert.equal(new Set(results.map((r) => r.json.id)).size, 1);
    const n = await db.query<{ n: number }>("select count(*)::int as n from tickets where subject = 'Concurrent retry'");
    assert.equal(n.rows[0].n, 1);
  } finally {
    await db.close();
  }
});

test("real Postgres: two admins racing to over-refund one invoice can't exceed its balance", { skip: !url && "TEST_DATABASE_URL not set" }, async () => {
  const db = await freshPostgres();
  try {
    await db.query("insert into users values ('u_zoe', 't_acme', 'u_zoe', 'zoe@acme.test', 'admin')");
    const app = await testApp({ db });
    const ana = await connectAs(app, "u_ana");
    const zoe = await connectAs(app, "u_zoe");
    // inv_a3 is $45.00; each admin prepares $30.00, then both confirm at the same moment.
    const a = await ana.call("request_refund", { invoice_id: "inv_a3", amount_cents: 3000, reason: "race test a" });
    const z = await zoe.call("request_refund", { invoice_id: "inv_a3", amount_cents: 3000, reason: "race test z" });
    const [ra, rz] = await Promise.all([
      ana.call("confirm_refund", { confirmation_id: a.json.confirmation_id }),
      zoe.call("confirm_refund", { confirmation_id: z.json.confirmation_id }),
    ]);
    assert.equal([ra, rz].filter((r) => !r.isError).length, 1, "exactly one refund wins");
    const inv = await db.query<{ refunded_cents: number }>("select refunded_cents from invoices where id = 'inv_a3'");
    assert.equal(inv.rows[0].refunded_cents, 3000);
    assert.equal(app.payments.refunds.size, 1, "Stripe called once");
  } finally {
    await db.close();
  }
});
