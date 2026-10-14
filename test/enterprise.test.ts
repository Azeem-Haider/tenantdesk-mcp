import { test } from "node:test";
import assert from "node:assert/strict";
import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair, type KeyLike } from "jose";
import { APP_ROLE } from "../src/db.js";
import { Authenticator, SCOPES, oidcVerifier } from "../src/auth.js";
import { loadConfig } from "../src/config.js";
import { MemoryRateLimiter } from "../src/ratelimit.js";
import { connectAs, testApp } from "./helpers.js";

test("row-level security: even an unfiltered query only sees the current tenant, and nothing without one", async () => {
  const { db } = await testApp();
  const asTenant = (tenant: string | null) =>
    db.transaction(async (tx) => {
      await tx.query(`set local role ${APP_ROLE}`);
      if (tenant) await tx.query("select set_config('app.tenant_id', $1, true)", [tenant]);
      return (await tx.query<{ id: string }>("select id from customers order by id")).rows.map((r) => r.id);
    });
  assert.deepEqual(await asTenant("t_acme"), ["c_acme_1", "c_acme_2", "c_acme_3"]);
  assert.deepEqual(await asTenant("t_bright"), ["c_bright_1", "c_bright_2"]);
  assert.deepEqual(await asTenant(null), [], "fails closed when no tenant is set");
});

test("the audit log is append-only for the application role", async () => {
  const { db } = await testApp();
  const ana = await connectAs(await testApp({ db }), "u_ana");
  await ana.call("list_customers");
  for (const sql of ["update audit_log set outcome = 'ok'", "delete from audit_log"]) {
    await assert.rejects(
      db.transaction(async (tx) => {
        await tx.query(`set local role ${APP_ROLE}`);
        await tx.query("select set_config('app.tenant_id', 't_acme', true)");
        await tx.query(sql);
      }),
      /permission denied/,
    );
  }
});

test("OAuth scopes limit the agent below the user's role: a read-only token can't write or refund", async () => {
  const app = await testApp();
  const ana = await connectAs(app, "u_ana", [SCOPES.read]); // Ana is an admin, but this token is read-only
  assert.equal((await ana.call("list_customers")).isError, false);
  const t = await ana.call("create_ticket", { customer_id: "c_acme_1", subject: "Hello", body: "test" });
  assert.match(t.text, /denied: token is missing the 'tenantdesk:write' scope/);
  const r = await ana.call("request_refund", { invoice_id: "inv_a1", amount_cents: 1000, reason: "goodwill credit" });
  assert.match(r.text, /denied: token is missing the 'tenantdesk:refunds' scope/);
});

test("a downgraded user loses write access on the very next call, with the same token", async () => {
  const app = await testApp();
  const ben = await connectAs(app, "u_ben");
  assert.equal((await ben.call("create_ticket", { customer_id: "c_acme_1", subject: "First", body: "ok" })).isError, false);
  await app.db.query("update users set role = 'viewer' where id = 'u_ben'");
  const r = await ben.call("create_ticket", { customer_id: "c_acme_1", subject: "Second", body: "should fail" });
  assert.match(r.text, /denied: role 'viewer'/);
});

test("idempotency keys: a retried write returns the first result and creates nothing new", async () => {
  const app = await testApp();
  const ben = await connectAs(app, "u_ben");
  const args = { customer_id: "c_acme_2", subject: "Call back", body: "Monday 10am", idempotency_key: "retry-key-0001" };
  const first = await ben.call("create_ticket", args);
  const retry = await ben.call("create_ticket", args);
  assert.equal(retry.json.id, first.json.id);
  const n = await app.db.query<{ n: number }>("select count(*)::int as n from tickets where subject = 'Call back'");
  assert.equal(n.rows[0].n, 1);
  const reused = await ben.call("create_ticket", { ...args, body: "different body" });
  assert.match(reused.text, /denied: idempotency key was already used for a different request/);
});

test("confirmed refunds go to the payment provider once, keyed by the confirmation id", async () => {
  const app = await testApp();
  const ana = await connectAs(app, "u_ana");
  const req = await ana.call("request_refund", { invoice_id: "inv_a1", amount_cents: 2500, reason: "double charge" });
  const ok = await ana.call("confirm_refund", { confirmation_id: req.json.confirmation_id });
  assert.equal(ok.isError, false);
  assert.match(ok.json.refund_id, /^re_/);
  const sent = [...app.payments.refunds.values()];
  assert.equal(sent.length, 1);
  assert.equal(sent[0].idempotencyKey, req.json.confirmation_id);
  assert.equal(sent[0].paymentIntent, "pi_demo_a1");
  assert.equal(sent[0].amountCents, 2500);
});

test("if the payment provider fails, nothing is refunded and the request can be retried", async () => {
  const app = await testApp();
  let fail = true;
  const original = app.payments.refund.bind(app.payments);
  app.payments.refund = async (r) => {
    if (fail) throw new Error("stripe timeout");
    return original(r);
  };
  const ana = await connectAs(app, "u_ana");
  const req = await ana.call("request_refund", { invoice_id: "inv_a4", amount_cents: 1000, reason: "service issue" });
  const failed = await ana.call("confirm_refund", { confirmation_id: req.json.confirmation_id });
  assert.equal(failed.text, "error: internal error", "provider errors are not leaked to the model");
  const inv = await app.db.query<{ refunded_cents: number }>("select refunded_cents from invoices where id = 'inv_a4'");
  assert.equal(inv.rows[0].refunded_cents, 0, "balance reservation rolled back");
  fail = false;
  const retried = await ana.call("confirm_refund", { confirmation_id: req.json.confirmation_id });
  assert.equal(retried.isError, false);
  assert.equal(retried.json.invoice_refunded_total_cents, 1000);
});

test("OIDC tokens: right issuer, audience and signature accepted; anything else rejected", async () => {
  const app = await testApp();
  const { publicKey, privateKey } = await generateKeyPair("ES256");
  const other = await generateKeyPair("ES256");
  const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "ES256" };
  const verifier = oidcVerifier({ issuer: "https://idp.example.com/", audience: "https://mcp.example.com/mcp", jwks: createLocalJWKSet({ keys: [jwk] }) });
  const auth = new Authenticator(app.db, verifier);

  const mint = (o: { iss?: string; aud?: string; exp?: string; key?: KeyLike; scope?: string } = {}) =>
    new SignJWT({ scope: o.scope ?? "tenantdesk:read" })
      .setProtectedHeader({ alg: "ES256", kid: "k1" })
      .setSubject("u_dev")
      .setIssuer(o.iss ?? "https://idp.example.com/")
      .setAudience(o.aud ?? "https://mcp.example.com/mcp")
      .setIssuedAt()
      .setExpirationTime(o.exp ?? "5m")
      .sign(o.key ?? privateKey);

  const p = await auth.principalFromToken(await mint());
  assert.deepEqual([p.userId, p.tenantId, p.role, [...p.scopes]], ["u_dev", "t_bright", "admin", ["tenantdesk:read"]]);

  for (const [label, token] of [
    ["wrong audience (token for another API)", await mint({ aud: "https://other-api.example.com" })],
    ["wrong issuer", await mint({ iss: "https://evil.example.com/" })],
    ["expired", await mint({ exp: "-1m" })],
    ["signed by another key", await mint({ key: other.privateKey })],
  ] as const) {
    await assert.rejects(auth.principalFromToken(token), /invalid or expired token/, label);
  }
});

test("production config refuses dev auth, demo data and default secrets", () => {
  assert.throws(
    () => loadConfig({ NODE_ENV: "production", SEED_DEMO: "true" }),
    (e: Error) =>
      /AUTH_MODE: dev auth is not allowed/.test(e.message) &&
      /DATABASE_URL: required in production/.test(e.message) &&
      /STRIPE_WEBHOOK_SECRET/.test(e.message) &&
      /SEED_DEMO/.test(e.message),
  );
  const ok = loadConfig({
    NODE_ENV: "production",
    AUTH_MODE: "oidc",
    OIDC_ISSUER: "https://idp.example.com/",
    DATABASE_URL: "postgres://app@db/tenantdesk",
    STRIPE_WEBHOOK_SECRET: "whsec_live_xxx",
    SEED_DEMO: "false",
  });
  assert.equal(ok.AUTH_MODE, "oidc");
});

test("token bucket refills over time", () => {
  let now = 0;
  const limiter = new MemoryRateLimiter(60, () => now); // 1 per second
  for (let i = 0; i < 60; i++) assert.equal(limiter.take("t").ok, true);
  const blocked = limiter.take("t");
  assert.equal(blocked.ok, false);
  now += 1000;
  assert.equal(limiter.take("t").ok, true);
});
