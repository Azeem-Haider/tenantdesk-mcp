import { createHmac, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { App } from "./app.js";
import type { Principal } from "./auth.js";
import { ForbiddenError, NotFoundError, TenantScope } from "./repo.js";

const WEBHOOK_TOLERANCE_SECONDS = 300;

export class BodyTooLargeError extends Error {}

export async function readBody(req: IncomingMessage, maxBytes: number): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > maxBytes) throw new BodyTooLargeError();
    chunks.push(c as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export function send(res: ServerResponse, status: number, body: unknown, type = "application/json", headers: Record<string, string> = {}) {
  res.writeHead(status, { "content-type": type, ...headers });
  res.end(type === "application/json" ? JSON.stringify(body) : String(body));
}

const csvCell = (v: unknown) => {
  const s = String(v ?? "");
  // Neutralise spreadsheet formula injection and escape quotes.
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return `"${safe.replace(/"/g, '""')}"`;
};

/** REST endpoints used by the web app. The caller is already authenticated; the tenant comes from their token. */
export async function handleApi(app: App, principal: Principal, requestId: string, req: IncomingMessage, res: ServerResponse, url: URL) {
  const scope = new TenantScope(app.db, principal, app.payments, requestId);
  try {
    if (req.method === "GET" && url.pathname === "/api/customers/export") {
      scope.authorize("tenantdesk:read", "admin", "agent");
      const rows = await scope.listCustomers(undefined, 1000);
      const csv = ["id,name,email,plan", ...rows.map((r: any) => [r.id, r.name, r.email, r.plan].map(csvCell).join(","))].join("\n");
      await scope.audit("api.customers.export", {}, "ok");
      return send(res, 200, csv, "text/csv", { "content-disposition": 'attachment; filename="customers.csv"' });
    }
    const inv = url.pathname.match(/^\/api\/invoices\/([\w-]+)$/);
    if (req.method === "GET" && inv) {
      return send(res, 200, await scope.getInvoice(inv[1]));
    }
    if (req.method === "GET" && url.pathname === "/api/audit-log") {
      const limit = Math.min(Number(url.searchParams.get("limit") ?? 1000) || 1000, 10_000);
      const rows = await scope.exportAudit({
        from: url.searchParams.get("from") ?? undefined,
        to: url.searchParams.get("to") ?? undefined,
        limit,
      });
      await scope.audit("api.audit_log.export", { from: url.searchParams.get("from"), to: url.searchParams.get("to") }, "ok");
      // NDJSON streams straight into Splunk, Datadog, Elastic or a SIEM.
      return send(res, 200, rows.map((r) => JSON.stringify(r)).join("\n") + "\n", "application/x-ndjson");
    }
    return send(res, 404, { error: "not found" });
  } catch (err) {
    if (err instanceof NotFoundError) return send(res, 404, { error: "not found" });
    if (err instanceof ForbiddenError) {
      await scope.audit(`api ${req.method} ${url.pathname}`, {}, "denied").catch(() => {});
      return send(res, 403, { error: err.message });
    }
    app.log.error({ err, requestId }, "api request failed");
    return send(res, 500, { error: "internal error" });
  }
}

/** Verifies a Stripe signature header: `t=<unix>,v1=<hex hmac of "t.body">`. */
export function verifyStripeSignature(rawBody: string, header: string | undefined, secret: string, now = Date.now()) {
  if (!header) return false;
  const parts = header.split(",").map((p) => p.split("=") as [string, string]);
  const t = Number(parts.find(([k]) => k === "t")?.[1]);
  const signatures = parts.filter(([k]) => k === "v1").map(([, v]) => v);
  if (!t || !signatures.length) return false;
  if (Math.abs(now / 1000 - t) > WEBHOOK_TOLERANCE_SECONDS) return false; // replay window
  const expected = Buffer.from(createHmac("sha256", secret).update(`${t}.${rawBody}`).digest("hex"), "hex");
  // Stripe sends several v1 signatures while a secret is being rotated; any valid one is enough.
  return signatures.some((s) => {
    const b = Buffer.from(s, "hex");
    return b.length === expected.length && timingSafeEqual(expected, b);
  });
}

/** Stripe webhook: signature-checked, each event processed once, tenant taken from our own invoice row. */
export async function handleStripeWebhook(app: App, raw: string, req: IncomingMessage, res: ServerResponse) {
  if (!verifyStripeSignature(raw, req.headers["stripe-signature"] as string | undefined, app.cfg.STRIPE_WEBHOOK_SECRET)) {
    app.metrics.inc("tenantdesk_webhooks_total", "Stripe webhooks by result", { result: "bad_signature" });
    return send(res, 400, { error: "invalid signature" });
  }
  let event: { id: string; type: string; data: { object: { amount_refunded?: number; metadata?: { invoice_id?: string } } } };
  try {
    event = JSON.parse(raw);
  } catch {
    return send(res, 400, { error: "invalid json" });
  }
  await app.db.transaction(async (tx) => {
    const first = await tx.query("insert into processed_webhook_events (event_id) values ($1) on conflict do nothing returning event_id", [event.id]);
    if (!first.rows[0]) {
      app.metrics.inc("tenantdesk_webhooks_total", "Stripe webhooks by result", { result: "duplicate" });
      return;
    }
    const invoiceId = event.data?.object?.metadata?.invoice_id;
    if (event.type === "invoice.paid" && invoiceId) {
      await tx.query("update invoices set status = 'paid' where id = $1 and status = 'open'", [invoiceId]);
    }
    if (event.type === "charge.refunded" && invoiceId) {
      const total = event.data.object.amount_refunded ?? 0;
      // Stripe sends the running total, so set it (never add it): replays can't inflate the refund.
      await tx.query(
        `update invoices set refunded_cents = least(amount_cents, greatest(refunded_cents, $2)),
                status = case when least(amount_cents, greatest(refunded_cents, $2)) >= amount_cents then 'refunded' else 'partially_refunded' end
          where id = $1`,
        [invoiceId, total],
      );
    }
    app.metrics.inc("tenantdesk_webhooks_total", "Stripe webhooks by result", { result: "processed" });
  });
  return send(res, 200, { received: true });
}
