import { createHmac, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Db } from "./db.js";
import { AuthError, principalFromToken } from "./auth.js";
import { NotFoundError, TenantScope } from "./repo.js";

const WEBHOOK_TOLERANCE_SECONDS = 300;

export async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

function send(res: ServerResponse, status: number, body: unknown, type = "application/json") {
  res.writeHead(status, { "content-type": type });
  res.end(type === "application/json" ? JSON.stringify(body) : String(body));
}

async function scopeFor(db: Db, req: IncomingMessage) {
  const header = req.headers.authorization ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : undefined;
  return new TenantScope(db, await principalFromToken(db, token));
}

const csvCell = (v: unknown) => {
  const s = String(v ?? "");
  // Neutralise spreadsheet formula injection and escape quotes.
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return `"${safe.replace(/"/g, '""')}"`;
};

/** REST endpoints used by the web app. Tenant always comes from the session token. */
export async function handleApi(db: Db, req: IncomingMessage, res: ServerResponse, url: URL) {
  try {
    if (req.method === "GET" && url.pathname === "/api/customers/export") {
      const scope = await scopeFor(db, req);
      scope.requireRole("admin", "agent");
      const rows = await scope.listCustomers(undefined, 1000);
      const csv = ["id,name,email,plan", ...rows.map((r: any) => [r.id, r.name, r.email, r.plan].map(csvCell).join(","))].join("\n");
      await scope.audit("api.customers.export", {}, "ok");
      return send(res, 200, csv, "text/csv");
    }
    const inv = url.pathname.match(/^\/api\/invoices\/([\w-]+)$/);
    if (req.method === "GET" && inv) {
      const scope = await scopeFor(db, req);
      const one = await scope.getInvoice(inv[1]);
      return send(res, 200, one);
    }
    return send(res, 404, { error: "not found" });
  } catch (err) {
    if (err instanceof AuthError) return send(res, 401, { error: err.message });
    if (err instanceof NotFoundError) return send(res, 404, { error: "not found" });
    if ((err as Error).name === "ForbiddenError")
      return send(res, 403, { error: (err as Error).message });
    return send(res, 500, { error: "internal error" });
  }
}

/** Verifies a Stripe-style signature header: `t=<unix>,v1=<hex hmac of "t.body">`. */
export function verifyStripeSignature(rawBody: string, header: string | undefined, secret: string, now = Date.now()) {
  if (!header) return false;
  const parts = Object.fromEntries(header.split(",").map((p) => p.split("=") as [string, string]));
  const t = Number(parts.t);
  if (!t || !parts.v1) return false;
  if (Math.abs(now / 1000 - t) > WEBHOOK_TOLERANCE_SECONDS) return false; // replay window
  const expected = createHmac("sha256", secret).update(`${t}.${rawBody}`).digest("hex");
  const a = Buffer.from(expected, "hex");
  const b = Buffer.from(parts.v1, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Stripe webhook: signature-checked, each event processed once, tenant taken from our own invoice row. */
export async function handleStripeWebhook(db: Db, req: IncomingMessage, res: ServerResponse) {
  const raw = await readBody(req);
  const secret = process.env.STRIPE_WEBHOOK_SECRET ?? "whsec_dev_only";
  if (!verifyStripeSignature(raw, req.headers["stripe-signature"] as string | undefined, secret)) {
    return send(res, 400, { error: "invalid signature" });
  }
  const event = JSON.parse(raw) as {
    id: string;
    type: string;
    data: { object: { amount_refunded?: number; metadata?: { invoice_id?: string } } };
  };
  const first = await db.query("insert into processed_webhook_events (event_id) values ($1) on conflict do nothing returning event_id", [event.id]);
  if (!first.rows[0]) return send(res, 200, { received: true, duplicate: true });

  if (event.type === "invoice.paid") {
    const invoiceId = event.data.object.metadata?.invoice_id;
    if (invoiceId) await db.query("update invoices set status = 'paid' where id = $1 and status = 'open'", [invoiceId]);
  }
  if (event.type === "charge.refunded") {
    const invoiceId = event.data.object.metadata?.invoice_id;
    const total = event.data.object.amount_refunded ?? 0;
    // Stripe sends the running total, so set it (never add it): replays can't inflate the refund.
    if (invoiceId)
      await db.query(
        `update invoices set refunded_cents = least(amount_cents, greatest(refunded_cents, $2)),
                status = case when $2 >= amount_cents then 'refunded' else 'partially_refunded' end
          where id = $1`,
        [invoiceId, total],
      );
  }
  return send(res, 200, { received: true });
}
