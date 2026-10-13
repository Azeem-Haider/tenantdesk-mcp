import { randomUUID } from "node:crypto";
import type { Db } from "./db.js";
import type { Principal, Role } from "./auth.js";

export class ForbiddenError extends Error {}
export class NotFoundError extends Error {}

/** Largest refund the AI is allowed to start, in cents. Bigger refunds go through the dashboard. */
export const REFUND_LIMIT_CENTS = 50_000;
export const REFUND_CONFIRM_TTL_MINUTES = 10;

/**
 * The only way tools touch data. Every query is scoped to the caller's tenant here,
 * in one place, so a tool cannot forget the filter and there is no tenant argument to spoof.
 */
export class TenantScope {
  constructor(private db: Db, readonly principal: Principal) {}

  private get tenant() {
    return this.principal.tenantId;
  }

  requireRole(...roles: Role[]) {
    if (!roles.includes(this.principal.role)) {
      throw new ForbiddenError(`role '${this.principal.role}' cannot do this; needs ${roles.join(" or ")}`);
    }
  }

  async listCustomers(query: string | undefined, limit: number) {
    const r = await this.db.query(
      `select id, name, email, plan from customers
        where tenant_id = $1 and ($2::text is null or name ilike '%' || $2 || '%' or email ilike '%' || $2 || '%')
        order by name limit $3`,
      [this.tenant, query ?? null, limit],
    );
    return r.rows;
  }

  async getCustomer(customerId: string) {
    const r = await this.db.query(
      "select id, name, email, plan from customers where tenant_id = $1 and id = $2",
      [this.tenant, customerId],
    );
    // Same answer whether the id belongs to another tenant or doesn't exist, so ids can't be probed.
    if (!r.rows[0]) throw new NotFoundError("customer not found");
    const invoices = await this.db.query(
      `select count(*)::int as count, coalesce(sum(amount_cents - refunded_cents), 0)::int as net_cents
         from invoices where tenant_id = $1 and customer_id = $2`,
      [this.tenant, customerId],
    );
    return { ...r.rows[0], invoices: invoices.rows[0] };
  }

  async searchInvoices(f: { status?: string; customerId?: string; from?: string; to?: string; limit: number }) {
    const r = await this.db.query(
      `select id, customer_id, amount_cents, refunded_cents, status, issued_at from invoices
        where tenant_id = $1
          and ($2::text is null or status = $2)
          and ($3::text is null or customer_id = $3)
          and ($4::date is null or issued_at >= $4)
          and ($5::date is null or issued_at <= $5)
        order by issued_at desc limit $6`,
      [this.tenant, f.status ?? null, f.customerId ?? null, f.from ?? null, f.to ?? null, f.limit],
    );
    return r.rows;
  }

  async ticketHistory(customerId: string) {
    await this.getCustomer(customerId); // 404s for other tenants' customers
    const r = await this.db.query(
      `select id, subject, status, created_at from tickets
        where tenant_id = $1 and customer_id = $2 order by created_at desc`,
      [this.tenant, customerId],
    );
    return r.rows;
  }

  async createTicket(customerId: string, subject: string, body: string) {
    this.requireRole("admin", "agent");
    await this.getCustomer(customerId);
    const id = `tk_${randomUUID().slice(0, 8)}`;
    await this.db.query(
      `insert into tickets (id, tenant_id, customer_id, subject, body, created_by) values ($1, $2, $3, $4, $5, $6)`,
      [id, this.tenant, customerId, subject, body, this.principal.userId],
    );
    return { id, customer_id: customerId, subject, status: "open" };
  }

  /** Step 1 of 2: validate and park the refund. Nothing moves until a human confirms. */
  async requestRefund(invoiceId: string, amountCents: number, reason: string) {
    this.requireRole("admin");
    if (amountCents > REFUND_LIMIT_CENTS) {
      throw new ForbiddenError(`refunds above $${REFUND_LIMIT_CENTS / 100} must be done in the dashboard`);
    }
    const inv = await this.db.query<{ amount_cents: number; refunded_cents: number; status: string }>(
      "select amount_cents, refunded_cents, status from invoices where tenant_id = $1 and id = $2",
      [this.tenant, invoiceId],
    );
    const invoice = inv.rows[0];
    if (!invoice) throw new NotFoundError("invoice not found");
    const refundable = invoice.amount_cents - invoice.refunded_cents;
    if (invoice.status === "open") throw new ForbiddenError("invoice is not paid yet");
    if (amountCents > refundable) throw new ForbiddenError(`only ${refundable} cents are refundable on this invoice`);

    const id = `rr_${randomUUID()}`;
    await this.db.query(
      `insert into refund_requests (id, tenant_id, invoice_id, amount_cents, reason, requested_by, status)
       values ($1, $2, $3, $4, $5, $6, 'pending')`,
      [id, this.tenant, invoiceId, amountCents, reason, this.principal.userId],
    );
    return { confirmation_id: id, invoice_id: invoiceId, amount_cents: amountCents, expires_in_minutes: REFUND_CONFIRM_TTL_MINUTES };
  }

  /** Step 2 of 2: only the same admin, inside the time window, can confirm. */
  async confirmRefund(confirmationId: string) {
    this.requireRole("admin");
    return this.db.transaction(async (tx) => {
      const r = await tx.query<{ invoice_id: string; amount_cents: number; requested_by: string; status: string; age_min: number }>(
        `select invoice_id, amount_cents, requested_by, status,
                extract(epoch from (now() - created_at)) / 60 as age_min
           from refund_requests where tenant_id = $1 and id = $2 for update`,
        [this.tenant, confirmationId],
      );
      const req = r.rows[0];
      if (!req) throw new NotFoundError("refund request not found");
      if (req.requested_by !== this.principal.userId) throw new ForbiddenError("only the admin who requested the refund can confirm it");
      if (req.status !== "pending") throw new ForbiddenError(`refund request is already ${req.status}`);
      if (req.age_min > REFUND_CONFIRM_TTL_MINUTES) {
        await tx.query("update refund_requests set status = 'expired' where id = $1", [confirmationId]);
        throw new ForbiddenError("refund request expired; start again");
      }
      // In production this is where stripe.refunds.create runs, with the request id as the idempotency key.
      const upd = await tx.query<{ refunded_cents: number; amount_cents: number }>(
        `update invoices set refunded_cents = refunded_cents + $3,
                status = case when refunded_cents + $3 >= amount_cents then 'refunded' else 'partially_refunded' end
          where tenant_id = $1 and id = $2 and refunded_cents + $3 <= amount_cents
          returning refunded_cents, amount_cents`,
        [this.tenant, req.invoice_id, req.amount_cents],
      );
      if (!upd.rows[0]) throw new ForbiddenError("invoice no longer has enough refundable balance");
      await tx.query("update refund_requests set status = 'confirmed' where id = $1", [confirmationId]);
      return { invoice_id: req.invoice_id, refunded_cents: req.amount_cents, invoice_refunded_total_cents: upd.rows[0].refunded_cents };
    });
  }

  async audit(tool: string, args: unknown, outcome: string) {
    await this.db.query(
      "insert into audit_log (tenant_id, user_id, tool, args, outcome) values ($1, $2, $3, $4, $5)",
      [this.tenant, this.principal.userId, tool, JSON.stringify(args ?? {}), outcome],
    );
  }
}
