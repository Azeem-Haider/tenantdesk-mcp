import { createHash, randomUUID } from "node:crypto";
import { APP_ROLE, type Db, type Queryable } from "./db.js";
import { SCOPES, type Principal, type Role, type Scope } from "./auth.js";
import type { PaymentProvider } from "./payments.js";

export class ForbiddenError extends Error {
  name = "ForbiddenError";
}
export class NotFoundError extends Error {
  name = "NotFoundError";
}

/** Largest refund the AI is allowed to start, in cents. Bigger refunds go through the dashboard. */
export const REFUND_LIMIT_CENTS = 50_000;
export const REFUND_CONFIRM_TTL_MINUTES = 10;

/**
 * The only way tools and endpoints touch tenant data.
 *
 * Two layers keep tenants apart:
 * 1. Every query here filters on the caller's tenant, in one place, with no tenant argument to spoof.
 * 2. Every query runs inside a transaction as the restricted `tenantdesk_app` role with
 *    `app.tenant_id` set, so Postgres row-level security hides other tenants' rows even if
 *    a filter were ever missed.
 */
export class TenantScope {
  constructor(
    private db: Db,
    readonly principal: Principal,
    private payments: PaymentProvider,
    readonly requestId?: string,
  ) {}

  private get tenant() {
    return this.principal.tenantId;
  }

  private tx<T>(fn: (tx: Queryable) => Promise<T>): Promise<T> {
    return this.db.transaction(async (tx) => {
      await tx.query(`set local role ${APP_ROLE}`);
      await tx.query("select set_config('app.tenant_id', $1, true)", [this.tenant]);
      return fn(tx);
    });
  }

  /** The token must carry the scope AND the user must hold one of the roles. */
  authorize(scope: Scope, ...roles: Role[]) {
    if (!this.principal.scopes.has(scope)) throw new ForbiddenError(`token is missing the '${scope}' scope`);
    if (roles.length && !roles.includes(this.principal.role)) {
      throw new ForbiddenError(`role '${this.principal.role}' cannot do this; needs ${roles.join(" or ")}`);
    }
  }

  /**
   * Replays the stored result when a write is retried with the same key, so an agent that
   * times out and tries again never creates a second ticket or refund request.
   */
  private async idempotent<T>(tx: Queryable, key: string | undefined, tool: string, args: unknown, fn: () => Promise<T>): Promise<T> {
    if (!key) return fn();
    const hash = createHash("sha256").update(JSON.stringify(args)).digest("hex");
    await tx.query("select pg_advisory_xact_lock(hashtext($1))", [`${this.tenant}:${key}`]);
    const prev = await tx.query<{ tool: string; request_hash: string; response: unknown }>(
      "select tool, request_hash, response from idempotency_keys where tenant_id = $1 and key = $2",
      [this.tenant, key],
    );
    if (prev.rows[0]) {
      if (prev.rows[0].tool !== tool || prev.rows[0].request_hash !== hash) {
        throw new ForbiddenError("idempotency key was already used for a different request");
      }
      const r = prev.rows[0].response;
      return (typeof r === "string" ? JSON.parse(r) : r) as T;
    }
    const result = await fn();
    await tx.query(
      "insert into idempotency_keys (tenant_id, key, tool, request_hash, response) values ($1, $2, $3, $4, $5)",
      [this.tenant, key, tool, hash, JSON.stringify(result)],
    );
    return result;
  }

  listCustomers(query: string | undefined, limit: number) {
    this.authorize(SCOPES.read);
    return this.tx(async (tx) => {
      const r = await tx.query(
        `select id, name, email, plan from customers
          where tenant_id = $1 and ($2::text is null or name ilike '%' || $2 || '%' or email ilike '%' || $2 || '%')
          order by name limit $3`,
        [this.tenant, query ?? null, limit],
      );
      return r.rows;
    });
  }

  private async customerIn(tx: Queryable, customerId: string) {
    const r = await tx.query("select id, name, email, plan from customers where tenant_id = $1 and id = $2", [this.tenant, customerId]);
    // Same answer whether the id belongs to another tenant or doesn't exist, so ids can't be probed.
    if (!r.rows[0]) throw new NotFoundError("customer not found");
    return r.rows[0];
  }

  getCustomer(customerId: string) {
    this.authorize(SCOPES.read);
    return this.tx(async (tx) => {
      const customer = await this.customerIn(tx, customerId);
      const invoices = await tx.query(
        `select count(*)::int as count, coalesce(sum(amount_cents - refunded_cents), 0)::int as net_cents
           from invoices where tenant_id = $1 and customer_id = $2`,
        [this.tenant, customerId],
      );
      return { ...customer, invoices: invoices.rows[0] };
    });
  }

  searchInvoices(f: { status?: string; customerId?: string; from?: string; to?: string; limit: number }) {
    this.authorize(SCOPES.read);
    return this.tx(async (tx) => {
      const r = await tx.query(
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
    });
  }

  getInvoice(invoiceId: string) {
    this.authorize(SCOPES.read);
    return this.tx(async (tx) => {
      const r = await tx.query(
        "select id, customer_id, amount_cents, refunded_cents, status, issued_at from invoices where tenant_id = $1 and id = $2",
        [this.tenant, invoiceId],
      );
      if (!r.rows[0]) throw new NotFoundError("invoice not found");
      return r.rows[0];
    });
  }

  ticketHistory(customerId: string) {
    this.authorize(SCOPES.read);
    return this.tx(async (tx) => {
      await this.customerIn(tx, customerId); // 404s for other tenants' customers
      const r = await tx.query(
        `select id, subject, status, created_at from tickets
          where tenant_id = $1 and customer_id = $2 order by created_at desc`,
        [this.tenant, customerId],
      );
      return r.rows;
    });
  }

  createTicket(customerId: string, subject: string, body: string, idempotencyKey?: string) {
    this.authorize(SCOPES.write, "admin", "agent");
    return this.tx((tx) =>
      this.idempotent(tx, idempotencyKey, "create_ticket", { customerId, subject, body }, async () => {
        await this.customerIn(tx, customerId);
        const id = `tk_${randomUUID().slice(0, 8)}`;
        await tx.query(
          `insert into tickets (id, tenant_id, customer_id, subject, body, created_by) values ($1, $2, $3, $4, $5, $6)`,
          [id, this.tenant, customerId, subject, body, this.principal.userId],
        );
        return { id, customer_id: customerId, subject, status: "open" };
      }),
    );
  }

  /** Step 1 of 2: validate and park the refund. Nothing moves until a human confirms. */
  requestRefund(invoiceId: string, amountCents: number, reason: string, idempotencyKey?: string) {
    this.authorize(SCOPES.refunds, "admin");
    if (amountCents > REFUND_LIMIT_CENTS) {
      throw new ForbiddenError(`refunds above $${REFUND_LIMIT_CENTS / 100} must be done in the dashboard`);
    }
    return this.tx((tx) =>
      this.idempotent(tx, idempotencyKey, "request_refund", { invoiceId, amountCents, reason }, async () => {
        const inv = await tx.query<{ amount_cents: number; refunded_cents: number; status: string }>(
          "select amount_cents, refunded_cents, status from invoices where tenant_id = $1 and id = $2",
          [this.tenant, invoiceId],
        );
        const invoice = inv.rows[0];
        if (!invoice) throw new NotFoundError("invoice not found");
        const refundable = invoice.amount_cents - invoice.refunded_cents;
        if (invoice.status === "open") throw new ForbiddenError("invoice is not paid yet");
        if (amountCents > refundable) throw new ForbiddenError(`only ${refundable} cents are refundable on this invoice`);

        const id = `rr_${randomUUID()}`;
        await tx.query(
          `insert into refund_requests (id, tenant_id, invoice_id, amount_cents, reason, requested_by, status)
           values ($1, $2, $3, $4, $5, $6, 'pending')`,
          [id, this.tenant, invoiceId, amountCents, reason, this.principal.userId],
        );
        return { confirmation_id: id, invoice_id: invoiceId, amount_cents: amountCents, expires_in_minutes: REFUND_CONFIRM_TTL_MINUTES };
      }),
    );
  }

  /**
   * Step 2 of 2: only the same admin, inside the time window, can confirm.
   * The invoice balance is reserved first, then Stripe is called with the confirmation id as the
   * idempotency key; if Stripe fails the transaction rolls back and the request stays pending for a retry.
   */
  confirmRefund(confirmationId: string) {
    this.authorize(SCOPES.refunds, "admin");
    return this.tx(async (tx) => {
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
      if (Number(req.age_min) > REFUND_CONFIRM_TTL_MINUTES) {
        throw new ForbiddenError("refund request expired; start again");
      }
      const upd = await tx.query<{ refunded_cents: number; stripe_payment_intent: string | null }>(
        `update invoices set refunded_cents = refunded_cents + $3,
                status = case when refunded_cents + $3 >= amount_cents then 'refunded' else 'partially_refunded' end
          where tenant_id = $1 and id = $2 and refunded_cents + $3 <= amount_cents
          returning refunded_cents, stripe_payment_intent`,
        [this.tenant, req.invoice_id, req.amount_cents],
      );
      const invoice = upd.rows[0];
      if (!invoice) throw new ForbiddenError("invoice no longer has enough refundable balance");
      if (!invoice.stripe_payment_intent) throw new ForbiddenError("invoice has no payment to refund");

      const refund = await this.payments.refund({
        paymentIntent: invoice.stripe_payment_intent,
        amountCents: req.amount_cents,
        idempotencyKey: confirmationId,
        metadata: { tenant_id: this.tenant, invoice_id: req.invoice_id, confirmation_id: confirmationId },
      });
      await tx.query("update refund_requests set status = 'confirmed', provider_refund_id = $2 where id = $1", [confirmationId, refund.id]);
      return {
        invoice_id: req.invoice_id,
        refunded_cents: req.amount_cents,
        invoice_refunded_total_cents: invoice.refunded_cents,
        refund_id: refund.id,
      };
    });
  }

  /** Admin export of the tenant's audit trail, for compliance reviews or a SIEM. */
  exportAudit(f: { from?: string; to?: string; limit: number }) {
    this.authorize(SCOPES.audit, "admin");
    return this.tx(async (tx) => {
      const r = await tx.query(
        `select id, at, user_id, request_id, tool, args, outcome from audit_log
          where tenant_id = $1 and ($2::timestamptz is null or at >= $2) and ($3::timestamptz is null or at < $3)
          order by id limit $4`,
        [this.tenant, f.from ?? null, f.to ?? null, f.limit],
      );
      return r.rows;
    });
  }

  /** Written in its own transaction, so denied and failed calls are recorded even though their work rolled back. */
  audit(tool: string, args: unknown, outcome: string) {
    return this.tx((tx) =>
      tx.query("insert into audit_log (tenant_id, user_id, request_id, tool, args, outcome) values ($1, $2, $3, $4, $5, $6)", [
        this.tenant,
        this.principal.userId,
        this.requestId ?? null,
        tool,
        JSON.stringify(args ?? {}),
        outcome,
      ]),
    );
  }
}
