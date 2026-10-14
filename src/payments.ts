import Stripe from "stripe";

export interface RefundRequest {
  paymentIntent: string;
  amountCents: number;
  /** Same key on every retry, so the provider never refunds twice. */
  idempotencyKey: string;
  metadata: Record<string, string>;
}

export interface PaymentProvider {
  refund(r: RefundRequest): Promise<{ id: string }>;
}

/** Real refunds through Stripe. Used when STRIPE_SECRET_KEY is set. */
export class StripePayments implements PaymentProvider {
  private stripe: Stripe;
  constructor(secretKey: string) {
    this.stripe = new Stripe(secretKey, { maxNetworkRetries: 2, timeout: 15_000 });
  }
  async refund(r: RefundRequest) {
    const refund = await this.stripe.refunds.create(
      { payment_intent: r.paymentIntent, amount: r.amountCents, metadata: r.metadata },
      { idempotencyKey: r.idempotencyKey },
    );
    return { id: refund.id };
  }
}

/** Demo and test provider: records refunds in memory and honours idempotency keys like Stripe does. */
export class FakePayments implements PaymentProvider {
  readonly refunds = new Map<string, { id: string } & RefundRequest>();
  async refund(r: RefundRequest) {
    const existing = this.refunds.get(r.idempotencyKey);
    if (existing) return { id: existing.id };
    const id = `re_demo_${this.refunds.size + 1}`;
    this.refunds.set(r.idempotencyKey, { id, ...r });
    return { id };
  }
}

export function paymentsFromConfig(cfg: { STRIPE_SECRET_KEY?: string }): PaymentProvider {
  return cfg.STRIPE_SECRET_KEY ? new StripePayments(cfg.STRIPE_SECRET_KEY) : new FakePayments();
}
