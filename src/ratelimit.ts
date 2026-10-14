/**
 * Per-tenant rate limit so one customer's runaway agent can't starve everyone else.
 * The in-memory limiter is right for a single instance; for several replicas, implement
 * RateLimiter on Redis (same interface) so the budget is shared.
 */
export interface RateLimiter {
  take(key: string): { ok: true } | { ok: false; retryAfterSeconds: number };
}

/** Token bucket: `perMinute` requests per minute, with bursts up to the same size. */
export class MemoryRateLimiter implements RateLimiter {
  private buckets = new Map<string, { tokens: number; at: number }>();
  constructor(private perMinute: number, private now = () => Date.now()) {}

  take(key: string) {
    const t = this.now();
    const ratePerMs = this.perMinute / 60_000;
    const b = this.buckets.get(key) ?? { tokens: this.perMinute, at: t };
    b.tokens = Math.min(this.perMinute, b.tokens + (t - b.at) * ratePerMs);
    b.at = t;
    this.buckets.set(key, b);
    if (b.tokens >= 1) {
      b.tokens -= 1;
      return { ok: true as const };
    }
    return { ok: false as const, retryAfterSeconds: Math.ceil((1 - b.tokens) / ratePerMs / 1000) };
  }
}
