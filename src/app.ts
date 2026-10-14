import type { Logger } from "pino";
import { loadConfig, type Config } from "./config.js";
import { openDb, type Db } from "./db.js";
import { authenticatorFromConfig, type Authenticator } from "./auth.js";
import { paymentsFromConfig, type PaymentProvider } from "./payments.js";
import { createLogger, Metrics } from "./observability.js";
import { MemoryRateLimiter, type RateLimiter } from "./ratelimit.js";

/** Everything a request handler needs. Built once at startup; tests swap parts out. */
export interface App {
  cfg: Config;
  db: Db;
  auth: Authenticator;
  payments: PaymentProvider;
  log: Logger;
  metrics: Metrics;
  limiter: RateLimiter;
}

export async function createApp(overrides: Partial<App> & { env?: NodeJS.ProcessEnv } = {}): Promise<App> {
  const cfg = overrides.cfg ?? loadConfig(overrides.env);
  const db = overrides.db ?? (await openDb(cfg));
  return {
    cfg,
    db,
    auth: overrides.auth ?? authenticatorFromConfig(db, cfg),
    payments: overrides.payments ?? paymentsFromConfig(cfg),
    log: overrides.log ?? createLogger(cfg.LOG_LEVEL),
    metrics: overrides.metrics ?? new Metrics(),
    limiter: overrides.limiter ?? new MemoryRateLimiter(cfg.RATE_LIMIT_PER_MINUTE),
  };
}
