import { z } from "zod";

/**
 * All configuration comes from the environment and is validated once at startup.
 * In production the server refuses to start with dev auth, a short JWT secret or a missing webhook secret.
 */
const schema = z
  .object({
    NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
    PORT: z.coerce.number().int().min(0).max(65535).default(3333),
    PUBLIC_URL: z.string().url().default("http://localhost:3333"),
    LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info"),

    DATABASE_URL: z.string().optional(),
    DATABASE_POOL_MAX: z.coerce.number().int().min(1).max(100).default(10),
    SEED_DEMO: z.enum(["true", "false"]).default("true").transform((v) => v === "true"),

    AUTH_MODE: z.enum(["dev", "oidc"]).default("dev"),
    TENANTDESK_JWT_SECRET: z.string().default("dev-only-secret-change-me-dev-only-secret"),
    OIDC_ISSUER: z.string().url().optional(),
    OIDC_AUDIENCE: z.string().optional(),
    OIDC_JWKS_URL: z.string().url().optional(),

    STRIPE_WEBHOOK_SECRET: z.string().default("whsec_dev_only"),
    STRIPE_SECRET_KEY: z.string().optional(),

    RATE_LIMIT_PER_MINUTE: z.coerce.number().int().min(1).default(120),
    MAX_BODY_BYTES: z.coerce.number().int().min(1024).default(1_000_000),

    OTEL_EXPORTER_OTLP_ENDPOINT: z.string().url().optional(),
    OTEL_SERVICE_NAME: z.string().default("tenantdesk-mcp"),
  })
  .superRefine((c, ctx) => {
    if (c.AUTH_MODE === "oidc" && !c.OIDC_ISSUER) {
      ctx.addIssue({ code: "custom", path: ["OIDC_ISSUER"], message: "required when AUTH_MODE=oidc" });
    }
    if (c.NODE_ENV !== "production") return;
    if (c.AUTH_MODE === "dev") ctx.addIssue({ code: "custom", path: ["AUTH_MODE"], message: "dev auth is not allowed in production" });
    if (!c.DATABASE_URL) ctx.addIssue({ code: "custom", path: ["DATABASE_URL"], message: "required in production" });
    if (c.STRIPE_WEBHOOK_SECRET === "whsec_dev_only")
      ctx.addIssue({ code: "custom", path: ["STRIPE_WEBHOOK_SECRET"], message: "set a real webhook secret in production" });
    if (c.SEED_DEMO) ctx.addIssue({ code: "custom", path: ["SEED_DEMO"], message: "demo data must not be seeded in production" });
  });

export type Config = z.infer<typeof schema>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  // Treat `VAR=` (common in compose files and CI) the same as an unset variable.
  const cleaned = Object.fromEntries(Object.entries(env).filter(([, v]) => v !== undefined && v !== ""));
  const parsed = schema.safeParse(cleaned);
  if (!parsed.success) {
    const problems = parsed.error.issues.map((i) => `  ${i.path.join(".")}: ${i.message}`).join("\n");
    throw new Error(`Invalid configuration:\n${problems}`);
  }
  return parsed.data;
}
