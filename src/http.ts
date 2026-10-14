import { randomUUID } from "node:crypto";
import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createApp, type App } from "./app.js";
import { AuthError, ALL_SCOPES, bearer, type Principal } from "./auth.js";
import { createServer } from "./server.js";
import { BodyTooLargeError, handleApi, handleStripeWebhook, readBody, send } from "./api.js";
import { startTelemetry } from "./observability.js";

/**
 * One HTTP server for the whole app:
 *   POST /mcp                                 MCP over Streamable HTTP (stateless, OAuth bearer per request)
 *   GET  /.well-known/oauth-protected-resource OAuth protected resource metadata (RFC 9728), used by MCP clients to find the IdP
 *   GET  /api/...                             REST endpoints for the web app (CSV export, invoices, audit log export)
 *   POST /webhooks/stripe                     Stripe webhook (signature-verified, idempotent)
 *   GET  /healthz, /readyz, /metrics          liveness, readiness (database ping), Prometheus metrics
 */
export async function startHttp(app: App, port: number): Promise<Server> {
  const resourceMetadataUrl = `${app.cfg.PUBLIC_URL.replace(/\/$/, "")}/.well-known/oauth-protected-resource`;

  async function authenticate(req: IncomingMessage, res: ServerResponse): Promise<Principal | undefined> {
    try {
      return await app.auth.principalFromToken(bearer(req.headers.authorization));
    } catch (err) {
      const msg = err instanceof AuthError ? err.message : "unauthorized";
      // Tells MCP clients where to start the OAuth flow.
      send(res, 401, { error: msg }, "application/json", {
        "www-authenticate": `Bearer resource_metadata="${resourceMetadataUrl}", error="invalid_token"`,
      });
      return undefined;
    }
  }

  function rateLimited(principal: Principal, res: ServerResponse) {
    const r = app.limiter.take(`tenant:${principal.tenantId}`);
    if (r.ok) return false;
    app.metrics.inc("tenantdesk_rate_limited_total", "Requests rejected by the per-tenant rate limit");
    send(res, 429, { error: "rate limit exceeded" }, "application/json", { "retry-after": String(r.retryAfterSeconds) });
    return true;
  }

  async function route(req: IncomingMessage, res: ServerResponse, url: URL, requestId: string) {
    const path = url.pathname;

    if (req.method === "GET" && path === "/healthz") return send(res, 200, { status: "ok" });
    if (req.method === "GET" && path === "/readyz") {
      try {
        await app.db.query("select 1");
        return send(res, 200, { status: "ready" });
      } catch {
        return send(res, 503, { status: "database unavailable" });
      }
    }
    if (req.method === "GET" && path === "/metrics") return send(res, 200, app.metrics.render(), "text/plain; version=0.0.4");

    if (req.method === "GET" && path.startsWith("/.well-known/oauth-protected-resource")) {
      return send(res, 200, {
        resource: `${app.cfg.PUBLIC_URL.replace(/\/$/, "")}/mcp`,
        authorization_servers: app.cfg.OIDC_ISSUER ? [app.cfg.OIDC_ISSUER] : [],
        scopes_supported: ALL_SCOPES,
        bearer_methods_supported: ["header"],
        resource_name: "TenantDesk MCP",
      });
    }

    if (req.method === "POST" && path === "/webhooks/stripe") {
      return handleStripeWebhook(app, await readBody(req, app.cfg.MAX_BODY_BYTES), req, res);
    }

    if (path.startsWith("/api/")) {
      const principal = await authenticate(req, res);
      if (!principal || rateLimited(principal, res)) return;
      return handleApi(app, principal, requestId, req, res, url);
    }

    if (path === "/mcp") {
      // Stateless server: no sessions to resume (GET) or end (DELETE).
      if (req.method !== "POST") return send(res, 405, { error: "method not allowed" }, "application/json", { allow: "POST" });
      const principal = await authenticate(req, res);
      if (!principal || rateLimited(principal, res)) return;

      const raw = await readBody(req, app.cfg.MAX_BODY_BYTES);
      let body: unknown;
      try {
        body = raw ? JSON.parse(raw) : undefined;
      } catch {
        return send(res, 400, { jsonrpc: "2.0", error: { code: -32700, message: "Parse error" }, id: null });
      }
      const server = createServer(app, async () => principal, requestId);
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      res.on("close", () => {
        transport.close();
        server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
      return;
    }

    return send(res, 404, { error: "not found" });
  }

  const http = createHttpServer(async (req, res) => {
    const started = performance.now();
    const incoming = req.headers["x-request-id"];
    const requestId = typeof incoming === "string" && /^[\w-]{1,64}$/.test(incoming) ? incoming : randomUUID();
    res.setHeader("x-request-id", requestId);
    res.setHeader("x-content-type-options", "nosniff");
    res.setHeader("cache-control", "no-store");
    const url = new URL(req.url ?? "/", "http://localhost");
    try {
      await route(req, res, url, requestId);
    } catch (err) {
      if (err instanceof BodyTooLargeError) {
        if (!res.headersSent) send(res, 413, { error: "request body too large" });
      } else {
        app.log.error({ err, requestId }, "unhandled request error");
        if (!res.headersSent) send(res, 500, { error: "internal error" });
      }
    } finally {
      const route = url.pathname.startsWith("/api/") ? "/api" : url.pathname.startsWith("/.well-known") ? "/.well-known" : url.pathname;
      app.metrics.inc("tenantdesk_http_requests_total", "HTTP requests by route and status", { route, status: String(res.statusCode) });
      if (url.pathname !== "/healthz" && url.pathname !== "/metrics") {
        app.log.info(
          { requestId, method: req.method, path: url.pathname, status: res.statusCode, ms: Math.round(performance.now() - started) },
          "request",
        );
      }
    }
  });
  http.requestTimeout = 30_000;
  http.headersTimeout = 15_000;
  await new Promise<void>((resolve) => http.listen(port, resolve));
  return http;
}

/** Stops taking new connections, lets in-flight requests finish, then closes the database pool. */
function shutdownOnSignals(app: App, http: Server, sdk?: { shutdown(): Promise<void> }) {
  let closing = false;
  const stop = async (signal: string) => {
    if (closing) return;
    closing = true;
    app.log.info({ signal }, "shutting down");
    const force = setTimeout(() => process.exit(1), 10_000).unref();
    http.close(async () => {
      await app.db.close().catch(() => {});
      await sdk?.shutdown().catch(() => {});
      clearTimeout(force);
      process.exit(0);
    });
    http.closeIdleConnections();
  };
  process.on("SIGTERM", () => stop("SIGTERM"));
  process.on("SIGINT", () => stop("SIGINT"));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const app = await createApp();
  const sdk = await startTelemetry(app.cfg);
  const http = await startHttp(app, app.cfg.PORT);
  shutdownOnSignals(app, http, sdk);
  app.log.info(
    { port: app.cfg.PORT, auth: app.cfg.AUTH_MODE, database: app.cfg.DATABASE_URL ? "postgres" : "pglite (in-memory)" },
    "tenantdesk listening (MCP at /mcp)",
  );
}
