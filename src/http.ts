import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createDb, type Db } from "./db.js";
import { AuthError, principalFromToken } from "./auth.js";
import { createServer } from "./server.js";
import { handleApi, handleStripeWebhook, readBody } from "./api.js";

/**
 * One HTTP server for the whole app:
 *   POST /mcp              MCP over Streamable HTTP (stateless, bearer auth per request)
 *   GET  /api/...          REST endpoints for the web app
 *   POST /webhooks/stripe  Stripe webhook (signature-verified)
 */
export async function startHttp(db: Db, port: number) {
  const http = createHttpServer(async (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (url.pathname === "/webhooks/stripe" && req.method === "POST") return handleStripeWebhook(db, req, res);
    if (url.pathname.startsWith("/api/")) return handleApi(db, req, res, url);
    if (url.pathname !== "/mcp") {
      res.writeHead(404).end();
      return;
    }
    const header = req.headers.authorization ?? "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : undefined;
    let principal;
    try {
      principal = await principalFromToken(db, token);
    } catch (err) {
      const msg = err instanceof AuthError ? err.message : "unauthorized";
      res.writeHead(401, { "content-type": "application/json", "www-authenticate": "Bearer" });
      res.end(JSON.stringify({ error: msg }));
      return;
    }
    const raw = await readBody(req);
    const body = raw ? JSON.parse(raw) : undefined;

    const server = createServer(db, async () => principal);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on("close", () => {
      transport.close();
      server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, body);
  });
  await new Promise<void>((resolve) => http.listen(port, resolve));
  return http;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT ?? 3333);
  const db = await createDb();
  await startHttp(db, port);
  console.error(`tenantdesk on http://localhost:${port}  (MCP at /mcp)`);
}
