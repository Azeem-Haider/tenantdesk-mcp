import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createDb, type Db } from "./db.js";
import { AuthError, principalFromToken } from "./auth.js";
import { createServer } from "./server.js";

/**
 * Remote mode: Streamable HTTP, stateless. Every request must carry
 * `Authorization: Bearer <token>`; the principal is resolved per request.
 */
export async function startHttp(db: Db, port: number) {
  const http = createHttpServer(async (req: IncomingMessage, res: ServerResponse) => {
    if (req.url !== "/mcp") {
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
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : undefined;

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
  console.error(`tenantdesk MCP server on http://localhost:${port}/mcp`);
}
