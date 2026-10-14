import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createApp } from "./app.js";
import { createLogger } from "./observability.js";
import { createServer } from "./server.js";

// Local mode for Claude Desktop / MCP Inspector. The token identifies the user;
// the server derives tenant and role from it on every call.
// stdout carries the MCP protocol, so logs go to stderr.
const app = await createApp({ log: createLogger(process.env.LOG_LEVEL ?? "warn", { stderr: true }).child({ transport: "stdio" }) });
const token = process.env.TENANTDESK_TOKEN;
const server = createServer(app, () => app.auth.principalFromToken(token));
await server.connect(new StdioServerTransport());
console.error("tenantdesk MCP server running on stdio");
