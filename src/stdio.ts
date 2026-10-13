import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createDb } from "./db.js";
import { principalFromToken } from "./auth.js";
import { createServer } from "./server.js";

// Local mode for Claude Desktop / MCP Inspector. The token identifies the user;
// the server derives tenant and role from it on every call.
const db = await createDb();
const token = process.env.TENANTDESK_TOKEN;
const server = createServer(db, () => principalFromToken(db, token));
await server.connect(new StdioServerTransport());
console.error("tenantdesk MCP server running on stdio");
