import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Db } from "./db.js";
import { AuthError, type Principal } from "./auth.js";
import { ForbiddenError, NotFoundError, TenantScope, REFUND_LIMIT_CENTS } from "./repo.js";

/**
 * Builds the MCP server for one caller. `resolvePrincipal` comes from the transport
 * (env token for stdio, Authorization header for HTTP). No tool takes a tenant or user id.
 */
export function createServer(db: Db, resolvePrincipal: () => Promise<Principal>) {
  const server = new McpServer({ name: "tenantdesk", version: "0.2.0" });

  async function run(tool: string, args: unknown, fn: (scope: TenantScope) => Promise<unknown>) {
    let scope: TenantScope | undefined;
    try {
      scope = new TenantScope(db, await resolvePrincipal());
      const result = await fn(scope);
      await scope.audit(tool, args, "ok");
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const outcome =
        err instanceof ForbiddenError ? "denied" :
        err instanceof NotFoundError ? "not_found" :
        err instanceof AuthError ? "unauthenticated" : "error";
      if (scope) await scope.audit(tool, args, outcome);
      // Internal errors are not echoed to the model; known errors are safe to show.
      const message = outcome === "error" ? "internal error" : (err as Error).message;
      return { isError: true, content: [{ type: "text" as const, text: `${outcome}: ${message}` }] };
    }
  }

  const readOnly = { readOnlyHint: true, openWorldHint: false };

  server.registerTool(
    "list_customers",
    {
      title: "List customers",
      description: "List customers in your workspace, optionally filtered by name or email.",
      inputSchema: { query: z.string().max(100).optional(), limit: z.number().int().min(1).max(50).default(20) },
      annotations: readOnly,
    },
    (args) => run("list_customers", args, (s) => s.listCustomers(args.query, args.limit)),
  );

  server.registerTool(
    "get_customer",
    {
      title: "Get customer",
      description: "Get one customer with an invoice summary.",
      inputSchema: { customer_id: z.string().max(64) },
      annotations: readOnly,
    },
    (args) => run("get_customer", args, (s) => s.getCustomer(args.customer_id)),
  );

  server.registerTool(
    "search_invoices",
    {
      title: "Search invoices",
      description: "Search invoices by status, customer and date range (YYYY-MM-DD).",
      inputSchema: {
        status: z.enum(["paid", "open", "refunded", "partially_refunded"]).optional(),
        customer_id: z.string().max(64).optional(),
        from: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
        to: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
        limit: z.number().int().min(1).max(100).default(25),
      },
      annotations: readOnly,
    },
    (args) =>
      run("search_invoices", args, (s) =>
        s.searchInvoices({ status: args.status, customerId: args.customer_id, from: args.from, to: args.to, limit: args.limit }),
      ),
  );

  server.registerTool(
    "get_ticket_history",
    {
      title: "Ticket history",
      description: "Support tickets for one customer, newest first.",
      inputSchema: { customer_id: z.string().max(64) },
      annotations: readOnly,
    },
    (args) => run("get_ticket_history", args, (s) => s.ticketHistory(args.customer_id)),
  );

  server.registerTool(
    "create_ticket",
    {
      title: "Create support ticket",
      description: "Open a support ticket for a customer. Agents and admins only.",
      inputSchema: {
        customer_id: z.string().max(64),
        subject: z.string().min(3).max(120),
        body: z.string().min(1).max(2000),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    (args) => run("create_ticket", args, (s) => s.createTicket(args.customer_id, args.subject, args.body)),
  );

  server.registerTool(
    "request_refund",
    {
      title: "Request a refund (step 1 of 2)",
      description:
        `Prepare a refund on a paid invoice. Admins only, max $${REFUND_LIMIT_CENTS / 100}. ` +
        "Returns a confirmation_id; nothing is refunded until confirm_refund is called with it. " +
        "Always show the amount to the user and get their explicit OK before confirming.",
      inputSchema: {
        invoice_id: z.string().max(64),
        amount_cents: z.number().int().positive(),
        reason: z.string().min(5).max(300),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    (args) => run("request_refund", args, (s) => s.requestRefund(args.invoice_id, args.amount_cents, args.reason)),
  );

  server.registerTool(
    "confirm_refund",
    {
      title: "Confirm a refund (step 2 of 2)",
      description: "Execute a refund prepared by request_refund. Only after the user explicitly approved the amount.",
      inputSchema: { confirmation_id: z.string().max(80) },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    (args) => run("confirm_refund", args, (s) => s.confirmRefund(args.confirmation_id)),
  );

  return server;
}
