> **⚠️ This is TenantDesk v0.1, deliberately vulnerable.** It is the version assessed in the sample security report. Do not deploy it. The fixed version is on `main` (v0.2.0).

# TenantDesk MCP

A tenant-safe [MCP](https://modelcontextprotocol.io) server for a multi-tenant SaaS.
Claude (or any MCP client) can look up customers, search invoices, open support tickets and prepare refunds, **but only inside the signed-in user's own workspace, with that user's role.**

Most MCP servers you find online pass a `tenant_id` or `user_id` in the tool arguments. That means the AI decides whose data it reads, and one prompt injection is enough to read another customer's data. TenantDesk does it the other way round.

## What makes it safe

| Risk | How TenantDesk handles it |
|---|---|
| AI reads another customer's data | Tools take **no tenant or user id**. The tenant and role come from the verified token and are looked up in the database on every call. |
| A tool forgets the tenant filter | All data access goes through one `TenantScope` class that adds the tenant filter to every query. Tools can't run SQL of their own. |
| Probing other tenants' record ids | "Not found" looks identical whether an id belongs to another tenant or doesn't exist. |
| AI issues refunds on its own | Refunds are **two steps**: `request_refund` parks the request, `confirm_refund` executes it. Admins only, capped at $500, only the same admin can confirm, and the confirmation expires after 10 minutes. |
| Over-refunding or double refunds | The balance check and update run in one transaction; a confirmation can only be used once. |
| Revoked users keep access | Tokens carry only the user id. Delete or downgrade the user and the next call reflects it. |
| No record of what the AI did | Every tool call, including denied ones, goes to `audit_log` with tenant, user, tool, arguments and outcome. |
| Error messages leaking internals | Known errors (denied, not found) are shown; anything unexpected becomes "internal error". |

## Tools

| Tool | Who can use it | Type |
|---|---|---|
| `list_customers` | everyone | read |
| `get_customer` | everyone | read |
| `search_invoices` | everyone | read |
| `get_ticket_history` | everyone | read |
| `create_ticket` | admin, agent | write |
| `request_refund` | admin | write (step 1 of 2) |
| `confirm_refund` | admin who requested it | destructive (step 2 of 2) |

Read tools are marked `readOnlyHint`, and `confirm_refund` is marked `destructiveHint`, so MCP clients can ask the user before running it.

## Run it

Requires Node.js 20+.

```bash
npm install
npm test            # 14 tests, including cross-tenant attacks
```

Demo data has two clinics:

| User | Tenant | Role |
|---|---|---|
| `u_ana` | Acme Dental | admin |
| `u_ben` | Acme Dental | agent |
| `u_cara` | Acme Dental | viewer |
| `u_dev` | Brightside Clinic | admin |
| `u_eli` | Brightside Clinic | agent |

### With Claude Desktop (stdio)

```bash
npm run token u_ana   # prints a token for Ana (Acme admin)
```

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "tenantdesk": {
      "command": "npx",
      "args": ["tsx", "/absolute/path/to/tenantdesk-mcp/src/stdio.ts"],
      "env": { "TENANTDESK_TOKEN": "<token from the command above>" }
    }
  }
}
```

Then ask Claude things like *"Which Acme customers have open invoices?"* or *"Refund $20 on invoice inv_a1, the customer was charged twice."*

### Over HTTP (remote MCP)

```bash
npm run http          # http://localhost:3333/mcp
```

Every request needs `Authorization: Bearer <token>`. Requests without one get `401`. The server is stateless, so each request is authenticated on its own.

### With MCP Inspector

```bash
TENANTDESK_TOKEN=$(npm run -s token u_ben) npx @modelcontextprotocol/inspector npx tsx src/stdio.ts
```

## Tests

`npm test` connects a real MCP client to the server and checks, among others:

- An Acme user only ever sees Acme customers.
- Asking for a Brightside customer by id returns "not found", identical to a made-up id.
- Passing `tenant_id` in the arguments does nothing.
- A Brightside admin can't read Acme ticket history or refund an Acme invoice.
- Viewers can't write, agents can't refund.
- Refunds need both steps, can't exceed the cap or the invoice balance, and can't be confirmed twice or by another admin.
- Every call, allowed or denied, is in the audit log.
- A deleted user's token stops working immediately.
- The HTTP endpoint rejects requests without a token.

## Project layout

```
src/db.ts       schema and demo data (PGlite: real Postgres in WASM, zero setup)
src/auth.ts     JWT verification -> Principal (user, tenant, role from the database)
src/repo.ts     TenantScope: the only data access path, tenant-filtered, role checks, refund flow
src/server.ts   MCP tool definitions, input validation, audit logging, error handling
src/stdio.ts    local transport (Claude Desktop, Inspector)
src/http.ts     Streamable HTTP transport with bearer auth
test/           end-to-end tests through a real MCP client
```

## Taking it to production

- Replace PGlite with node-postgres and a `DATABASE_URL`; add Postgres row-level security as a second safety net.
- Replace the HS256 dev secret with your identity provider (OAuth 2.1 / OIDC) and verify its tokens in `principalFromToken`.
- In `confirmRefund`, call `stripe.refunds.create` with the refund request id as the idempotency key.
- Ship `audit_log` to your log pipeline and alert on spikes of `denied` outcomes.

## License

MIT. Built by Azeem Haider.
