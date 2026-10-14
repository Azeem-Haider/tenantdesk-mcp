# Changelog

## 1.0.0 (2026-10-14)

Enterprise release.

- OAuth 2.1 / OIDC: tokens verified against the identity provider's JWKS with issuer, audience and expiry checks; protected resource metadata (RFC 9728) and `WWW-Authenticate` pointer on 401.
- OAuth scopes (`tenantdesk:read`, `:write`, `:refunds`, `:audit`) checked together with the user's role.
- Postgres row-level security as a second isolation layer; queries run as the restricted `tenantdesk_app` role.
- Real Postgres support (node-postgres pool) alongside PGlite; migrations with an advisory lock; `npm run migrate`.
- Refunds executed through Stripe with the confirmation id as idempotency key; balance reservation rolls back on provider failure.
- Idempotency keys for `create_ticket` and `request_refund`.
- Append-only audit log with request ids; NDJSON export endpoint for admins.
- Per-tenant rate limiting, body size limit, request timeouts, security headers.
- Structured logging (pino), Prometheus metrics, OpenTelemetry tracing.
- Health and readiness probes, graceful shutdown, startup config validation with production guards.
- Stripe webhook accepts multiple `v1` signatures during secret rotation.
- Dockerfile (non-root), Docker Compose (Postgres 16, optional Jaeger).
- Tests: 14 to 33, including real-Postgres concurrency tests.

## 0.2.0

Fixed build after the security assessment: all 10 findings closed.

## 0.1.0

Deliberately vulnerable build used for the sample security assessment.
