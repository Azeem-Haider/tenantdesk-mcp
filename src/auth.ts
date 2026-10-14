import { SignJWT, createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from "jose";
import type { Db } from "./db.js";
import type { Config } from "./config.js";

export type Role = "admin" | "agent" | "viewer";

/**
 * OAuth scopes limit what an AI client may do on the user's behalf, on top of the user's role.
 * An admin can hand Claude a read-only token: role says "admin", scope says "read".
 */
export const SCOPES = {
  read: "tenantdesk:read",
  write: "tenantdesk:write",
  refunds: "tenantdesk:refunds",
  audit: "tenantdesk:audit",
} as const;
export type Scope = (typeof SCOPES)[keyof typeof SCOPES];
export const ALL_SCOPES: Scope[] = Object.values(SCOPES);

/** Who is calling. Built only from a verified token plus the database, never from tool arguments. */
export interface Principal {
  userId: string;
  tenantId: string;
  role: Role;
  scopes: ReadonlySet<string>;
}

export class AuthError extends Error {
  name = "AuthError";
}

/** Checks a bearer token's signature and claims; returns the subject and granted scopes. */
export type TokenVerifier = (token: string) => Promise<{ sub: string; scopes: string[] }>;

function scopesOf(payload: JWTPayload): string[] {
  if (typeof payload.scope === "string") return payload.scope.split(" ").filter(Boolean);
  if (Array.isArray(payload.scp)) return payload.scp.filter((s): s is string => typeof s === "string");
  return [];
}

const withSlash = (u: string) => (u.endsWith("/") ? u : `${u}/`);

/**
 * Production: tokens issued by your identity provider (Auth0, Okta, Entra ID, Keycloak, ...).
 * Signature checked against the provider's JWKS; issuer, audience (this server's URL) and expiry are required.
 */
export function oidcVerifier(opts: { issuer: string; audience: string; jwks?: JWTVerifyGetKey; jwksUrl?: string }): TokenVerifier {
  const jwks = opts.jwks ?? createRemoteJWKSet(new URL(opts.jwksUrl ?? new URL(".well-known/jwks.json", withSlash(opts.issuer))));
  return async (token) => {
    const { payload } = await jwtVerify(token, jwks, {
      issuer: opts.issuer,
      audience: opts.audience,
      algorithms: ["RS256", "PS256", "ES256", "EdDSA"],
      requiredClaims: ["sub", "exp"],
    });
    return { sub: payload.sub!, scopes: scopesOf(payload) };
  };
}

const DEV_ISSUER = "tenantdesk-dev";
const DEV_SECRET = "dev-only-secret-change-me-dev-only-secret";
const devKey = (secret: string) => new TextEncoder().encode(secret);

/** Local development only (rejected by config in production): HS256 tokens signed with a shared secret. */
export function devVerifier(secret: string): TokenVerifier {
  return async (token) => {
    const { payload } = await jwtVerify(token, devKey(secret), {
      issuer: DEV_ISSUER,
      algorithms: ["HS256"],
      requiredClaims: ["sub", "exp"],
    });
    return { sub: payload.sub!, scopes: scopesOf(payload) };
  };
}

/** Mints a dev token. Defaults to all scopes; pass `scopes` to hand an agent less. */
export async function issueToken(
  userId: string,
  opts: { ttl?: string; scopes?: string[]; secret?: string } = {},
): Promise<string> {
  return new SignJWT({ scope: (opts.scopes ?? ALL_SCOPES).join(" ") })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(userId)
    .setIssuer(DEV_ISSUER)
    .setIssuedAt()
    .setExpirationTime(opts.ttl ?? "8h")
    .sign(devKey(opts.secret ?? process.env.TENANTDESK_JWT_SECRET ?? DEV_SECRET));
}

/**
 * Turns a bearer token into a Principal. Tokens carry identity and scopes only;
 * tenant and role are read from the database on every request, so a revoked or downgraded
 * user loses access on their next call and a forged tenant or role claim does nothing.
 */
export class Authenticator {
  constructor(private db: Db, private verify: TokenVerifier) {}

  async principalFromToken(token: string | undefined): Promise<Principal> {
    if (!token) throw new AuthError("missing token");
    let claims: { sub: string; scopes: string[] };
    try {
      claims = await this.verify(token);
    } catch {
      throw new AuthError("invalid or expired token");
    }
    const r = await this.db.query<{ id: string; tenant_id: string; role: Role }>(
      "select id, tenant_id, role from users where external_sub = $1",
      [claims.sub],
    );
    const user = r.rows[0];
    if (!user) throw new AuthError("unknown user");
    return { userId: user.id, tenantId: user.tenant_id, role: user.role, scopes: new Set(claims.scopes) };
  }
}

export function devAuthenticator(db: Db, secret = process.env.TENANTDESK_JWT_SECRET ?? DEV_SECRET) {
  return new Authenticator(db, devVerifier(secret));
}

export function authenticatorFromConfig(db: Db, cfg: Config): Authenticator {
  if (cfg.AUTH_MODE === "oidc") {
    return new Authenticator(
      db,
      oidcVerifier({ issuer: cfg.OIDC_ISSUER!, audience: cfg.OIDC_AUDIENCE ?? cfg.PUBLIC_URL, jwksUrl: cfg.OIDC_JWKS_URL }),
    );
  }
  return devAuthenticator(db, cfg.TENANTDESK_JWT_SECRET);
}

export function bearer(header: string | undefined): string | undefined {
  return header?.startsWith("Bearer ") ? header.slice(7).trim() : undefined;
}
