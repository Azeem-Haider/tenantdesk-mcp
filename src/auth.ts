import { SignJWT, jwtVerify } from "jose";
import type { Db } from "./db.js";

export type Role = "admin" | "agent" | "viewer";

/** Who is calling. Built only from a verified token plus the database, never from tool arguments. */
export interface Principal {
  userId: string;
  tenantId: string;
  role: Role;
}

export class AuthError extends Error {}

const secret = () =>
  new TextEncoder().encode(process.env.TENANTDESK_JWT_SECRET ?? "dev-only-secret-change-me-dev-only-secret");

/** Tokens carry only the user id. Tenant and role are looked up fresh on every request,
 *  so a revoked or downgraded user loses access immediately and a forged tenant claim is useless. */
export async function issueToken(userId: string, ttl = "8h"): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(userId)
    .setIssuer("tenantdesk")
    .setIssuedAt()
    .setExpirationTime(ttl)
    .sign(secret());
}

export async function principalFromToken(db: Db, token: string | undefined): Promise<Principal> {
  if (!token) throw new AuthError("missing token");
  let sub: string | undefined;
  try {
    const { payload } = await jwtVerify(token, secret(), { issuer: "tenantdesk", algorithms: ["HS256"] });
    sub = payload.sub;
  } catch {
    throw new AuthError("invalid or expired token");
  }
  if (!sub) throw new AuthError("token has no subject");
  const r = await db.query<{ id: string; tenant_id: string; role: Role }>(
    "select id, tenant_id, role from users where id = $1",
    [sub],
  );
  const user = r.rows[0];
  if (!user) throw new AuthError("unknown user");
  return { userId: user.id, tenantId: user.tenant_id, role: user.role };
}
