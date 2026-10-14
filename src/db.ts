import { PGlite } from "@electric-sql/pglite";
import pg from "pg";
import { DEMO_SEED, MIGRATIONS } from "./migrations.js";

export interface Queryable {
  query<T = any>(sql: string, params?: unknown[]): Promise<{ rows: T[] }>;
}

/**
 * The small database surface the app needs. Two implementations:
 * - Postgres via node-postgres (production, DATABASE_URL)
 * - PGlite, real Postgres compiled to WASM (zero-setup demo and tests)
 * Both run the same migrations, row-level security included.
 */
export interface Db extends Queryable {
  transaction<T>(fn: (tx: Queryable) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

/** Role used for all tenant-scoped work. Row-level security applies to it; the owner role is only used for auth lookups and webhooks. */
export const APP_ROLE = "tenantdesk_app";

class PgliteDb implements Db {
  constructor(private lite: PGlite) {}
  query<T>(sql: string, params?: unknown[]) {
    return this.lite.query<T>(sql, params);
  }
  transaction<T>(fn: (tx: Queryable) => Promise<T>) {
    return this.lite.transaction((tx) => fn({ query: <R>(s: string, p?: unknown[]) => tx.query<R>(s, p) }));
  }
  close() {
    return this.lite.close();
  }
}

class PostgresDb implements Db {
  constructor(private pool: pg.Pool) {}
  async query<T>(sql: string, params?: unknown[]) {
    const r = await this.pool.query(sql, params as any[]);
    return { rows: r.rows as T[] };
  }
  async transaction<T>(fn: (tx: Queryable) => Promise<T>) {
    const client = await this.pool.connect();
    try {
      await client.query("begin");
      const result = await fn({
        query: async <R>(s: string, p?: unknown[]) => ({ rows: (await client.query(s, p as any[])).rows as R[] }),
      });
      await client.query("commit");
      return result;
    } catch (err) {
      await client.query("rollback").catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }
  close() {
    return this.pool.end();
  }
}

/** Applies pending migrations. An advisory lock makes it safe when several instances start at once. */
export async function migrate(db: Db) {
  await db.transaction(async (tx) => {
    await tx.query("select pg_advisory_xact_lock(724001)");
    await tx.query("create table if not exists schema_migrations (id text primary key, applied_at timestamptz not null default now())");
    const done = new Set((await tx.query<{ id: string }>("select id from schema_migrations")).rows.map((r) => r.id));
    for (const m of MIGRATIONS) {
      if (done.has(m.id)) continue;
      for (const statement of splitSql(m.sql)) await tx.query(statement);
      await tx.query("insert into schema_migrations (id) values ($1)", [m.id]);
    }
  });
}

export async function seedDemo(db: Db) {
  const existing = await db.query<{ n: number }>("select count(*)::int as n from tenants");
  if (existing.rows[0].n > 0) return;
  await db.transaction(async (tx) => {
    for (const statement of splitSql(DEMO_SEED)) await tx.query(statement);
  });
}

/** Splits a migration into statements, keeping $$ ... $$ blocks intact. */
function splitSql(sql: string): string[] {
  const out: string[] = [];
  let buf = "";
  let inDollar = false;
  for (const line of sql.split("\n")) {
    if (line.trim().startsWith("--")) continue;
    buf += line + "\n";
    if ((line.match(/\$\$/g) ?? []).length % 2 === 1) inDollar = !inDollar;
    if (!inDollar && line.trim().endsWith(";")) {
      out.push(buf.trim());
      buf = "";
    }
  }
  if (buf.trim()) out.push(buf.trim());
  return out;
}

/** In-memory Postgres (PGlite) with schema and, by default, demo data. Used by tests and the zero-setup demo. */
export async function createDb(opts: { seed?: boolean } = {}): Promise<Db> {
  const db = new PgliteDb(new PGlite());
  await migrate(db);
  if (opts.seed ?? true) await seedDemo(db);
  return db;
}

export async function createPostgresDb(url: string, poolMax = 10): Promise<Db> {
  const db = new PostgresDb(new pg.Pool({ connectionString: url, max: poolMax }));
  await migrate(db);
  return db;
}

export async function openDb(cfg: { DATABASE_URL?: string; DATABASE_POOL_MAX: number; SEED_DEMO: boolean }): Promise<Db> {
  const db = cfg.DATABASE_URL ? await createPostgresDb(cfg.DATABASE_URL, cfg.DATABASE_POOL_MAX) : await createDb({ seed: false });
  if (cfg.SEED_DEMO) await seedDemo(db);
  return db;
}
