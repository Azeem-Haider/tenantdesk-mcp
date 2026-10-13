import { PGlite } from "@electric-sql/pglite";

/**
 * TenantDesk uses PGlite (real Postgres compiled to WASM) so the demo runs
 * with zero setup. Swap in node-postgres and a DATABASE_URL for production.
 */
export type Db = PGlite;

const SCHEMA = `
create table tenants (
  id text primary key,
  name text not null
);

create table users (
  id text primary key,
  tenant_id text not null references tenants(id),
  email text not null unique,
  role text not null check (role in ('admin', 'agent', 'viewer'))
);

create table customers (
  id text primary key,
  tenant_id text not null references tenants(id),
  name text not null,
  email text not null,
  plan text not null
);

create table invoices (
  id text primary key,
  tenant_id text not null references tenants(id),
  customer_id text not null references customers(id),
  amount_cents integer not null check (amount_cents >= 0),
  refunded_cents integer not null default 0,
  status text not null check (status in ('paid', 'open', 'refunded', 'partially_refunded')),
  issued_at date not null
);

create table tickets (
  id text primary key,
  tenant_id text not null references tenants(id),
  customer_id text not null references customers(id),
  subject text not null,
  body text not null,
  status text not null default 'open',
  created_by text references users(id),
  created_at timestamptz not null default now()
);

create table refund_requests (
  id text primary key,
  tenant_id text not null references tenants(id),
  invoice_id text not null references invoices(id),
  amount_cents integer not null,
  reason text not null,
  requested_by text not null references users(id),
  status text not null check (status in ('pending', 'confirmed', 'expired')),
  created_at timestamptz not null default now()
);

create table audit_log (
  id bigserial primary key,
  at timestamptz not null default now(),
  tenant_id text not null,
  user_id text not null,
  tool text not null,
  args jsonb not null,
  outcome text not null
);

create table processed_webhook_events (
  event_id text primary key,
  received_at timestamptz not null default now()
);
`;

const SEED = `
insert into tenants values ('t_acme', 'Acme Dental'), ('t_bright', 'Brightside Clinic');

insert into users values
  ('u_ana',   't_acme',   'ana@acme.test',      'admin'),
  ('u_ben',   't_acme',   'ben@acme.test',      'agent'),
  ('u_cara',  't_acme',   'cara@acme.test',     'viewer'),
  ('u_dev',   't_bright', 'dev@brightside.test','admin'),
  ('u_eli',   't_bright', 'eli@brightside.test','agent');

insert into customers values
  ('c_acme_1',  't_acme',   'Jordan Lee',     'jordan@example.com', 'pro'),
  ('c_acme_2',  't_acme',   'Priya Shah',     'priya@example.com',  'basic'),
  ('c_acme_3',  't_acme',   'Marco Rossi',    'marco@example.com',  'pro'),
  ('c_bright_1','t_bright', 'Sam Okafor',     'sam@example.com',    'pro'),
  ('c_bright_2','t_bright', 'Lena Fischer',   'lena@example.com',   'basic');

insert into invoices values
  ('inv_a1', 't_acme',   'c_acme_1',   12000, 0, 'paid', '2026-09-01'),
  ('inv_a2', 't_acme',   'c_acme_1',   12000, 0, 'open', '2026-10-01'),
  ('inv_a3', 't_acme',   'c_acme_2',    4500, 0, 'paid', '2026-09-12'),
  ('inv_a4', 't_acme',   'c_acme_3',   12000, 0, 'paid', '2026-09-20'),
  ('inv_b1', 't_bright', 'c_bright_1', 30000, 0, 'paid', '2026-09-05'),
  ('inv_b2', 't_bright', 'c_bright_2',  9900, 0, 'open', '2026-10-02');

insert into tickets (id, tenant_id, customer_id, subject, body, status, created_by) values
  ('tk_a1', 't_acme',   'c_acme_1',   'Charged twice in September', 'Customer says the card was charged twice.', 'open', 'u_ben'),
  ('tk_a2', 't_acme',   'c_acme_2',   'Upgrade to pro', 'Wants to upgrade next month.', 'closed', 'u_ben'),
  ('tk_b1', 't_bright', 'c_bright_1', 'Invoice address wrong', 'Needs the clinic address on invoices.', 'open', 'u_eli');
`;

export async function createDb(): Promise<Db> {
  const db = new PGlite();
  await db.exec(SCHEMA);
  await db.exec(SEED);
  return db;
}
