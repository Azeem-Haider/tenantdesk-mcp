/**
 * Schema migrations, applied in order and recorded in schema_migrations.
 * Kept as TypeScript strings so they ship inside the build with no file-path lookups.
 */
export const MIGRATIONS: { id: string; sql: string }[] = [
  {
    id: "001_schema",
    sql: `
create table tenants (
  id text primary key,
  name text not null
);

create table users (
  id text primary key,
  tenant_id text not null references tenants(id),
  external_sub text not null unique,
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
create index customers_tenant_idx on customers (tenant_id, name);

create table invoices (
  id text primary key,
  tenant_id text not null references tenants(id),
  customer_id text not null references customers(id),
  amount_cents integer not null check (amount_cents >= 0),
  refunded_cents integer not null default 0 check (refunded_cents >= 0 and refunded_cents <= amount_cents),
  status text not null check (status in ('paid', 'open', 'refunded', 'partially_refunded')),
  stripe_payment_intent text,
  issued_at date not null
);
create index invoices_tenant_idx on invoices (tenant_id, issued_at desc);

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
create index tickets_tenant_customer_idx on tickets (tenant_id, customer_id, created_at desc);

create table refund_requests (
  id text primary key,
  tenant_id text not null references tenants(id),
  invoice_id text not null references invoices(id),
  amount_cents integer not null check (amount_cents > 0),
  reason text not null,
  requested_by text not null references users(id),
  status text not null check (status in ('pending', 'confirmed', 'expired')),
  provider_refund_id text,
  created_at timestamptz not null default now()
);

create table audit_log (
  id bigserial primary key,
  at timestamptz not null default now(),
  tenant_id text not null,
  user_id text not null,
  request_id text,
  tool text not null,
  args jsonb not null,
  outcome text not null
);
create index audit_log_tenant_at_idx on audit_log (tenant_id, at);

create table idempotency_keys (
  tenant_id text not null,
  key text not null,
  tool text not null,
  request_hash text not null,
  response jsonb not null,
  created_at timestamptz not null default now(),
  primary key (tenant_id, key)
);

create table processed_webhook_events (
  event_id text primary key,
  received_at timestamptz not null default now()
);
`,
  },
  {
    // Second safety net under the TenantScope filters: even a query that forgets "where tenant_id = ..."
    // only sees the current tenant's rows, and with no tenant set it sees nothing.
    id: "002_row_level_security",
    sql: `
do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'tenantdesk_app') then
    create role tenantdesk_app nologin;
  end if;
end $$;
grant tenantdesk_app to current_user;
grant usage on schema public to tenantdesk_app;

grant select on tenants, customers, invoices, tickets, refund_requests, idempotency_keys to tenantdesk_app;
grant insert, update on tickets, refund_requests to tenantdesk_app;
grant update (refunded_cents, status) on invoices to tenantdesk_app;
grant insert on idempotency_keys to tenantdesk_app;
-- The audit log is append-only for the application: no update, no delete.
grant select, insert on audit_log to tenantdesk_app;
grant usage on sequence audit_log_id_seq to tenantdesk_app;

alter table tenants enable row level security;
alter table customers enable row level security;
alter table invoices enable row level security;
alter table tickets enable row level security;
alter table refund_requests enable row level security;
alter table audit_log enable row level security;
alter table idempotency_keys enable row level security;

create policy tenant_isolation on tenants using (id = current_setting('app.tenant_id', true));
create policy tenant_isolation on customers using (tenant_id = current_setting('app.tenant_id', true));
create policy tenant_isolation on invoices using (tenant_id = current_setting('app.tenant_id', true));
create policy tenant_isolation on tickets using (tenant_id = current_setting('app.tenant_id', true));
create policy tenant_isolation on refund_requests using (tenant_id = current_setting('app.tenant_id', true));
create policy tenant_isolation on audit_log using (tenant_id = current_setting('app.tenant_id', true));
create policy tenant_isolation on idempotency_keys using (tenant_id = current_setting('app.tenant_id', true));
`,
  },
];

export const DEMO_SEED = `
insert into tenants values ('t_acme', 'Acme Dental'), ('t_bright', 'Brightside Clinic');

insert into users (id, tenant_id, external_sub, email, role) values
  ('u_ana',   't_acme',   'u_ana',  'ana@acme.test',       'admin'),
  ('u_ben',   't_acme',   'u_ben',  'ben@acme.test',       'agent'),
  ('u_cara',  't_acme',   'u_cara', 'cara@acme.test',      'viewer'),
  ('u_dev',   't_bright', 'u_dev',  'dev@brightside.test', 'admin'),
  ('u_eli',   't_bright', 'u_eli',  'eli@brightside.test', 'agent');

insert into customers values
  ('c_acme_1',  't_acme',   'Jordan Lee',     'jordan@example.com', 'pro'),
  ('c_acme_2',  't_acme',   'Priya Shah',     'priya@example.com',  'basic'),
  ('c_acme_3',  't_acme',   'Marco Rossi',    'marco@example.com',  'pro'),
  ('c_bright_1','t_bright', 'Sam Okafor',     'sam@example.com',    'pro'),
  ('c_bright_2','t_bright', 'Lena Fischer',   'lena@example.com',   'basic');

insert into invoices (id, tenant_id, customer_id, amount_cents, refunded_cents, status, stripe_payment_intent, issued_at) values
  ('inv_a1', 't_acme',   'c_acme_1',   12000, 0, 'paid', 'pi_demo_a1', '2026-09-01'),
  ('inv_a2', 't_acme',   'c_acme_1',   12000, 0, 'open', null,         '2026-10-01'),
  ('inv_a3', 't_acme',   'c_acme_2',    4500, 0, 'paid', 'pi_demo_a3', '2026-09-12'),
  ('inv_a4', 't_acme',   'c_acme_3',   12000, 0, 'paid', 'pi_demo_a4', '2026-09-20'),
  ('inv_b1', 't_bright', 'c_bright_1', 30000, 0, 'paid', 'pi_demo_b1', '2026-09-05'),
  ('inv_b2', 't_bright', 'c_bright_2',  9900, 0, 'open', null,         '2026-10-02');

insert into tickets (id, tenant_id, customer_id, subject, body, status, created_by) values
  ('tk_a1', 't_acme',   'c_acme_1',   'Charged twice in September', 'Customer says the card was charged twice.', 'open', 'u_ben'),
  ('tk_a2', 't_acme',   'c_acme_2',   'Upgrade to pro', 'Wants to upgrade next month.', 'closed', 'u_ben'),
  ('tk_b1', 't_bright', 'c_bright_1', 'Invoice address wrong', 'Needs the clinic address on invoices.', 'open', 'u_eli');
`;
