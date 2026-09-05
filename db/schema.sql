-- NyayaNet database schema
-- Idempotent where practical so it can be applied to an existing prototype.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  role text not null default 'investigator' check (role in ('admin','supervisor','investigator','analyst')),
  is_authorized boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists public.investigations (
  id uuid primary key default gen_random_uuid(),
  investigation_code text unique not null default ('INV-' || to_char(now(),'YYYYMMDD') || '-' || upper(substr(replace(gen_random_uuid()::text,'-',''),1,8))),
  title text not null,
  description text,
  status text not null default 'active',
  created_by uuid not null references public.profiles(id),
  created_at timestamptz not null default now(),
  closed_at timestamptz
);

create table if not exists public.documents (
  id uuid primary key default gen_random_uuid(),
  investigation_id uuid not null references public.investigations(id) on delete cascade,
  source_type text not null,
  title text not null,
  content text not null,
  language text not null default 'en',
  content_hash text not null,
  extracted_entities jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.persons (
  id uuid primary key default gen_random_uuid(),
  person_id text unique not null,
  investigation_id uuid not null references public.investigations(id) on delete cascade,
  name text not null,
  phone_num text,
  age integer,
  location text,
  vehicle_num text,
  org text,
  bank_account text,
  crime_recorded text,
  fir_text text,
  fir_language text,
  source_document_id uuid references public.documents(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.person_relationships (
  id uuid primary key default gen_random_uuid(),
  relationship_id text unique not null,
  investigation_id uuid not null references public.investigations(id) on delete cascade,
  person_a_id text not null,
  person_a_name text,
  person_b_id text not null,
  person_b_name text,
  phone_call_count integer not null default 0,
  phone_call_dates text,
  phone_call_durations_sec text,
  total_call_duration_sec numeric not null default 0,
  transaction_count integer not null default 0,
  transaction_dates text,
  transaction_amounts text,
  total_transaction_amount numeric not null default 0,
  meeting_count integer not null default 0,
  meeting_dates text,
  meeting_locations text,
  relationship_label integer,
  ground_truth_confidence numeric(6,5),
  model_confidence numeric(6,5),
  relationship_type text,
  relationship_description text,
  reason text,
  suspicious boolean not null default false,
  anomaly_score numeric,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Preserve the starter's generic entity/link/audit tables for compatibility.
create table if not exists public.entities (
  id uuid primary key default gen_random_uuid(),
  investigation_id uuid not null references public.investigations(id) on delete cascade,
  entity_type text not null,
  name text not null,
  normalized_name text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.network_links (
  id uuid primary key default gen_random_uuid(),
  investigation_id uuid not null references public.investigations(id) on delete cascade,
  source_entity_id uuid not null references public.entities(id),
  target_entity_id uuid not null references public.entities(id),
  relation_type text not null,
  reason text not null,
  confidence numeric(5,4) not null check(confidence between 0 and 1),
  evidence_ids uuid[] not null default '{}',
  previous_hash text not null default '',
  link_hash text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.audit_log (
  id bigserial primary key,
  actor_id uuid references public.profiles(id),
  investigation_id uuid references public.investigations(id),
  action text not null,
  object_type text not null,
  object_id text,
  payload jsonb not null default '{}'::jsonb,
  previous_hash text not null default '',
  event_hash text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.analysis_runs (
  id uuid primary key default gen_random_uuid(),
  investigation_id uuid not null references public.investigations(id) on delete cascade,
  actor_id uuid references public.profiles(id),
  sources_processed integer not null default 0,
  entities_extracted integer not null default 0,
  candidate_links integer not null default 0,
  suspicious_links integer not null default 0,
  summary jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

-- Add columns to installations from an older prototype without destroying data.
alter table public.investigations add column if not exists closed_at timestamptz;
alter table public.persons add column if not exists age integer;
alter table public.persons add column if not exists bank_account text;
alter table public.persons add column if not exists fir_text text;
alter table public.persons add column if not exists fir_language text;
alter table public.persons add column if not exists source_document_id uuid references public.documents(id);
alter table public.persons add column if not exists updated_at timestamptz not null default now();

alter table public.person_relationships add column if not exists relationship_type text;
alter table public.person_relationships add column if not exists relationship_description text;
alter table public.person_relationships add column if not exists model_confidence numeric(6,5);
alter table public.person_relationships add column if not exists reason text;
alter table public.person_relationships add column if not exists suspicious boolean not null default false;
alter table public.person_relationships add column if not exists anomaly_score numeric;
alter table public.person_relationships add column if not exists updated_at timestamptz not null default now();

create index if not exists idx_persons_investigation on public.persons(investigation_id);
create index if not exists idx_persons_name on public.persons(lower(name));
create index if not exists idx_persons_phone on public.persons(phone_num);
create index if not exists idx_person_relationships_investigation on public.person_relationships(investigation_id);
create index if not exists idx_person_relationships_a on public.person_relationships(person_a_id);
create index if not exists idx_person_relationships_b on public.person_relationships(person_b_id);
create index if not exists idx_documents_investigation on public.documents(investigation_id);
create index if not exists idx_analysis_runs_investigation on public.analysis_runs(investigation_id);

create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path=public as $$
begin
  insert into public.profiles(id, full_name)
  values(new.id, coalesce(new.raw_user_meta_data->>'full_name', ''))
  on conflict do nothing;
  return new;
end; $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute procedure public.handle_new_user();

-- RLS
alter table public.profiles enable row level security;
alter table public.investigations enable row level security;
alter table public.documents enable row level security;
alter table public.persons enable row level security;
alter table public.person_relationships enable row level security;
alter table public.entities enable row level security;
alter table public.network_links enable row level security;
alter table public.audit_log enable row level security;
alter table public.analysis_runs enable row level security;

drop policy if exists "authorized users read own profile" on public.profiles;
create policy "authorized users read own profile" on public.profiles
for select to authenticated using (id = auth.uid());

drop policy if exists "authorized investigators read investigations" on public.investigations;
create policy "authorized investigators read investigations" on public.investigations
for select to authenticated using (
  created_by = auth.uid() or exists(
    select 1 from public.profiles p
    where p.id = auth.uid() and p.is_authorized
  )
);

drop policy if exists "authorized users create investigations" on public.investigations;
create policy "authorized users create investigations" on public.investigations
for insert to authenticated with check (
  created_by = auth.uid() and exists(
    select 1 from public.profiles p
    where p.id = auth.uid() and p.is_authorized
  )
);

-- Authorized investigators can read evidence and analytical outputs.
-- PostgreSQL has no dynamic CREATE POLICY in plain SQL, so these are explicit.
drop policy if exists "authorized users read documents" on public.documents;
create policy "authorized users read documents" on public.documents for select to authenticated using (
  exists(select 1 from public.investigations i where i.id = investigation_id and (i.created_by = auth.uid() or exists(select 1 from public.profiles p where p.id = auth.uid() and p.is_authorized)))
);

drop policy if exists "authorized users read persons" on public.persons;
create policy "authorized users read persons" on public.persons for select to authenticated using (
  exists(select 1 from public.investigations i where i.id = investigation_id and (i.created_by = auth.uid() or exists(select 1 from public.profiles p where p.id = auth.uid() and p.is_authorized)))
);

drop policy if exists "authorized users read person relationships" on public.person_relationships;
create policy "authorized users read person relationships" on public.person_relationships for select to authenticated using (
  exists(select 1 from public.investigations i where i.id = investigation_id and (i.created_by = auth.uid() or exists(select 1 from public.profiles p where p.id = auth.uid() and p.is_authorized)))
);

drop policy if exists "authorized users read entities" on public.entities;
create policy "authorized users read entities" on public.entities for select to authenticated using (
  exists(select 1 from public.investigations i where i.id = investigation_id and (i.created_by = auth.uid() or exists(select 1 from public.profiles p where p.id = auth.uid() and p.is_authorized)))
);

drop policy if exists "authorized users read links" on public.network_links;
create policy "authorized users read links" on public.network_links for select to authenticated using (
  exists(select 1 from public.investigations i where i.id = investigation_id and (i.created_by = auth.uid() or exists(select 1 from public.profiles p where p.id = auth.uid() and p.is_authorized)))
);

drop policy if exists "authorized users read audit" on public.audit_log;
create policy "authorized users read audit" on public.audit_log for select to authenticated using (
  exists(select 1 from public.investigations i where i.id = investigation_id and (i.created_by = auth.uid() or exists(select 1 from public.profiles p where p.id = auth.uid() and p.is_authorized)))
);

drop policy if exists "authorized users read analysis runs" on public.analysis_runs;
create policy "authorized users read analysis runs" on public.analysis_runs for select to authenticated using (
  exists(select 1 from public.investigations i where i.id = investigation_id and (i.created_by = auth.uid() or exists(select 1 from public.profiles p where p.id = auth.uid() and p.is_authorized)))
);

-- Controlled writes remain server-side via the FastAPI service role.
