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
 created_at timestamptz not null default now()
);

create table if not exists public.entities (
 id uuid primary key default gen_random_uuid(),
 investigation_id uuid not null references public.investigations(id) on delete cascade,
 entity_type text not null,
 name text not null,
 normalized_name text,
 metadata jsonb not null default '{}'::jsonb,
 created_at timestamptz not null default now()
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

create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path=public as $$
begin insert into public.profiles(id) values(new.id) on conflict do nothing; return new; end; $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute procedure public.handle_new_user();

alter table public.profiles enable row level security;
alter table public.investigations enable row level security;
alter table public.entities enable row level security;
alter table public.documents enable row level security;
alter table public.network_links enable row level security;
alter table public.audit_log enable row level security;

create policy "authorized users read own profile" on public.profiles for select to authenticated using (id=auth.uid());
create policy "authorized investigators read investigations" on public.investigations for select to authenticated using (created_by=auth.uid() or exists(select 1 from public.profiles p where p.id=auth.uid() and p.is_authorized));
create policy "authorized users create investigations" on public.investigations for insert to authenticated with check (created_by=auth.uid() and exists(select 1 from public.profiles p where p.id=auth.uid() and p.is_authorized));
create policy "authorized users read entities" on public.entities for select to authenticated using (exists(select 1 from public.investigations i where i.id=investigation_id and (i.created_by=auth.uid() or exists(select 1 from public.profiles p where p.id=auth.uid() and p.is_authorized))));
create policy "authorized users read documents" on public.documents for select to authenticated using (exists(select 1 from public.investigations i where i.id=investigation_id and (i.created_by=auth.uid() or exists(select 1 from public.profiles p where p.id=auth.uid() and p.is_authorized))));
create policy "authorized users read links" on public.network_links for select to authenticated using (exists(select 1 from public.investigations i where i.id=investigation_id and (i.created_by=auth.uid() or exists(select 1 from public.profiles p where p.id=auth.uid() and p.is_authorized))));
create policy "authorized users read audit" on public.audit_log for select to authenticated using (exists(select 1 from public.investigations i where i.id=investigation_id and (i.created_by=auth.uid() or exists(select 1 from public.profiles p where p.id=auth.uid() and p.is_authorized))));

-- IMPORTANT: do not grant direct UPDATE/DELETE on evidence/link/audit tables to normal users.
-- The FastAPI service should expose controlled append-only operations and use a server-only key.
