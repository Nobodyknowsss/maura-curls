-- Keep public."user" in sync with verified Supabase Auth users.
--
-- The app table is public."user" (singular); Supabase's auth table is auth.users
-- (plural). auth.users gets a row at signup (email_confirmed_at = NULL), which is
-- then UPDATEd when the user verifies. Sync is handled entirely by triggers so
-- that `prisma db pull` of the public schema stays clean (no cross-schema FK,
-- so no need to introspect/manage the auth schema in schema.prisma).
--
-- This script is idempotent and safe to re-run.
--
-- Apply with:
--   npx prisma db execute --file prisma/sql/sync-auth-users.sql
-- (or paste into the Supabase SQL Editor).

-- a) Remove a stale leftover trigger from an earlier setup. handle_new_user()
--    inserted into a non-existent public.users (plural) table on every signup,
--    which raised "relation public.users does not exist" -> the GoTrue
--    "Database error saving new user". Superseded by the verified-only trigger.
drop trigger if exists on_auth_user_created on auth.users;
drop function if exists public.handle_new_user();

-- b) uid is always supplied from auth.users.id now, so drop the generated default.
alter table public."user" alter column uid drop default;

-- c) Remove the cross-schema FK. A FK from public."user" to auth.users makes
--    `prisma db pull` fail with P4002 unless the auth schema is added to the
--    datasource (which drags every Supabase auth table into schema.prisma).
--    Cascade-on-delete is reproduced by the AFTER DELETE trigger in (f) instead.
alter table public."user" drop constraint if exists user_uid_fkey;

-- d) Mirror verified users into public."user".
--    SECURITY DEFINER bypasses RLS; empty search_path forces schema-qualified names.
create or replace function public.handle_verified_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.email_confirmed_at is not null
     and (tg_op = 'INSERT' or old.email_confirmed_at is null) then
    insert into public."user" (uid, email, created_at)
    values (new.id, new.email, new.created_at)
    on conflict (uid) do nothing;
  end if;
  return new;
end;
$$;

-- e) Fire at signup (insert) and at verification (update).
drop trigger if exists on_auth_user_verified on auth.users;
create trigger on_auth_user_verified
  after insert or update on auth.users
  for each row execute function public.handle_verified_user();

-- f) Clean up the mirror when an auth user is deleted (replaces FK ON DELETE CASCADE).
create or replace function public.handle_deleted_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  delete from public."user" where uid = old.id;
  return old;
end;
$$;

drop trigger if exists on_auth_user_deleted on auth.users;
create trigger on_auth_user_deleted
  after delete on auth.users
  for each row execute function public.handle_deleted_user();
