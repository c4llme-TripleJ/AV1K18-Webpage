-- AV1K18 class site: accounts, roles, captain requests, shared files.
-- Run once in Supabase: SQL Editor -> New query -> paste -> Run.
-- Before running: Authentication -> Providers -> Email -> turn OFF "Confirm email".

-- ───────── Profiles (one per account) ─────────
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique check (username ~ '^[a-z0-9_]{3,20}$'),
  role text not null default 'member' check (role in ('member','captain','admin')),
  planet text check (planet in ('moon','giant','ringed')),
  school_email text,
  created_at timestamptz not null default now(),
  check ((role = 'captain') = (planet is not null) or role = 'admin')
);
-- Only one captain per planet
create unique index one_captain_per_planet on public.profiles (planet) where role = 'captain';

create function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from profiles where id = auth.uid() and role = 'admin');
$$;

-- New account -> profile (username comes from sign-up metadata)
create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into profiles (id, username) values (new.id, lower(new.raw_user_meta_data->>'username'));
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- Members may edit only their own school_email; never role or planet
create function public.guard_profile_update() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is not null and not public.is_admin() and (new.role <> old.role or new.planet is distinct from old.planet
      or new.username <> old.username or new.id <> old.id) then
    raise exception 'Not allowed to change role, planet or username';
  end if;
  return new;
end $$;
create trigger guard_profile_update before update on public.profiles
  for each row execute function public.guard_profile_update();

alter table public.profiles enable row level security;
create policy "signed-in can read profiles" on public.profiles for select to authenticated using (true);
create policy "edit own profile" on public.profiles for update to authenticated
  using (id = auth.uid()) with check (id = auth.uid());
create policy "admins edit profiles" on public.profiles for update to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- ───────── Captain verification requests ─────────
create table public.captain_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  planet text not null check (planet in ('moon','giant','ringed')),
  note text check (char_length(note) <= 300),
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at timestamptz not null default now()
);
create unique index one_pending_request_per_user on public.captain_requests (user_id) where status = 'pending';

alter table public.captain_requests enable row level security;
create policy "see own or all if admin" on public.captain_requests for select to authenticated
  using (user_id = auth.uid() or public.is_admin());
create policy "request for yourself" on public.captain_requests for insert to authenticated
  with check (user_id = auth.uid() and status = 'pending');

-- Admin actions (checked on the server, not in the browser)
create function public.approve_captain(req uuid) returns void
language plpgsql security definer set search_path = public as $$
declare r captain_requests;
begin
  if not is_admin() then raise exception 'Admins only'; end if;
  select * into r from captain_requests where id = req and status = 'pending';
  if not found then raise exception 'Request not found or already handled'; end if;
  if exists (select 1 from profiles where role = 'captain' and planet = r.planet) then
    raise exception 'That planet already has a captain; remove them first';
  end if;
  update profiles set role = 'captain', planet = r.planet where id = r.user_id and role = 'member';
  update captain_requests set status = 'approved' where id = req;
end $$;

create function public.reject_captain(req uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'Admins only'; end if;
  update captain_requests set status = 'rejected' where id = req and status = 'pending';
end $$;

create function public.remove_captain(target uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'Admins only'; end if;
  update profiles set role = 'member', planet = null where id = target and role = 'captain';
end $$;

-- ───────── Files ─────────
create table public.files (
  id uuid primary key default gen_random_uuid(),
  planet text not null check (planet in ('moon','giant','ringed')),
  name text not null check (char_length(name) <= 200),
  mime text not null,
  size bigint not null check (size <= 10485760),
  path text not null unique,
  uploader uuid not null default auth.uid() references public.profiles(id),
  created_at timestamptz not null default now()
);

create function public.can_upload(p text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from profiles where id = auth.uid()
    and (role = 'admin' or (role = 'captain' and planet = p)));
$$;

alter table public.files enable row level security;
create policy "anyone can list files" on public.files for select to anon, authenticated using (true);
create policy "captain of the planet or admin can add" on public.files for insert to authenticated
  with check (uploader = auth.uid() and public.can_upload(planet));
create policy "own files or admin can delete" on public.files for delete to authenticated
  using (uploader = auth.uid() or public.is_admin());

-- ───────── Storage: public-read bucket, 10 MB cap, allowed types ─────────
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types) values (
  'planet-files', 'planet-files', true, 10485760,
  array['image/jpeg','image/png','image/webp','image/gif','application/pdf','text/plain',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']);

-- Files live under "<planet>/<unique-name>"; the first folder must be a planet the user may upload to
create policy "anyone can read planet files" on storage.objects for select to anon, authenticated
  using (bucket_id = 'planet-files');
create policy "upload to own planet" on storage.objects for insert to authenticated
  with check (bucket_id = 'planet-files' and public.can_upload((storage.foldername(name))[1]));
create policy "delete own or admin" on storage.objects for delete to authenticated
  using (bucket_id = 'planet-files' and (owner = auth.uid() or public.is_admin()));

-- ───────── Make the host and web devs admins ─────────
-- After each of them has created an account on the site, run (with their usernames):
-- update public.profiles set role = 'admin' where username in ('host_username','dev1','dev2','dev3');
