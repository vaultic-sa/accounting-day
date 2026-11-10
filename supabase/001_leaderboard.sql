-- =====================================================================
--  تحدّي اليوم العالمي للمحاسبة — shared leaderboard (Supabase / Postgres)
--
--  Security model
--  * Tables live in `public` with RLS ENABLED and NO policies, and every
--    privilege revoked from anon/authenticated: the browser can never read,
--    insert, update or delete a row directly.
--  * The browser talks only to four SECURITY DEFINER functions (RPC):
--      register_player, start_game, finish_game, get_leaderboard
--  * The score is computed HERE, from the submitted answers and the answer
--    key stored in the database. Any score sent by the browser is ignored.
--  * Each player gets a random secret token; only its SHA-256 hash is stored.
--  * finish_game is idempotent: a session is scored exactly once; repeating
--    the request (refresh, double click, retry) returns the stored result.
--  * Durations are measured with the server clock (start_game → finish_game)
--    and used as the tie-breaker.
--  Safe to re-run.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;
create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

-- ---------------------------------------------------------------- tables
create table if not exists public.players (
  id          uuid primary key default gen_random_uuid(),
  player_no   bigint generated always as identity unique,
  name        text not null check (char_length(name) between 2 and 30),
  token_hash  text not null,
  created_at  timestamptz not null default now()
);

create table if not exists public.game_sessions (
  id           uuid primary key default gen_random_uuid(),
  player_id    uuid not null references public.players(id) on delete cascade,
  started_at   timestamptz not null default now(),
  finished_at  timestamptz,
  status       text not null default 'open' check (status in ('open','finished')),
  score        integer check (score >= 0),
  correct      integer check (correct >= 0),
  total        integer check (total > 0),
  duration_ms  integer check (duration_ms > 0),
  answers      jsonb,
  constraint finished_consistent check (
    (status = 'finished') = (finished_at is not null and score is not null and duration_ms is not null))
);
create index if not exists game_sessions_player_idx on public.game_sessions (player_id, started_at desc);
create index if not exists game_sessions_rank_idx   on public.game_sessions (score desc, duration_ms, finished_at)
  where status = 'finished';

create table if not exists public.answer_key (
  r            smallint not null,
  qi           smallint not null,
  kind         text not null check (kind in ('opt','word','amount')),
  correct_opt  smallint,
  word         text,
  amount       numeric,
  primary key (r, qi)
);

-- per-IP request log for basic flood protection (stores only a hash of the IP)
create table if not exists private.rate_events (
  ip_hash  text not null,
  kind     text not null,
  at       timestamptz not null default now()
);
create index if not exists rate_events_idx on private.rate_events (ip_hash, kind, at);

-- ------------------------------------------------------------- lock down
alter table public.players       enable row level security;
alter table public.game_sessions enable row level security;
alter table public.answer_key    enable row level security;
alter table public.players       force row level security;
alter table public.game_sessions force row level security;
alter table public.answer_key    force row level security;
revoke all on public.players, public.game_sessions, public.answer_key from public, anon, authenticated;
revoke all on sequence public.players_player_no_seq from public, anon, authenticated;

-- --------------------------------------------------------------- helpers
create or replace function private.token_hash(p_token text) returns text
language sql immutable set search_path = '' as $$
  select encode(extensions.digest(coalesce(p_token,''), 'sha256'), 'hex')
$$;

create or replace function private.check_player(p_player_id uuid, p_token text) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.players
                 where id = p_player_id and token_hash = private.token_hash(p_token))
$$;

-- Throws 'rate_limited' when one IP makes more than p_max calls of p_kind in p_window.
create or replace function private.rate_limit(p_kind text, p_max int, p_window interval) returns void
language plpgsql security definer set search_path = '' as $$
declare
  h   json := nullif(current_setting('request.headers', true), '')::json;
  ip  text := coalesce(h->>'cf-connecting-ip', nullif(split_part(coalesce(h->>'x-forwarded-for',''), ',', 1), ''));
  ih  text;
begin
  if ip is null then return; end if;          -- unknown origin: don't block everyone together
  ih := private.token_hash('ip:' || btrim(ip));
  delete from private.rate_events where at < now() - interval '1 day';
  if (select count(*) from private.rate_events
      where ip_hash = ih and kind = p_kind and at > now() - p_window) >= p_max then
    raise exception 'rate_limited' using errcode = 'P0001';
  end if;
  insert into private.rate_events (ip_hash, kind) values (ih, p_kind);
end $$;

-- Best finished session per player, ranked. Tie-break: higher score, then
-- shorter server-measured duration, then whoever finished first, then player number.
create or replace function private.ranked()
returns table (rnk bigint, player_id uuid, player_no bigint, name text, score int, correct int,
               total int, duration_ms int, finished_at timestamptz, session_id uuid)
language sql stable security definer set search_path = '' as $$
  with best as (
    select distinct on (s.player_id) s.player_id, s.score, s.correct, s.total, s.duration_ms, s.finished_at, s.id
    from public.game_sessions s
    where s.status = 'finished'
    order by s.player_id, s.score desc, s.duration_ms asc, s.finished_at asc
  )
  select row_number() over (order by b.score desc, b.duration_ms asc, b.finished_at asc, p.player_no asc),
         p.id, p.player_no, p.name, b.score, b.correct, b.total, b.duration_ms, b.finished_at, b.id
  from best b join public.players p on p.id = b.player_id
$$;

-- ------------------------------------------------------------------- API
-- 1) Registration: called when the player submits their name.
create or replace function public.register_player(p_name text) returns json
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_name  text := regexp_replace(btrim(coalesce(p_name,'')), '\s+', ' ', 'g');
  v_token text := encode(extensions.gen_random_bytes(24), 'hex');
  v_id uuid; v_no bigint;
begin
  if char_length(v_name) < 2 or char_length(v_name) > 30 or v_name ~ '[[:cntrl:]<>]' then
    raise exception 'bad_name' using errcode = 'P0001';
  end if;
  perform private.rate_limit('register', 300, interval '10 minutes');
  insert into public.players (name, token_hash) values (v_name, private.token_hash(v_token))
  returning id, player_no into v_id, v_no;
  return json_build_object('player_id', v_id, 'player_no', v_no, 'name', v_name, 'token', v_token);
end $$;

-- 2) Start of a game (button «ادخل اللعبة»). The server clock starts here.
create or replace function public.start_game(p_player_id uuid, p_token text) returns json
language plpgsql volatile security definer set search_path = '' as $$
declare v_id uuid; v_at timestamptz;
begin
  if not private.check_player(p_player_id, p_token) then
    raise exception 'bad_token' using errcode = 'P0001';
  end if;
  if (select count(*) from public.game_sessions
      where player_id = p_player_id and started_at > now() - interval '1 hour') >= 30 then
    raise exception 'rate_limited' using errcode = 'P0001';
  end if;
  perform private.rate_limit('start', 600, interval '10 minutes');
  insert into public.game_sessions (player_id) values (p_player_id) returning id, started_at into v_id, v_at;
  return json_build_object('session_id', v_id, 'started_at', v_at);
end $$;

-- Result + rank for a session's player.
create or replace function private.result_json(p_session_id uuid, p_already boolean) returns json
language sql stable security definer set search_path = '' as $$
  select json_build_object(
    'already',      p_already,
    'score',        s.score,
    'correct',      s.correct,
    'total',        s.total,
    'duration_ms',  s.duration_ms,
    'is_best',      r.session_id = s.id,
    'best_score',   r.score,
    'best_duration_ms', r.duration_ms,
    'rank',         r.rnk,
    'participants', (select count(*) from private.ranked()),
    'player_no',    r.player_no)
  from public.game_sessions s
  join private.ranked() r on r.player_id = s.player_id
  where s.id = p_session_id
$$;

-- 3) End of game. p_answers = JSON array, one object per question:
--    {r, qi, pick, hint, tl, att}
--    pick: option index | word | amount | null (time ran out)
--    tl:   whole seconds left on the clock (timed rounds 0,1,3)
--    att:  0 or 1 — attempts used before the final answer (dalgona round 2)
create or replace function public.finish_game(p_session_id uuid, p_token text, p_answers jsonb) returns json
language plpgsql volatile security definer set search_path = '' as $$
declare
  s        public.game_sessions%rowtype;
  k        public.answer_key%rowtype;
  a        jsonb;
  v_r int; v_qi int; v_pick jsonb; v_hint boolean; v_tl numeric; v_att int; v_limit int;
  v_ok boolean; v_pts int;
  v_score int := 0; v_correct int := 0; v_hints int := 0; v_rope int := 0; v_used numeric := 0;
  v_total int; v_elapsed bigint; v_seen text[] := '{}';
begin
  select * into s from public.game_sessions where id = p_session_id for update;
  if not found then raise exception 'bad_session' using errcode = 'P0001'; end if;
  if not private.check_player(s.player_id, p_token) then
    raise exception 'bad_token' using errcode = 'P0001';
  end if;
  if s.status = 'finished' then return private.result_json(s.id, true); end if;   -- idempotent

  select count(*) into v_total from public.answer_key;
  if jsonb_typeof(p_answers) is distinct from 'array' or jsonb_array_length(p_answers) <> v_total then
    raise exception 'bad_answers' using errcode = 'P0001';
  end if;
  v_elapsed := floor(extract(epoch from (clock_timestamp() - s.started_at)) * 1000);
  if v_elapsed > 12 * 3600 * 1000 then raise exception 'session_expired' using errcode = 'P0001'; end if;

  for a in select value from jsonb_array_elements(p_answers) loop
    if jsonb_typeof(a) <> 'object' or jsonb_typeof(a->'r') <> 'number' or jsonb_typeof(a->'qi') <> 'number'
       or (a->>'r') !~ '^\d$' or (a->>'qi') !~ '^\d{1,2}$' then
      raise exception 'bad_answers' using errcode = 'P0001';
    end if;
    v_r := (a->>'r')::int; v_qi := (a->>'qi')::int;
    if (v_r || ':' || v_qi) = any (v_seen) then raise exception 'bad_answers' using errcode = 'P0001'; end if;
    v_seen := v_seen || (v_r || ':' || v_qi);
    select * into k from public.answer_key where r = v_r and qi = v_qi;
    if not found then raise exception 'bad_answers' using errcode = 'P0001'; end if;

    v_pick := a->'pick';
    v_hint := coalesce(a->'hint' = 'true'::jsonb, false);
    if v_hint then v_hints := v_hints + 1; end if;

    v_limit := case v_r when 0 then 30 when 1 then 60 when 3 then 45 else 0 end;
    v_tl := 0;
    if v_limit > 0 and v_pick is not null and jsonb_typeof(v_pick) <> 'null' then
      if jsonb_typeof(a->'tl') <> 'number' then raise exception 'bad_answers' using errcode = 'P0001'; end if;
      v_tl := round((a->>'tl')::numeric);
      if v_tl < 0 or v_tl > v_limit then raise exception 'bad_answers' using errcode = 'P0001'; end if;
    end if;
    v_att := 0;
    if v_r = 2 and a->'att' = '1'::jsonb then v_att := 1; end if;

    v_ok := case k.kind
      when 'opt'    then jsonb_typeof(v_pick) = 'number' and (v_pick #>> '{}')::numeric = k.correct_opt
      when 'word'   then jsonb_typeof(v_pick) = 'string' and (v_pick #>> '{}') = k.word
      when 'amount' then jsonb_typeof(v_pick) = 'number' and abs((v_pick #>> '{}')::numeric - k.amount) < 0.5
    end;
    v_ok := coalesce(v_ok, false);

    -- same rules as basePts() in index.html
    v_pts := case v_r when 0 then 100 + 5 * v_tl::int
                      when 1 then 150
                      when 2 then case when v_att = 0 then 200 else 100 end
                      when 3 then 150
                      when 4 then 200
                      else 300 end;
    if not v_ok then v_pts := 0; elsif v_hint then v_pts := round(v_pts / 2.0); end if;

    v_score := v_score + v_pts;
    if v_ok then v_correct := v_correct + 1; end if;
    if v_r = 3 then v_rope := v_rope + case when v_ok then 1 else -1 end; end if;
    if v_limit > 0 then v_used := v_used + (v_limit - v_tl); end if;
  end loop;

  if v_hints > 3 then raise exception 'bad_answers' using errcode = 'P0001'; end if;
  if v_rope > 0 then v_score := v_score + 300; end if;          -- tug-of-war bonus
  -- the clock must cover the seconds the answers say were spent on timed questions
  if v_elapsed < greatest(30000, v_used * 1000 - 5000) then
    raise exception 'too_fast' using errcode = 'P0001';
  end if;

  update public.game_sessions
     set status = 'finished', finished_at = clock_timestamp(), score = v_score, correct = v_correct,
         total = v_total, duration_ms = v_elapsed, answers = p_answers
   where id = s.id;
  return private.result_json(s.id, false);
end $$;

-- 4) Public leaderboard (top N + the caller's own row when a player id is given).
create or replace function public.get_leaderboard(p_limit int default 20, p_player_id uuid default null) returns json
language sql stable security definer set search_path = '' as $$
  with r as (select * from private.ranked())
  select json_build_object(
    'participants', (select count(*) from r),
    'generated_at', now(),
    'top', coalesce((select json_agg(json_build_object(
              'rank', rnk, 'player_no', player_no, 'name', name, 'score', score,
              'correct', correct, 'total', total, 'duration_ms', duration_ms) order by rnk)
            from r where rnk <= least(greatest(coalesce(p_limit, 20), 1), 50)), '[]'::json),
    'me', (select json_build_object(
              'rank', rnk, 'player_no', player_no, 'name', name, 'score', score,
              'correct', correct, 'total', total, 'duration_ms', duration_ms)
           from r where p_player_id is not null and r.player_id = p_player_id))
$$;

-- ---------------------------------------------------------------- grants
revoke all on all functions in schema private from public, anon, authenticated;
revoke all on function public.register_player(text)                 from public, anon, authenticated;
revoke all on function public.start_game(uuid, text)                from public, anon, authenticated;
revoke all on function public.finish_game(uuid, text, jsonb)        from public, anon, authenticated;
revoke all on function public.get_leaderboard(int, uuid)            from public, anon, authenticated;
grant execute on function public.register_player(text)              to anon, authenticated;
grant execute on function public.start_game(uuid, text)             to anon, authenticated;
grant execute on function public.finish_game(uuid, text, jsonb)     to anon, authenticated;
grant execute on function public.get_leaderboard(int, uuid)         to anon, authenticated;
