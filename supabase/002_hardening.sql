-- Hardening after the pre-launch security review. Safe to re-run.
-- 1) Rate limit keys on Cloudflare's cf-connecting-ip (set by Cloudflare, cannot be forged by
--    the client); never on the client-controlled first entry of X-Forwarded-For.
-- 2) finish_game: payload size cap, and only a normalized copy of the answers is stored.
-- 3) A finished game must take at least 60 s of server time (a human cannot do 34 questions faster).
-- 4) Moderation: players.hidden removes a player from the ranking without deleting data.

alter table public.players add column if not exists hidden boolean not null default false;

create or replace function private.rate_limit(p_kind text, p_max int, p_window interval) returns void
language plpgsql security definer set search_path = '' as $$
declare
  h   json := nullif(current_setting('request.headers', true), '')::json;
  ip  text := nullif(btrim(h->>'cf-connecting-ip'), '');
  ih  text;
begin
  if ip is null then return; end if;
  ih := private.token_hash('ip:' || ip);
  delete from private.rate_events where at < now() - interval '1 day';
  if (select count(*) from private.rate_events
      where ip_hash = ih and kind = p_kind and at > now() - p_window) >= p_max then
    raise exception 'rate_limited' using errcode = 'P0001';
  end if;
  insert into private.rate_events (ip_hash, kind) values (ih, p_kind);
end $$;

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
  where not p.hidden
$$;

create or replace function private.result_json(p_session_id uuid, p_already boolean) returns json
language sql stable security definer set search_path = '' as $$
  select json_build_object(
    'already',      p_already,
    'score',        s.score,
    'correct',      s.correct,
    'total',        s.total,
    'duration_ms',  s.duration_ms,
    'is_best',      coalesce(r.session_id = s.id, false),
    'best_score',   r.score,
    'best_duration_ms', r.duration_ms,
    'rank',         r.rnk,
    'participants', (select count(*) from private.ranked()),
    'player_no',    p.player_no)
  from public.game_sessions s
  join public.players p on p.id = s.player_id
  left join private.ranked() r on r.player_id = s.player_id
  where s.id = p_session_id
$$;

create or replace function public.finish_game(p_session_id uuid, p_token text, p_answers jsonb) returns json
language plpgsql volatile security definer set search_path = '' as $$
declare
  s        public.game_sessions%rowtype;
  k        public.answer_key%rowtype;
  a        jsonb;
  v_r int; v_qi int; v_pick jsonb; v_hint boolean; v_tl numeric; v_att int; v_limit int;
  v_ok boolean; v_pts int;
  v_score int := 0; v_correct int := 0; v_hints int := 0; v_rope int := 0; v_used numeric := 0;
  v_total int; v_elapsed bigint; v_seen text[] := '{}'; v_norm jsonb := '[]'::jsonb;
begin
  if p_answers is null or pg_column_size(p_answers) > 16384 then
    raise exception 'bad_answers' using errcode = 'P0001';
  end if;
  select * into s from public.game_sessions where id = p_session_id for update;
  if not found then raise exception 'bad_session' using errcode = 'P0001'; end if;
  if not private.check_player(s.player_id, p_token) then
    raise exception 'bad_token' using errcode = 'P0001';
  end if;
  if s.status = 'finished' then return private.result_json(s.id, true); end if;

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
    if v_pick is null then v_pick := 'null'::jsonb; end if;
    if jsonb_typeof(v_pick) not in ('number','string','null')
       or (jsonb_typeof(v_pick) = 'string' and char_length(v_pick #>> '{}') > 20)
       or (jsonb_typeof(v_pick) = 'number' and abs((v_pick #>> '{}')::numeric) > 1e12) then
      raise exception 'bad_answers' using errcode = 'P0001';
    end if;
    v_hint := coalesce(a->'hint' = 'true'::jsonb, false);
    if v_hint then v_hints := v_hints + 1; end if;

    v_limit := case v_r when 0 then 30 when 1 then 60 when 3 then 45 else 0 end;
    v_tl := 0;
    if v_limit > 0 and jsonb_typeof(v_pick) <> 'null' then
      if jsonb_typeof(a->'tl') is distinct from 'number' then raise exception 'bad_answers' using errcode = 'P0001'; end if;
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
    v_norm := v_norm || jsonb_build_array(jsonb_build_object('r', v_r, 'qi', v_qi, 'pick', v_pick,
                'hint', v_hint, 'tl', v_tl, 'att', v_att, 'ok', v_ok, 'pts', v_pts));
  end loop;

  if v_hints > 3 then raise exception 'bad_answers' using errcode = 'P0001'; end if;
  if v_rope > 0 then v_score := v_score + 300; end if;
  if v_elapsed < greatest(60000, v_used * 1000 - 5000) then
    raise exception 'too_fast' using errcode = 'P0001';
  end if;

  update public.game_sessions
     set status = 'finished', finished_at = clock_timestamp(), score = v_score, correct = v_correct,
         total = v_total, duration_ms = v_elapsed, answers = v_norm
   where id = s.id;
  return private.result_json(s.id, false);
end $$;

drop function if exists public.tmp_ip_probe();

revoke all on all functions in schema private from public, anon, authenticated;
revoke all on function public.finish_game(uuid, text, jsonb) from public, anon, authenticated;
grant execute on function public.finish_game(uuid, text, jsonb) to anon;

-- The game has no signed-in users (Auth sign-ups are disabled), so only anon may call the API.
revoke execute on function public.register_player(text), public.start_game(uuid, text),
  public.finish_game(uuid, text, jsonb), public.get_leaderboard(int, uuid) from authenticated;
