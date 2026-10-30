# PROGRESS

## Current block
4. OTX enrichment — DONE (done-check passed on Docker 2026-10-30). Blocks 1-3 DONE.
   Next: block 5 (API). Unit tests 25/25.

## Block 4 — OTX enrichment (done 2026-10-30)
- normalizer/enrich.py: OtxTagger loads /data/intel/otx_ipv4.json, tags known_bad
  (+20 severity, cap 100) / unknown, reloads on mtime change; missing/empty file
  -> all unknown (pipeline never blocks). Wired into normalizer/main.py. 3 unit
  tests (test_enrich.py).
- intel/updater.py: OTXv2 SDK (1.5.12) getall_iter(modified_since=30d), IPv4 only,
  cap OTX_MAX_IPS, atomic write to the cache; refresh every OTX_REFRESH_S (6h);
  missing key/SDK error never crashes. EPHEMERAL: deletes the file on startup and
  on SIGTERM/SIGINT; intel_cache is a named volume (not a host bind-mount), wiped
  by make reset.
- docker-compose: intel-updater service (OTX_API_KEY/OTX_MAX_IPS/… from .env),
  intel_cache volume, normalizer mounts it :ro. common/config.py OTX_* added;
  .env.example documents OTX_MAX_IPS/LOOKBACK/REFRESH (key stays in .env only).
- Done-check PASSED: key authenticates (AUTH OK, real IPv4 returned); intel-updater
  pulled 442 IPv4 (tested with OTX_MAX_IPS=500 for speed; prod default 100000);
  injected event from an OTX IP -> intel_status=known_bad, severity 20->40 (fail)
  / 0->20 (success); non-OTX IP -> unknown, severity unchanged. File confirmed
  DELETED-ON-SHUTDOWN and re-pulled on restart.
- NOTE: the running intel-updater container currently has OTX_MAX_IPS=500 baked in
  from the test `up`. To use the full 100000 cap, set OTX_MAX_IPS in .env (or omit)
  and recreate: `docker compose up -d --build intel-updater`.
- spec-checker: 1 mismatch ("newest pulses first" not enforced) RESOLVED — verified
  the OTX subscribed-pulses endpoint yields pulses newest-first (modified desc), so
  early-stop at the cap keeps the newest; pull_ipv4 documents this and warns if the
  order is ever violated. Ephemeral-file requirement: PASS. Everything else matched.

## Block 3 — Detection (code complete 2026-10-29)
- detector/state.py: IpState (deque of (ts,user) failures, per-(rule,technique)
  cooldowns, flags) + StateStore (event-time eviction, EVICT_IDLE_S=1800).
- detector/rules/: base.py (Rule Protocol + build_alert), ssh_bruteforce.py
  (T1110.001 per (ip,user) >=10/60s; T1110.003 >=5 distinct users/300s; sets
  bruteforce_seen), valid_after_bruteforce.py (T1078 on success if bruteforce_seen
  within 600s), __init__.py RULES list.
- detector/engine.py: consume normalized (group detectors), run RULES, produce
  alerts keyed by source.ip, commit after flush, opportunistic evict.
- injector/inject.py: scenario raw SSH lines -> syslog-raw, controlled @timestamps,
  --ip/--user. detector + injector added to docker-compose (detector x2; injector
  in `tools` profile, run on demand).
- tests/unit/: test_bruteforce.py + test_valid_after.py (+factories.py); all SPEC
  cases incl. the 3 revised ones. 22/22 unit tests pass.
- tests/pipeline/run_pipeline.sh + Makefile `pipeline`: injects A1-A3/C1-C2 with a
  fresh random /16 per run, polls Postgres alerts (15s each).

## Block 3 done-check — PASSED on Docker 2026-10-29 (user-confirmed)
- [x] `make test` passes (22/22: parsers + detection, incl. 3 revised cases)
- [x] `make pipeline` passes (A1->T1110.001; A2->T1110.001+T1078; A3->T1110.003;
      C1/C2 -> no alert)

## Spec changes (agreed during build — MIRROR THESE INTO THE claude.ai DOC)
- 2026-10-29 (block 3 design): T1110.001 Password Guessing redefined from
  "≥10 SSH failures from one IP within 60 s" (IP-level) to "≥10 failures against
  the same (source.ip, user.name) within 60 s" (per-user). T1110.003 spray stays
  ≥5 distinct usernames/IP in 5 min. Cooldown is now per (rule, technique,
  source.ip) so T1110.001 and T1110.003 alert independently. Rationale: cleanly
  separates guessing from spraying; A1/A2 (same user `admin`) still fire
  T1110.001, A3 (distinct users) fires T1110.003 only — documented expected
  results unchanged. SPEC.md updated (Detection engine table + cooldown bullet +
  Testing cases). User to copy this into the source-of-truth claude.ai doc.
  Also tidied two illustrative samples in SPEC.md to match: Rule Protocol no
  longer lists a single `technique: str` (a rule may emit multiple techniques);
  IpState description now says a (timestamp, user.name) failure window + per-
  (rule, technique) cooldowns instead of `window(name, seconds)`.

## Block 2 — Pipeline core (code complete 2026-10-29)
- common/: schema.py (Event/Alert, Pydantic v2, nested dotted ECS JSON, UUIDv5
  event.id via make_event_id), config.py (topics, groups, PG, thresholds),
  kafka.py (producer/consumer helpers; enable.auto.commit=false).
- producers/tail.py: --source/--file/--topic; reads from start, follows, reopens
  on truncation/inode change; raw lines produced unkeyed (SPEC allows).
- normalizer/: main.py (consume raw topics group `normalizers`, parse, enrich,
  produce normalized keyed by source.ip, commit after produce), parsers/ssh.py
  (strips UTC ns timestamp prefix; 3 line types; else None), parsers/nginx.py
  (combined format -> all web fields, tz->UTC), enrich.py (block 2: always
  `unknown`; OTX plugs in here at block 4).
- storage/: schema.sql (idempotent CREATE ... IF NOT EXISTS), writer.py (consumes
  normalized + alerts group `storage`; batch 500/1s; ON CONFLICT DO NOTHING;
  commit Kafka offsets after DB commit; 24h retention every 10 min).
- docker-compose.yml: added kafka (KRaft, AUTO_CREATE=false, retention env),
  kafka-init (one-shot, 4 topics x3 partitions RF1), postgres (healthcheck),
  producer-ssh/web, normalizer x2, storage-writer; healthchecks + depends_on
  (service_healthy + kafka-init service_completed_successfully). New `siem`
  network (non-internal) for the pipeline; lab stays internal.
- tests/unit/: test_ssh_parser.py, test_nginx_parser.py (all 3 SSH types +
  unrelated line None; combined line maps every web field + tz convert). 9 pass.
- pytest.ini (pythonpath=.), tests/requirements.txt, Makefile `test` -> pytest,
  .env.example +Postgres creds.

## Block 2 done-check — PASSED on Docker 2026-10-29
- [x] 13/13 services healthy; 4 topics created (3 partitions each); kafka-init
      Exited(0); both normalizers + storage-writer running; no errors/tracebacks.
- [x] events in Postgres: 7 SSH (authentication/ssh_login) + 5 web (web/http_request).
- [x] SSH row: source_ip, user_name, outcome, severity, intel_status=unknown, UTC ts
      filled; url/status_code NULL (web-only fields null on SSH). 
- [x] Web row: source_ip, url, status_code, outcome (302<400=success), severity=0,
      intel_status=unknown, UTC ts filled; user_name NULL (SSH-only field null on web).

## Gotcha fixed during block 2 done-check
- The user's `.env` was copied from `.env.example` in block 1, BEFORE the Postgres
  vars were added, so POSTGRES_USER/PASSWORD/DB were blank and postgres:16-alpine
  refused to start ("Database is uninitialized and superuser password is not
  specified"). Fixed by appending POSTGRES_USER/PASSWORD/DB=siem to `.env`.
  Lesson: when new vars are added to `.env.example`, an existing `.env` must be
  updated too (compose does not merge them automatically).

## Done (block 1)
- Read CLAUDE.md and SPEC.md
- `docker-compose.yml`: lab services only — target-ssh, dvwa + dvwa-db,
  target-web (nginx reverse proxy), traffic-gen, attacker. Lab network
  `internal: true`; shared volumes `ssh_logs`, `web_logs`.
- `lab/target-ssh/init-users.sh`: creates normal SSH users (admin via image env)
- `lab/nginx/nginx.conf`: reverse proxy to DVWA, combined access log to volume
- `lab/traffic-gen/`: paramiko SSH logins (~1/10 typo-then-retry = C1) + DVWA GETs
- `lab/attacker/`: `attack <scenario>` for A1–A3, C1–C2; wordlists
  (no_hit.txt 51, hit.txt with real pw near end, users.txt 7 users); timed mode
  via ATTACK_INTERVAL_MIN
- `.env.example`, `.gitignore` (ignores .env), `Makefile` (up/down/reset + stubs)

## Done-check (block 1) — PASSED on Docker 2026-10-29
- [x] traffic-gen produces SSH log lines: real file /config/logs/openssh/current
      has `Accepted password for alice/bob ...` (confirmed `LOG_STDOUT=false` path).
- [x] traffic-gen produces Nginx log lines: combined format with browser UA.
- [x] `attack bruteforce-fail` adds ~50 failures: +59 `Failed password` lines,
      hydra 51 tries, 0 valid found.

## Verified-on-first-run facts (feed block 2)
- SSH log path CONFIRMED: `/config/logs/openssh/current`, each line prefixed with
  a high-precision local timestamp, e.g.
  `2026-10-29 08:55:38.274  Accepted password for bob from 172.18.0.5 port 42240 ssh2`.
  The SSH parser must strip that leading timestamp prefix (there is no hostname/
  `sshd[pid]:` prefix from this image). Source IP appears as the lab subnet (172.18.0.x).
- `/custom-cont-init.d/10-normal-users.sh` hook WORKS; alice/bob/carol created.
  Minor: image logs `Failed to set uids to 100x` after a normal-user login
  (normal users have shell /bin/false); the `Accepted password` line is still
  logged, so it does not affect parsing. Left as-is.
- nginx FIX applied: image ships access.log as a symlink to /dev/stdout, which
  made `tail` hang and left no file to tail. target-web now runs a command that
  `rm`s the symlink so nginx writes a REAL file at /var/log/nginx/access.log on
  the web_logs volume (docker-compose.yml target-web `command:`).

## Next
- Block 2 (Pipeline core): Kafka + topics + retention, producers, normalizer,
  storage-writer. First real-run task: confirm the openssh-server image's actual
  log path + line prefix (SPEC says to check on first run) and point producer-ssh
  at it; also locate the DVWA one-time browser setup step.

## Open issues
- DVWA needs a one-time browser setup (Create/Reset DB, security=Low). Outside-
  the-editor step — ask the user before doing it. Not needed until web traffic
  matters; core build only uses DVWA for normal GETs.

## NOTE for block 4 (OTX)
- The real OTX_API_KEY goes in `.env` ONLY, never `.env.example`. Ask the user
  for permission / the key before touching anything OTX-related.
