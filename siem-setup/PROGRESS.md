# PROGRESS

## Current block
1. Lab + scripts — DONE (done-check passed on Docker 2026-10-29). Next: block 2.

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
