# SIEM Log Aggregator — Core Build Spec

Oct 29, 2026

> **Keep in sync.** This file is a copy of the claude.ai doc "SIEM Log Aggregator — Core Build Spec", which is the source of truth. Any change goes in both: edit the doc and ask Claude (in the chat that made it) to regenerate this file. Spec changes agreed during the build are logged in `PROGRESS.md` under "Spec changes" and copied back to the doc.

## Goal and hard rules

Build a local, $0 SIEM pipeline: real SSH and web logs from a Docker attack lab flow through Kafka, get normalized to one schema, tagged with AlienVault OTX intel, checked by two ATT&CK detections (T1110 Brute Force, T1078 Valid Accounts), stored briefly in Postgres, and served by a small FastAPI.

Rules for every agent working on this repo:

1. **Everything runs locally in Docker Compose.** No cloud services, no paid APIs.
2. **Rules read time from the event, never the clock.** Use `@timestamp`, never `time.time()` or `datetime.now()` inside detection logic.
3. **Every Kafka message between services is JSON keyed by `source.ip`** (raw topics may use the IP when the producer can parse it, else no key).
4. **One schema.** All normalized events validate against the Pydantic `Event` model in "Event and alert schema". Rules only read normalized fields.
5. **Keep disk small.** Retention limits in "Storage and retention" are requirements, not suggestions.
6. **No per-event external API calls.** OTX is pulled in bulk; lookups are in memory.
7. **Simplest working option wins.** Anything not in this spec goes under "Out of scope", not into the build.
8. **The lab network has no internet route** (`internal: true`). Only attack containers on that network.

## Architecture

Services never call each other directly: every hop goes through a Kafka topic, so any stage can be restarted or scaled on its own.

```
 Attack lab                                    Injector
 (target-ssh, nginx + DVWA,                    (test scenarios as
  traffic-gen, attacker)                        raw log lines)
        |                                             |
        v                                             |
 producer-ssh, producer-web                           |
 (tail log files from shared volumes)                 |
        |                                             |
        v                                             v
 [Kafka: syslog-raw, web-logs-raw] <------------------+
        |
        v
 normalizer x2  <--------------------------  intel-updater
 (parse lines, map to ECS schema,            (OTX IPv4 set, every 6 h)
  tag OTX status)
        |
        v
 [Kafka: normalized-security-events (key = source.ip)]
        |                                  |
        v                                  v
 detector x2                         storage-writer
 (plugin rules: T1110, T1078)        (batch inserts, deletes events after 24 h)
        |                              ^          |
        v                              |          v
 [Kafka: security-alerts] -------------+     PostgreSQL: events, alerts
        |                                         |
        v                                         v
 FastAPI: REST from Postgres, WS /live from security-alerts; dashboard built on top
```

Normalized events and alerts are keyed by `source.ip`, so every event from one IP reaches the same detector replica and its time windows stay correct.

| Topic | Partitions | Written by | Read by (consumer group) |
| --- | --- | --- | --- |
| `syslog-raw` | 3 | producer-ssh, injector | normalizers |
| `web-logs-raw` | 3 | producer-web | normalizers |
| `normalized-security-events` | 3 | normalizers (key = source.ip) | detectors, storage |
| `security-alerts` | 3 | detectors (key = source.ip) | storage, api |

## Kafka

One `apache/kafka` broker in KRaft mode; every service connects to `kafka:9092` on the Compose network. No port is published to the host; debug with `docker compose exec kafka /opt/kafka/bin/...`.

- **Topics are created explicitly.** A one-shot `kafka-init` service runs `kafka-topics.sh --create --if-not-exists` for the four topics above: 3 partitions, replication factor 1. The broker sets `KAFKA_AUTO_CREATE_TOPICS_ENABLE=false`, so a client can never create a 1-partition topic by accident.
- **Retention** is set on the broker (see Storage and retention).
- **Consumers:** `enable.auto.commit=false`; commit offsets only after a message is fully processed (storage-writer: after its batch insert commits). `auto.offset.reset=earliest` for normalizers, detectors and storage; `latest` for api.
- **Producers:** read their log file from the start, follow it for new lines, and reopen from the start if the file shrinks (after `make reset`). Re-sent lines are harmless because `event.id` is deterministic (see the schema section).
- **Startup order:** `kafka` has a healthcheck (`kafka-topics.sh --bootstrap-server localhost:9092 --list`), `postgres` uses `pg_isready`. Producers, normalizers, detectors, storage-writer and api use `depends_on` with `condition: service_healthy` on what they need, plus `condition: service_completed_successfully` on `kafka-init`.

## Repo layout and services

One repo, one `docker-compose.yml`, Python 3.12 for every service.

```
siem/
  docker-compose.yml
  Makefile
  .env.example          # OTX_API_KEY, thresholds, ATTACK_INTERVAL_MIN=0
  common/               # schema.py (Event, Alert), kafka.py helpers, config.py
  lab/
    nginx/nginx.conf    # reverse proxy to dvwa, combined access log
    traffic-gen/        # Dockerfile, traffic.py
    attacker/           # Dockerfile, attack.sh, wordlists/
  producers/tail.py     # --source ssh|web --file <path> --topic <topic>
  normalizer/           # main.py, parsers/ssh.py, parsers/nginx.py, enrich.py
  intel/updater.py      # OTX bulk pull -> /data/intel/otx_ipv4.json
  detector/             # engine.py, state.py, rules/__init__.py (RULES list), rules/*.py
  storage/              # writer.py, schema.sql
  api/main.py           # FastAPI
  injector/inject.py    # writes scenario log lines straight to raw topics
  tests/                # unit/, pipeline/, e2e/
```

| Service | Image or build | Purpose | Replicas |
| --- | --- | --- | --- |
| kafka | `apache/kafka` (KRaft, single broker) | All topics | 1 |
| postgres | `postgres:16-alpine` | Events (24 h) and alerts | 1 |
| target-ssh | `linuxserver/openssh-server` | SSH target, listens on port 2222 | 1 |
| dvwa + dvwa-db | `ghcr.io/digininja/dvwa` + `mariadb` | Vulnerable web app and its database | 1 |
| target-web | `nginx:alpine` | Reverse proxy in front of DVWA; writes the access log | 1 |
| traffic-gen | build `lab/traffic-gen` (python:3.12-slim) | Normal SSH logins and page views | 1 |
| attacker | build `lab/attacker` (debian:bookworm-slim + hydra, sshpass) | On-demand attack scenarios | 1 |
| producer-ssh, producer-web | build `producers` | Tail log files into raw topics | 1 each |
| normalizer | build `normalizer` | Parse, normalize, OTX tag | 2 |
| intel-updater | build `intel` | Pull OTX IPv4 indicators every 6 h | 1 |
| detector | build `detector` | Plugin rules engine | 2 |
| storage-writer | build `storage` | Batch inserts, retention cleanup | 1 |
| api | build `api` | REST + WebSocket on port 8000 | 1 |

Log files reach the producers through shared named volumes, mounted read-only on the producer side. On first run, check the openssh-server image's actual log path and line prefix; the SSH parser must handle whatever prefix that image adds.

## Event and alert schema

Every normalized event uses a small subset of Elastic Common Schema (ECS) field names. Pydantic models live in `common/schema.py`; JSON on the wire uses the dotted ECS names as nested objects (`{"source": {"ip": "..."}}`).

| ECS field | Type | SSH example | Web example |
| --- | --- | --- | --- |
| `@timestamp` | datetime (UTC) | 2026-10-29T06:12:01Z | 2026-10-29T06:12:03Z |
| `event.id` | UUID | UUIDv5 of observer.type + raw line | UUIDv5 of observer.type + raw line |
| `event.category` | str | authentication | web |
| `event.action` | str | ssh_login | http_request |
| `event.outcome` | success \| failure \| unknown | failure | success (status < 400) |
| `event.severity` | int 0–100 | 20 (failure), 0 (success) | 0 |
| `event.original` | str | full raw line | full raw line |
| `source.ip` | IPv4/IPv6 str | 172.20.0.5 | 172.20.0.5 |
| `user.name` | str \| null | admin | null |
| `url.original` | str \| null | null | /vulnerabilities/sqli/?id=1 |
| `http.request.method` | str \| null | null | GET |
| `http.response.status_code` | int \| null | null | 200 |
| `user_agent.original` | str \| null | null | Mozilla/5.0 ... |
| `threat.indicator.status` | known_bad or unknown | unknown | unknown |
| `observer.type` | str | ssh | nginx |

SSH lines to parse (others are ignored, not errors):

- `Failed password for <user> from <ip> port <n> ssh2` → failure
- `Failed password for invalid user <user> from <ip> ...` → failure
- `Accepted password for <user> from <ip> port <n> ssh2` → success

**Timestamps are UTC.** The openssh-server image prefixes each line with a timestamp that has no timezone and no `sshd[pid]:` part, e.g. `2026-10-29 08:55:38.274  Accepted password for ...`. `target-ssh` sets `TZ=Etc/UTC`, and the SSH parser reads that prefix as UTC. Nginx uses the standard combined log format, whose timestamps carry their own offset; convert them to UTC.

**`event.id` is deterministic:** a UUIDv5 of `observer.type` + the raw line. The same line always gets the same ID, so a line sent twice is dropped by `ON CONFLICT DO NOTHING`.

**Alert** (published to `security-alerts`, stored in `alerts`):

| Field | Type | Notes |
| --- | --- | --- |
| `alert.id` | UUID | |
| `@timestamp` | datetime | time of the triggering event |
| `rule.id` | str | e.g. ssh-bruteforce, ssh-valid-after-bruteforce |
| `threat.technique.id` | str | T1110.001, T1110.003, T1078 |
| `severity` | int 0–100 | 50 for T1110, 80 for T1078 |
| `source.ip` | str | |
| `first_seen`, `last_seen` | datetime | span of the evidence events |
| `event_count` | int | events in the window |
| `details` | dict | usernames tried, OTX status, short reason |

## Attack lab

The lab produces both normal and attack logs. Attacks run only when you call them; nothing waits on a timer.

**Lab accounts on target-ssh:** `admin` (weak password `password123`, the attack target) plus 2–3 normal users with strong passwords for traffic-gen. Put all credentials in `.env`.

**traffic-gen** loops forever with random 2–20 s sleeps:

- SSH login with the correct password as a normal user (paramiko), then disconnect.
- About 1 in 10 logins: one wrong password first, then the right one (control C1).
- HTTP GET of normal DVWA pages through target-web with a browser user agent.

**attacker** runs one scenario per command: `docker compose exec attacker attack <scenario>`. Setting `ATTACK_INTERVAL_MIN` above 0 also runs A1–A3 on a timer for unattended demos (default 0 = off). Use `hydra -t 4`; more parallel connections get dropped by sshd and show up as connection errors instead of failed logins.

| Scenario | What runs | Expected result |
| --- | --- | --- |
| A1 `bruteforce-fail` | `hydra -l admin -P wordlists/no_hit.txt -t 4 ssh://target-ssh:2222` (about 50 wrong passwords) | One T1110.001 alert, no T1078 |
| A2 `bruteforce-success` | Same, with `wordlists/hit.txt` (real password near the end) | T1110.001 alert, then one T1078 alert |
| A3 `password-spray` | `hydra -L wordlists/users.txt -p 'Winter2026!' -t 4 ssh://target-ssh:2222` (≥ 5 usernames) | One T1110.003 alert |
| C1 `normal-typo` (control) | One wrong password, then the right one | No alert |
| C2 `slow-guess` (control) | `sshpass` loop: one wrong guess every 30 s for 5 min | No alert (documented blind spot) |

**DVWA one-time setup:** open it in a browser, click Create/Reset Database, log in as admin / password, set security to Low. DVWA only serves normal traffic in the core build; web attacks are on the later list.

## Detection engine

One detector service with rules as plugins: each rule is a class with the same two methods, and the engine offers every event to every rule in the `RULES` list. Adding a rule = one new class + one line in `detector/rules/__init__.py`. The engine, Kafka code and other rules never change.

```python
class Rule(Protocol):
    id: str
    technique: str
    severity: int
    def applies(self, ev: Event) -> bool: ...                       # cheap filter
    def evaluate(self, ev: Event, st: IpState) -> list[Alert]: ...  # 0..n alerts

# detector/engine.py
for msg in consumer:                      # group "detectors", topic normalized-security-events
    ev = Event.model_validate_json(msg.value())
    st = states[ev.source.ip]             # created on first sight
    for rule in RULES:
        if rule.applies(ev):
            for alert in rule.evaluate(ev, st):
                producer.produce("security-alerts", key=ev.source.ip, value=alert.json())
```

**IpState** (in memory, one per source IP): sliding windows of timestamps (`window(name, seconds)`), a set of usernames per window, per-rule cooldowns, and flags with timestamps (`mark(name, ts)`, `seen_within(name, seconds, now)`). All "now" values are the current event's `@timestamp`. Evict IPs idle for 30 min (by event time) so memory stays flat. State resets if a detector restarts; that is an accepted limitation.

| Rule | Technique | Fires when | Severity |
| --- | --- | --- | --- |
| `ssh-bruteforce` | T1110.001 Password Guessing | ≥ 10 SSH failures from one IP within 60 s | 50 |
| `ssh-bruteforce` | T1110.003 Password Spraying | Failures from one IP against ≥ 5 distinct `user.name` within 5 min | 50 |
| `ssh-valid-after-bruteforce` | T1078 Valid Accounts | SSH success from an IP whose `bruteforce_seen` flag is set within the last 10 min | 80 |

- The alert fires on the event that crosses the threshold, not when the window ends.
- Cooldown: one alert per rule per IP per 5 min. A 50-guess hydra run produces one T1110 alert.
- BruteForce sets `bruteforce_seen` whenever it fires; ValidAccounts only reads that flag.
- All thresholds come from env vars (`BF_FAIL_COUNT=10`, `BF_WINDOW_S=60`, `SPRAY_USERS=5`, `SPRAY_WINDOW_S=300`, `VALID_LOOKBACK_S=600`, `COOLDOWN_S=300`).

## OTX enrichment

AlienVault OTX indicators are pulled in bulk and checked in memory; there is no OTX call per event. OTX is free with an account; the API key comes from the API Integration section of your OTX settings and goes in `.env` as `OTX_API_KEY`.

- **intel-updater:** on startup and every 6 h, uses the official `OTXv2` Python SDK to read pulses your account subscribes to, modified in the **last 30 days** only. Confirm the SDK's method names against its repo examples before coding.
- **IPv4 only, capped at 100,000.** Keep only IPv4 indicators and discard every other type (domains, URLs, hashes) as the data arrives. Stop once 100,000 unique IPs are collected, newest pulses first. The saved file is a JSON list at `/data/intel/otx_ipv4.json`, about 2 MB.
- **No per-IP API calls.** The pipeline never asks OTX about a single IP.
- **normalizer tagging:** loads that file at start and reloads it when its modified time changes. Every event gets `threat.indicator.status`:
  - `known_bad` when `source.ip` is in the set; add 20 to `event.severity`.
  - `unknown` when it isn't (including every private lab IP); `event.severity` is unchanged. Not on the list means not known, not safe.
- **No key or empty set:** log a warning; every event is tagged `unknown`. The pipeline must never block on OTX.
- **Demo:** lab traffic will always show `unknown`. `injector` takes `--ip` so a scenario can be sent from an IP copied out of `otx_ipv4.json` to show `known_bad`. The updater logs the IP count and file size after each pull.

## Storage and retention

The whole project keeps well under 1 GB of data. These limits are requirements.

| Where | Limit | How |
| --- | --- | --- |
| Kafka topics | 2 h or 100 MB per partition | `KAFKA_LOG_RETENTION_HOURS=2`, `KAFKA_LOG_RETENTION_BYTES=104857600`, `KAFKA_LOG_SEGMENT_BYTES=16777216` (Kafka deletes whole segments only; the 1 GB default would never roll) |
| Postgres `events` | 24 h | storage-writer runs `DELETE FROM events WHERE ts < now() - interval '24 hours'` every 10 min |
| Postgres `alerts` | Kept | One row per attack, not per line |
| Lab log files | Until reset | `make reset` = `docker compose down -v` |

**storage-writer** consumes `normalized-security-events` and `security-alerts` (group `storage`), buffers rows, and inserts every 500 rows or 1 s, whichever comes first.

```sql
CREATE TABLE events (
  id          BIGSERIAL PRIMARY KEY,
  event_id    UUID UNIQUE,
  ts          TIMESTAMPTZ NOT NULL,
  source_ip   INET,
  category    TEXT, action TEXT, outcome TEXT,
  user_name   TEXT, url TEXT, status_code INT,
  severity    SMALLINT,
  intel_status TEXT,                    -- known_bad | unknown
  raw         TEXT
);
CREATE INDEX ON events (ts DESC);
CREATE INDEX ON events (source_ip, ts DESC);

CREATE TABLE alerts (
  id          BIGSERIAL PRIMARY KEY,
  alert_id    UUID UNIQUE,
  ts          TIMESTAMPTZ NOT NULL,
  rule_id     TEXT, technique TEXT, severity SMALLINT,
  source_ip   INET,
  first_seen  TIMESTAMPTZ, last_seen TIMESTAMPTZ,
  event_count INT,
  details     JSONB
);
CREATE INDEX ON alerts (ts DESC);
```

Use `ON CONFLICT DO NOTHING` on the UUID columns so a replayed Kafka message never duplicates a row.

## API

FastAPI on port 8000, four endpoints. The dashboard is built on top of these and is not specified here.

| Endpoint | Returns | Source |
| --- | --- | --- |
| `GET /alerts?since=&limit=50` | Newest alerts first | Postgres `alerts` |
| `GET /events?ip=&since=&limit=100` | Events for one IP, newest first | Postgres `events` |
| `GET /stats` | Counts of events and alerts in the last hour, by severity band and by technique | Postgres |
| `WS /live` | Each new alert as JSON as it arrives | Kafka `security-alerts`, own consumer group `api` |

Also expose `GET /health` returning 200 once Postgres and Kafka are reachable; `make e2e` waits on it.

## Testing

Three levels, fastest first. Nothing waits on a timer: rules fire when a threshold is crossed, and unit tests set event timestamps directly.

| Level | Command | What it checks | Speed |
| --- | --- | --- | --- |
| 1. Unit | `make test` | Rule logic: pytest builds `Event` objects with chosen timestamps and calls `rule.evaluate()`. No Docker. | < 1 s |
| 2. Pipeline | `make pipeline` | `injector` writes each scenario's raw SSH lines to `syslog-raw`; the test polls Postgres for the expected alerts within 15 s | ~10 s per scenario |
| 3. End to end | `make e2e` | Runs attacker scenarios A1–A3 and C1–C2 in turn, checks `GET /alerts` after each against the table in Attack lab | ~5 min |

Unit cases that must pass before the detector ships:

- [ ] 10 failures from one IP within 59 s → one T1110.001 alert; 9 failures → none
- [ ] 10 failures spread over 5 min → none (C2 blind spot, tested on purpose)
- [ ] 25 failures in a row → still one alert (cooldown)
- [ ] Brute force, then success from the same IP within 10 min → T1078; same success from another IP → none
- [ ] Success with no prior failures → none; one typo then success → none (C1)
- [ ] One IP failing against 5 distinct usernames within 5 min → T1110.003
- [ ] SSH parser: each of the three line types parses; an unrelated sshd line returns None
- [ ] Nginx parser: a combined-format line maps to every web field in the schema

`make reset` wipes Kafka, Postgres and log volumes between demo runs.

## Build order

Build in this order; each block is done only when its check passes. Rough total: 9–11 hours.

- [ ] **1. Lab + scripts (2 h).** Compose file with targets, traffic-gen and attacker. Done when `docker compose up` produces SSH and Nginx log lines from traffic-gen, and `attack bruteforce-fail` adds about 50 failure lines.
- [ ] **2. Pipeline core (2–3 h).** Kafka with topics and retention, producers, normalizer, storage-writer. Done when lab events appear in Postgres `events` with every field that applies to their source filled (web-only fields stay null on SSH events).
- [ ] **3. Detection (2 h).** Engine, IpState, both rules, unit tests, injector. Done when `make test` and `make pipeline` pass.
- [ ] **4. OTX enrichment (1 h).** intel-updater and normalizer tagging. Done when an injected event from an OTX IP has `threat.indicator.status = known_bad`.
- [ ] **5. API (1 h).** Four endpoints plus health. Done when `make e2e` passes all five scenarios. Dashboard is built on top afterward.
- [ ] **6. README (1 h).** Architecture diagram, how to run, screenshot of alerts firing, `kafka-consumer-groups --describe --group detectors` output showing 2 detectors sharing partitions, and the C2 blind spot explained.

## Out of scope for the core build

Agents must not build these yet; they come after every block above passes.

- Web detections (T1595 Active Scanning, T1190 Exploit Public-Facing Application, T1059.004 Unix Shell) and their lab attacks (gobuster, nikto, sqlmap, command injection)
- Cross-source correlation rule (same IP alerting on SSH and web)
- Public dataset replay (Loghub OpenSSH), load testing and the scaling chart
- GeoIP and extra blocklists; OTX lookups for IPs not in the cached list (per-alert context); pulling more than 100,000 OTX IPs or more than 30 days of pulses
- Redis for detector state; dead-letter topic for unparseable lines
- Zeek / Suricata and the `network-raw` topic
- CI, ATT&CK Navigator layer
