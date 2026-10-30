# SIEM Log Aggregator

A local, $0 SIEM pipeline: Docker attack lab → Kafka → normalizer (ECS schema + OTX tag) → detector (T1110, T1078) → Postgres → FastAPI.

**Read `SPEC.md` before doing any work.** It is the source of truth for field names, topics, thresholds, retention and build order. If the code and the spec disagree, or the spec is unclear, stop and ask. Never silently change the spec to match the code.

## Hard rules

1. Everything runs locally in Docker Compose. No cloud services, no paid APIs, no honeypots.
2. Detection rules read time from the event's `@timestamp`, never from `time.time()` or `datetime.now()`.
3. `normalized-security-events` and `security-alerts` messages are JSON keyed by `source.ip`.
4. Every normalized event validates against the Pydantic `Event` model in `common/schema.py`. Rules read only normalized fields.
5. Retention limits in SPEC.md are requirements: Kafka 2 h / 100 MB per partition with 16 MB segments; Postgres events 24 h.
6. No per-event or per-IP external API calls. OTX is pulled in bulk (last 30 days, IPv4 only, max 100,000 IPs) and checked in memory. Not on the list = `unknown`.
7. The lab network is `internal: true`. Attack tools only ever target lab containers.
8. Simplest working option wins. Anything in SPEC.md's "Out of scope" section is not built, even if it looks quick.

## How to work

- Follow SPEC.md's **Build order** one block at a time. A block is done only when its done-check passes. Don't start the next block until then.
- Keep `PROGRESS.md` up to date: the current block, what's done, what's next, and any open issue. Update it at the end of every block and before stopping. Read it at the start of every session.
- Write unit tests alongside the code, not after. Detection rule changes need the unit cases in SPEC.md's Testing section to pass.
- Config comes from env vars, read in `common/config.py`, with defaults matching SPEC.md. Commit `.env.example`, never `.env`.
- Python 3.12, type hints, Pydantic v2, `confluent-kafka`, `psycopg` 3, FastAPI. Pin versions in each service's `requirements.txt`.

## Commands

```
docker compose up -d --build     # start everything
make test                        # unit tests, no Docker
make pipeline                    # injector scenarios -> alerts in Postgres
make e2e                         # real attacker scenarios A1-A3, C1-C2
make reset                       # docker compose down -v (wipes all data)
docker compose exec attacker attack <scenario>
```

## Subagents (in .claude/agents/)

- **test-runner**: run any `make test` / `make pipeline` / `make e2e`. Returns only failures and likely causes. Use it instead of reading test output in the main session.
- **log-debugger**: when a container won't start, crashes or a stage passes no data. Returns the root error and a suggested fix.
- **spec-checker**: at the end of every build block, before marking it done. Returns mismatches between the code and SPEC.md.

Subagents don't see this conversation. When delegating, say which block you're on, which files changed, and what you expect.
