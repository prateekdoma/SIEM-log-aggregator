"""storage-writer: batch normalized events and alerts into Postgres.

Consumes normalized-security-events and security-alerts (group `storage`), buffers
rows, and inserts every STORAGE_BATCH_SIZE rows or STORAGE_FLUSH_SECONDS, whichever
comes first. Kafka offsets are committed only after the batch INSERT commits, so a
crash replays uncommitted messages; ON CONFLICT DO NOTHING on the UUID columns makes
replays idempotent. Every RETENTION_INTERVAL_SECONDS it deletes events older than
EVENTS_RETENTION_HOURS. Nothing writes alerts until block 3, but the alert path is
wired now (SPEC "Kafka" change 4).

Batch flush timing and retention use the wall clock on purpose; the "read time from
the event" rule applies to detection logic, not to storage housekeeping.
"""
from __future__ import annotations

import pathlib
import signal
import sys
import time

import psycopg
from confluent_kafka import KafkaError
from psycopg.types.json import Jsonb

from common import config
from common.kafka import make_consumer
from common.schema import Alert, Event

SCHEMA_PATH = pathlib.Path(__file__).with_name("schema.sql")

_INSERT_EVENT = """
INSERT INTO events
  (event_id, ts, source_ip, category, action, outcome,
   user_name, url, status_code, severity, intel_status, raw)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (event_id) DO NOTHING
"""

_INSERT_ALERT = """
INSERT INTO alerts
  (alert_id, ts, rule_id, technique, severity, source_ip,
   first_seen, last_seen, event_count, details)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (alert_id) DO NOTHING
"""

_running = True


def _stop(*_: object) -> None:
    global _running
    _running = False


def _event_row(ev: Event) -> tuple:
    return (
        str(ev.event.id),
        ev.timestamp,
        ev.source.ip,
        ev.event.category,
        ev.event.action,
        ev.event.outcome,
        ev.user.name,
        ev.url.original,
        ev.http.response.status_code,
        ev.event.severity,
        ev.threat.indicator.status,
        ev.event.original,
    )


def _alert_row(al: Alert) -> tuple:
    return (
        str(al.alert.id),
        al.timestamp,
        al.rule.id,
        al.threat.technique.id,
        al.severity,
        al.source.ip,
        al.first_seen,
        al.last_seen,
        al.event_count,
        Jsonb(al.details),
    )


def _init_schema(conn: psycopg.Connection) -> None:
    conn.execute(SCHEMA_PATH.read_text())
    conn.commit()


def _run_retention(conn: psycopg.Connection) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM events WHERE ts < now() - interval '%s hours'"
            % config.EVENTS_RETENTION_HOURS
        )
    conn.commit()


def main() -> int:
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    conn = psycopg.connect(config.pg_conninfo(), autocommit=False)
    _init_schema(conn)

    consumer = make_consumer(
        config.GROUP_STORAGE,
        [config.TOPIC_NORMALIZED, config.TOPIC_ALERTS],
    )
    print("[storage] started", flush=True)

    event_rows: list[tuple] = []
    alert_rows: list[tuple] = []
    last_flush = time.monotonic()
    last_retention = time.monotonic()

    def flush() -> None:
        nonlocal last_flush
        if event_rows or alert_rows:
            with conn.cursor() as cur:
                if event_rows:
                    cur.executemany(_INSERT_EVENT, event_rows)
                if alert_rows:
                    cur.executemany(_INSERT_ALERT, alert_rows)
            conn.commit()
            # DB is durable; only now is it safe to advance Kafka offsets.
            consumer.commit(asynchronous=False)
            event_rows.clear()
            alert_rows.clear()
        last_flush = time.monotonic()

    try:
        while _running:
            msg = consumer.poll(0.2)
            if msg is not None and not msg.error():
                if msg.topic() == config.TOPIC_NORMALIZED:
                    event_rows.append(_event_row(Event.from_json(msg.value())))
                elif msg.topic() == config.TOPIC_ALERTS:
                    alert_rows.append(_alert_row(Alert.from_json(msg.value())))
            elif msg is not None and msg.error().code() != KafkaError._PARTITION_EOF:
                print(f"[storage] consume error: {msg.error()}", flush=True)

            buffered = len(event_rows) + len(alert_rows)
            due = (time.monotonic() - last_flush) >= config.STORAGE_FLUSH_SECONDS
            if buffered >= config.STORAGE_BATCH_SIZE or (buffered and due):
                flush()

            if (time.monotonic() - last_retention) >= config.RETENTION_INTERVAL_SECONDS:
                _run_retention(conn)
                last_retention = time.monotonic()
    finally:
        flush()
        consumer.close()
        conn.close()
        print("[storage] stopped", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
