"""FastAPI: REST over Postgres + a WebSocket live feed off Kafka.

Endpoints (SPEC "API"):
  GET  /alerts?since=&limit=50          newest alerts first (Postgres alerts)
  GET  /events?ip=&since=&limit=100     events for one IP, newest first
  GET  /stats                           last-hour counts by severity band + technique
  WS   /live                            each new alert as it arrives
  GET  /health                          200 once Postgres and Kafka are reachable

/live uses ONE background Kafka consumer (group `api`, auto.offset.reset=latest)
that fans every alert out to all connected WebSocket clients, so every viewer
sees every alert (a per-client consumer in one group would split partitions).
"""
from __future__ import annotations

import asyncio
import threading
from contextlib import asynccontextmanager
from datetime import datetime

from confluent_kafka import KafkaError
from confluent_kafka.admin import AdminClient
from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from common import config
from common.kafka import make_consumer

# Severity bands for /stats (SPEC leaves the cutoffs to us).
SEVERITY_BANDS = {
    "low": (0, 29),
    "medium": (30, 49),
    "high": (50, 79),
    "critical": (80, 100),
}

pool = ConnectionPool(config.pg_conninfo(), min_size=1, max_size=5, open=False)


class LiveHub:
    """Fan-out of alert JSON from the Kafka thread to WebSocket clients."""

    def __init__(self) -> None:
        self.clients: set[asyncio.Queue] = set()
        self.loop: asyncio.AbstractEventLoop | None = None

    def register(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self.clients.add(queue)
        return queue

    def unregister(self, queue: asyncio.Queue) -> None:
        self.clients.discard(queue)

    def publish_threadsafe(self, message: str) -> None:
        if self.loop is None:
            return
        for queue in list(self.clients):
            self.loop.call_soon_threadsafe(self._offer, queue, message)

    @staticmethod
    def _offer(queue: asyncio.Queue, message: str) -> None:
        try:
            queue.put_nowait(message)
        except asyncio.QueueFull:
            pass  # a slow client never backs up the shared consumer


hub = LiveHub()


def _kafka_loop(stop: threading.Event) -> None:
    consumer = make_consumer(config.GROUP_API, [config.TOPIC_ALERTS], offset_reset="latest")
    try:
        while not stop.is_set():
            msg = consumer.poll(0.5)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    print(f"[api] live consume error: {msg.error()}", flush=True)
                continue
            hub.publish_threadsafe(msg.value().decode("utf-8", errors="replace"))
    finally:
        consumer.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    hub.loop = asyncio.get_running_loop()
    pool.open()
    stop = threading.Event()
    thread = threading.Thread(target=_kafka_loop, args=(stop,), daemon=True)
    thread.start()
    print("[api] started", flush=True)
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=5)
        pool.close()
        print("[api] stopped", flush=True)


app = FastAPI(title="SIEM Log Aggregator API", lifespan=lifespan)


def _rows(sql: str, params: list) -> list[dict]:
    with pool.connection() as conn:
        conn.row_factory = dict_row
        return conn.execute(sql, params).fetchall()


@app.get("/health")
def health():
    ok_db = ok_kafka = False
    try:
        with pool.connection() as conn:
            conn.execute("SELECT 1")
        ok_db = True
    except Exception:
        pass
    try:
        AdminClient({"bootstrap.servers": config.KAFKA_BOOTSTRAP}).list_topics(timeout=5)
        ok_kafka = True
    except Exception:
        pass
    healthy = ok_db and ok_kafka
    return JSONResponse(
        {"status": "ok" if healthy else "degraded", "postgres": ok_db, "kafka": ok_kafka},
        status_code=200 if healthy else 503,
    )


@app.get("/alerts")
def get_alerts(since: datetime | None = None, limit: int = Query(50, ge=1, le=500)):
    sql = (
        "SELECT alert_id, ts, rule_id, technique, severity, host(source_ip) AS source_ip, "
        "first_seen, last_seen, event_count, details FROM alerts"
    )
    params: list = []
    if since is not None:
        sql += " WHERE ts >= %s"
        params.append(since)
    sql += " ORDER BY ts DESC LIMIT %s"
    params.append(limit)
    return _rows(sql, params)


@app.get("/events")
def get_events(
    ip: str | None = None,
    since: datetime | None = None,
    limit: int = Query(100, ge=1, le=1000),
):
    sql = (
        "SELECT event_id, ts, host(source_ip) AS source_ip, category, action, outcome, "
        "user_name, url, status_code, severity, intel_status FROM events"
    )
    conds: list[str] = []
    params: list = []
    if ip:
        conds.append("source_ip = %s")
        params.append(ip)
    if since is not None:
        conds.append("ts >= %s")
        params.append(since)
    if conds:
        sql += " WHERE " + " AND ".join(conds)
    sql += " ORDER BY ts DESC LIMIT %s"
    params.append(limit)
    return _rows(sql, params)


@app.get("/stats")
def stats():
    band_cols = ", ".join(
        f"count(*) FILTER (WHERE severity BETWEEN {lo} AND {hi}) AS {name}"
        for name, (lo, hi) in SEVERITY_BANDS.items()
    )
    with pool.connection() as conn:
        conn.row_factory = dict_row
        events = conn.execute(
            f"SELECT count(*) AS total, {band_cols} FROM events "
            "WHERE ts >= now() - interval '1 hour'"
        ).fetchone()
        alerts_total = conn.execute(
            "SELECT count(*) AS total FROM alerts WHERE ts >= now() - interval '1 hour'"
        ).fetchone()["total"]
        by_technique = conn.execute(
            "SELECT technique, count(*) AS count FROM alerts "
            "WHERE ts >= now() - interval '1 hour' GROUP BY technique ORDER BY count DESC"
        ).fetchall()
    return {
        "window": "1h",
        "events": {
            "total": events["total"],
            "by_severity": {name: events[name] for name in SEVERITY_BANDS},
        },
        "alerts": {
            "total": alerts_total,
            "by_technique": {row["technique"]: row["count"] for row in by_technique},
        },
    }


@app.websocket("/live")
async def live(websocket: WebSocket):
    await websocket.accept()
    queue = hub.register()
    try:
        while True:
            message = await queue.get()
            await websocket.send_text(message)
    except WebSocketDisconnect:
        pass
    finally:
        hub.unregister(queue)
