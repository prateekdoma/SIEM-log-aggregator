"""Central config: topic names, consumer groups, and env-var settings.

Defaults match SPEC.md so the services run with the committed `.env.example`.
Detection thresholds live here too so block 3 reads them from one place.
"""
from __future__ import annotations

import os

# --- Kafka ----------------------------------------------------------------
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka:9092")

TOPIC_SYSLOG_RAW = "syslog-raw"
TOPIC_WEB_LOGS_RAW = "web-logs-raw"
TOPIC_NORMALIZED = "normalized-security-events"
TOPIC_ALERTS = "security-alerts"

ALL_TOPICS = [
    TOPIC_SYSLOG_RAW,
    TOPIC_WEB_LOGS_RAW,
    TOPIC_NORMALIZED,
    TOPIC_ALERTS,
]
TOPIC_PARTITIONS = 3
TOPIC_REPLICATION = 1

# Consumer groups (SPEC Architecture table).
GROUP_NORMALIZERS = "normalizers"
GROUP_DETECTORS = "detectors"
GROUP_STORAGE = "storage"
GROUP_API = "api"

# --- Postgres -------------------------------------------------------------
PG_HOST = os.getenv("PG_HOST", "postgres")
PG_PORT = int(os.getenv("PG_PORT", "5432"))
PG_DB = os.getenv("POSTGRES_DB", "siem")
PG_USER = os.getenv("POSTGRES_USER", "siem")
PG_PASSWORD = os.getenv("POSTGRES_PASSWORD", "siem")


def pg_conninfo() -> str:
    return (
        f"host={PG_HOST} port={PG_PORT} dbname={PG_DB} "
        f"user={PG_USER} password={PG_PASSWORD}"
    )


# --- Storage batching / retention -----------------------------------------
STORAGE_BATCH_SIZE = int(os.getenv("STORAGE_BATCH_SIZE", "500"))
STORAGE_FLUSH_SECONDS = float(os.getenv("STORAGE_FLUSH_SECONDS", "1"))
EVENTS_RETENTION_HOURS = int(os.getenv("EVENTS_RETENTION_HOURS", "24"))
RETENTION_INTERVAL_SECONDS = int(os.getenv("RETENTION_INTERVAL_SECONDS", str(10 * 60)))

# --- OTX (used from block 4) ----------------------------------------------
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
OTX_FILE = os.getenv("OTX_FILE", "/data/intel/otx_ipv4.json")
OTX_MAX_IPS = int(os.getenv("OTX_MAX_IPS", "100000"))
OTX_LOOKBACK_DAYS = int(os.getenv("OTX_LOOKBACK_DAYS", "30"))
OTX_REFRESH_S = int(os.getenv("OTX_REFRESH_S", str(6 * 3600)))

# --- Detection thresholds (used from block 3) -----------------------------
BF_FAIL_COUNT = int(os.getenv("BF_FAIL_COUNT", "10"))
BF_WINDOW_S = int(os.getenv("BF_WINDOW_S", "60"))
SPRAY_USERS = int(os.getenv("SPRAY_USERS", "5"))
SPRAY_WINDOW_S = int(os.getenv("SPRAY_WINDOW_S", "300"))
VALID_LOOKBACK_S = int(os.getenv("VALID_LOOKBACK_S", "600"))
COOLDOWN_S = int(os.getenv("COOLDOWN_S", "300"))
# Evict an IP's in-memory state after this many seconds idle (by event time).
EVICT_IDLE_S = int(os.getenv("EVICT_IDLE_S", "1800"))
