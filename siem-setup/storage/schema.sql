-- Postgres schema for the SIEM pipeline. Idempotent (IF NOT EXISTS) so the
-- storage-writer can run it on every start.

CREATE TABLE IF NOT EXISTS events (
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
CREATE INDEX IF NOT EXISTS events_ts_idx ON events (ts DESC);
CREATE INDEX IF NOT EXISTS events_ip_ts_idx ON events (source_ip, ts DESC);

CREATE TABLE IF NOT EXISTS alerts (
  id          BIGSERIAL PRIMARY KEY,
  alert_id    UUID UNIQUE,
  ts          TIMESTAMPTZ NOT NULL,
  rule_id     TEXT, technique TEXT, severity SMALLINT,
  source_ip   INET,
  first_seen  TIMESTAMPTZ, last_seen TIMESTAMPTZ,
  event_count INT,
  details     JSONB
);
CREATE INDEX IF NOT EXISTS alerts_ts_idx ON alerts (ts DESC);
