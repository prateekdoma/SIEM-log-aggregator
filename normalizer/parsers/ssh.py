"""Parse sshd log lines from the linuxserver/openssh-server image into Events.

Each line is prefixed with a timezone-less, `sshd[pid]:`-less timestamp written
by the image's s6 logger, e.g.

    2026-10-29 08:55:38.274007429  Accepted password for bob from 172.18.0.5 port 42240 ssh2

`target-ssh` runs with TZ=Etc/UTC, so that prefix is read as UTC (SPEC "Timestamps
are UTC"). The three auth lines below are parsed; any other sshd line returns None
(ignored, not an error — no dead-letter in the core build).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from common.schema import (
    Event,
    EventFields,
    Observer,
    Source,
    User,
    make_event_id,
)

OBSERVER_TYPE = "ssh"
SEVERITY_FAILURE = 20
SEVERITY_SUCCESS = 0

# Leading "YYYY-MM-DD HH:MM:SS.fffffffff" prefix, then the sshd message.
_PREFIX_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(?P<msg>.*)$"
)

# Order matters: the "invalid user" variant is checked before the plain one.
_FAILED_INVALID_RE = re.compile(
    r"^Failed password for invalid user (?P<user>\S+) from (?P<ip>\S+) port \d+ ssh2"
)
_FAILED_RE = re.compile(
    r"^Failed password for (?P<user>\S+) from (?P<ip>\S+) port \d+ ssh2"
)
_ACCEPTED_RE = re.compile(
    r"^Accepted password for (?P<user>\S+) from (?P<ip>\S+) port \d+ ssh2"
)


def _parse_prefix_ts(ts: str) -> datetime:
    """Parse the log prefix timestamp as UTC. Nanoseconds are truncated to micros."""
    if "." in ts:
        date_part, frac = ts.split(".", 1)
        frac = (frac[:6]).ljust(6, "0")          # datetime handles at most microseconds
        dt = datetime.strptime(f"{date_part}.{frac}", "%Y-%m-%d %H:%M:%S.%f")
    else:
        dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    return dt.replace(tzinfo=timezone.utc)


def parse_ssh_line(raw: str) -> Event | None:
    """Return an Event for an auth line, or None for anything else."""
    raw = raw.rstrip("\n")
    prefix = _PREFIX_RE.match(raw)
    if not prefix:
        return None
    timestamp = _parse_prefix_ts(prefix.group("ts"))
    message = prefix.group("msg")

    outcome: str
    for pattern, line_outcome in (
        (_FAILED_INVALID_RE, "failure"),
        (_FAILED_RE, "failure"),
        (_ACCEPTED_RE, "success"),
    ):
        match = pattern.match(message)
        if match:
            outcome = line_outcome
            break
    else:
        return None

    severity = SEVERITY_FAILURE if outcome == "failure" else SEVERITY_SUCCESS
    return Event(
        timestamp=timestamp,
        event=EventFields(
            id=make_event_id(OBSERVER_TYPE, raw),
            category="authentication",
            action="ssh_login",
            outcome=outcome,
            severity=severity,
            original=raw,
        ),
        source=Source(ip=match.group("ip")),
        observer=Observer(type=OBSERVER_TYPE),
        user=User(name=match.group("user")),
    )
