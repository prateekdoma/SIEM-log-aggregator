"""Parse nginx combined-format access log lines into Events.

Combined format:
    $remote_addr - $remote_user [$time_local] "$request" $status
    $body_bytes_sent "$http_referer" "$http_user_agent"

e.g.
    172.18.0.5 - - [29/Oct/2026:09:01:37 +0000] "GET /setup.php HTTP/1.1" 200 1754 "-" "Mozilla/5.0 ..."

The $time_local field carries its own offset; it is converted to UTC. A line that
does not match the format returns None (ignored, not an error).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from common.schema import (
    Event,
    EventFields,
    Http,
    HttpRequest,
    HttpResponse,
    Observer,
    Source,
    Url,
    UserAgent,
    make_event_id,
)

OBSERVER_TYPE = "nginx"

_COMBINED_RE = re.compile(
    r"^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "
    r'"(?P<method>\S+) (?P<path>\S+) (?P<proto>[^"]*)" '
    r"(?P<status>\d{3}) (?P<size>\S+) "
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


def _dash_to_none(value: str) -> str | None:
    return None if value == "-" else value


def parse_nginx_line(raw: str) -> Event | None:
    """Return an Event for a combined-format line, or None if it doesn't match."""
    raw = raw.rstrip("\n")
    match = _COMBINED_RE.match(raw)
    if not match:
        return None

    timestamp = datetime.strptime(match.group("time"), _TIME_FMT).astimezone(
        timezone.utc
    )
    status = int(match.group("status"))
    outcome = "success" if status < 400 else "failure"

    return Event(
        timestamp=timestamp,
        event=EventFields(
            id=make_event_id(OBSERVER_TYPE, raw),
            category="web",
            action="http_request",
            outcome=outcome,
            severity=0,
            original=raw,
        ),
        source=Source(ip=match.group("ip")),
        observer=Observer(type=OBSERVER_TYPE),
        url=Url(original=match.group("path")),
        http=Http(
            request=HttpRequest(method=match.group("method")),
            response=HttpResponse(status_code=status),
        ),
        user_agent=UserAgent(original=_dash_to_none(match.group("ua"))),
    )
