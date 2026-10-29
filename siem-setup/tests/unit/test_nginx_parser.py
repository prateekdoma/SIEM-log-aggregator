"""Nginx parser unit cases (SPEC Testing section).

A combined-format line maps to every web field in the schema.
"""
from __future__ import annotations

from datetime import timezone

from normalizer.parsers.nginx import parse_nginx_line

COMBINED = (
    '172.18.0.5 - - [29/Oct/2026:09:01:37 +0000] '
    '"GET /vulnerabilities/sqli/?id=1 HTTP/1.1" 200 1754 '
    '"-" "Mozilla/5.0 (X11; Linux x86_64) Chrome/129.0.0.0 Safari/537.36"'
)
# A line whose local time carries a non-UTC offset, to check conversion.
COMBINED_OFFSET = (
    '10.0.0.9 - - [29/Oct/2026:12:00:00 +0200] '
    '"POST /login.php HTTP/1.1" 403 12 "-" "curl/8.4.0"'
)


def test_combined_line_maps_every_web_field():
    ev = parse_nginx_line(COMBINED)
    assert ev is not None
    assert ev.observer.type == "nginx"
    assert ev.event.category == "web"
    assert ev.event.action == "http_request"
    assert ev.event.outcome == "success"      # status < 400
    assert ev.event.severity == 0
    assert ev.source.ip == "172.18.0.5"
    assert ev.url.original == "/vulnerabilities/sqli/?id=1"
    assert ev.http.request.method == "GET"
    assert ev.http.response.status_code == 200
    assert ev.user_agent.original.startswith("Mozilla/5.0")
    assert ev.event.original == COMBINED
    # SSH-only field stays null on a web event.
    assert ev.user.name is None
    # Timestamp in UTC.
    assert ev.timestamp.tzinfo == timezone.utc
    assert ev.timestamp.hour == 9


def test_non_2xx_is_failure_and_offset_converts_to_utc():
    ev = parse_nginx_line(COMBINED_OFFSET)
    assert ev is not None
    assert ev.event.outcome == "failure"      # 403 >= 400
    assert ev.http.response.status_code == 403
    assert ev.http.request.method == "POST"
    # 12:00 +0200 -> 10:00 UTC
    assert ev.timestamp.hour == 10


def test_malformed_line_returns_none():
    assert parse_nginx_line("this is not a combined log line") is None
