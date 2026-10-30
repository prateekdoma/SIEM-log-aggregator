"""SSH parser unit cases (SPEC Testing section).

Each of the three line types parses; an unrelated sshd line returns None.
"""
from __future__ import annotations

from datetime import timezone

from normalizer.parsers.ssh import parse_ssh_line

# Real prefix from the linuxserver/openssh-server image: UTC, nanoseconds, no
# `sshd[pid]:` part.
FAILED = (
    "2026-10-29 08:55:38.274007429  "
    "Failed password for admin from 172.18.0.5 port 42240 ssh2"
)
FAILED_INVALID = (
    "2026-10-29 08:55:39.100000000  "
    "Failed password for invalid user operator from 203.0.113.9 port 51515 ssh2"
)
ACCEPTED = (
    "2026-10-29 08:55:54.555188506  "
    "Accepted password for bob from 172.18.0.5 port 34568 ssh2"
)
UNRELATED = "2026-10-29 08:55:38.276789804  Failed to set uids to 1002."


def test_failed_password_parses():
    ev = parse_ssh_line(FAILED)
    assert ev is not None
    assert ev.observer.type == "ssh"
    assert ev.event.category == "authentication"
    assert ev.event.action == "ssh_login"
    assert ev.event.outcome == "failure"
    assert ev.event.severity == 20
    assert ev.source.ip == "172.18.0.5"
    assert ev.user.name == "admin"
    assert ev.event.original == FAILED
    # Timestamp read as UTC.
    assert ev.timestamp.tzinfo == timezone.utc
    assert ev.timestamp.year == 2026 and ev.timestamp.hour == 8
    # Web-only fields stay null on an SSH event.
    assert ev.url.original is None
    assert ev.http.request.method is None
    assert ev.http.response.status_code is None
    assert ev.user_agent.original is None


def test_failed_invalid_user_parses():
    ev = parse_ssh_line(FAILED_INVALID)
    assert ev is not None
    assert ev.event.outcome == "failure"
    assert ev.event.severity == 20
    assert ev.source.ip == "203.0.113.9"
    assert ev.user.name == "operator"


def test_accepted_password_parses():
    ev = parse_ssh_line(ACCEPTED)
    assert ev is not None
    assert ev.event.outcome == "success"
    assert ev.event.severity == 0
    assert ev.source.ip == "172.18.0.5"
    assert ev.user.name == "bob"


def test_unrelated_sshd_line_returns_none():
    assert parse_ssh_line(UNRELATED) is None


def test_non_sshd_prefixless_line_returns_none():
    assert parse_ssh_line("not a log line at all") is None


def test_event_id_is_deterministic():
    assert parse_ssh_line(FAILED).event.id == parse_ssh_line(FAILED).event.id
    assert parse_ssh_line(FAILED).event.id != parse_ssh_line(ACCEPTED).event.id
