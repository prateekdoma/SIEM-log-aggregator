"""Helpers for detection unit tests: build Events with chosen timestamps and
run them through the rules exactly as the engine does.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from common.schema import Event, EventFields, Observer, Source, User
from detector.rules import RULES
from detector.state import StateStore

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def at(seconds: float) -> datetime:
    """A timestamp `seconds` after the fixed base T0."""
    return T0 + timedelta(seconds=seconds)


def ssh_event(
    ts: datetime,
    *,
    ip: str = "198.51.100.7",
    user: str | None = "admin",
    outcome: str = "failure",
) -> Event:
    severity = 20 if outcome == "failure" else 0
    return Event(
        timestamp=ts,
        event=EventFields(
            id=uuid.uuid4(),
            category="authentication",
            action="ssh_login",
            outcome=outcome,
            severity=severity,
            original=f"{ts:%Y-%m-%d %H:%M:%S.%f}  {outcome} for {user} from {ip}",
        ),
        source=Source(ip=ip),
        observer=Observer(type="ssh"),
        user=User(name=user),
    )


def run(events, rules=RULES):
    """Feed events through all rules with per-IP state, like the engine."""
    store = StateStore()
    alerts = []
    for ev in events:
        st = store.get(ev.source.ip, ev.timestamp)
        for rule in rules:
            if rule.applies(ev):
                alerts.extend(rule.evaluate(ev, st))
    return alerts


def techniques(alerts) -> list[str]:
    return [a.threat.technique.id for a in alerts]
