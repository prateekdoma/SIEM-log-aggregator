"""Rule plugin contract and a shared alert builder.

A rule is any object with `id`, `severity`, `applies(ev)` and
`evaluate(ev, st)`. The engine offers every event to every rule in
`detector.rules.RULES`; adding a detection is one new class plus one line in
`__init__.py`, with the engine and other rules untouched.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Protocol

from common.schema import (
    Alert,
    AlertRef,
    RuleRef,
    Source,
    TechniqueRef,
    ThreatTechnique,
)
from detector.state import IpState


class Rule(Protocol):
    id: str
    severity: int

    def applies(self, ev) -> bool: ...                 # cheap filter
    def evaluate(self, ev, st: IpState) -> list[Alert]: ...   # 0..n alerts


def build_alert(
    *,
    rule_id: str,
    technique: str,
    severity: int,
    source_ip: str,
    timestamp: datetime,
    first_seen: datetime,
    last_seen: datetime,
    event_count: int,
    usernames: list[str | None],
    otx_status: str,
    reason: str,
) -> Alert:
    return Alert(
        timestamp=timestamp,
        alert=AlertRef(id=uuid.uuid4()),
        rule=RuleRef(id=rule_id),
        threat=ThreatTechnique(technique=TechniqueRef(id=technique)),
        severity=severity,
        source=Source(ip=source_ip),
        first_seen=first_seen,
        last_seen=last_seen,
        event_count=event_count,
        details={
            "usernames": usernames,
            "otx_status": otx_status,
            "reason": reason,
        },
    )
