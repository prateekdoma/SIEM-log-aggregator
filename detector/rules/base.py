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

from common import config
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


def adjust_severity(base: int, otx_status: str, success_access: bool) -> int:
    """Floor successful-access alerts at SUCCESS_ACCESS_MIN_SEVERITY, then add the
    known_bad bonus (capped at 100)."""
    severity = base
    if success_access:
        severity = max(severity, config.SUCCESS_ACCESS_MIN_SEVERITY)
    if otx_status == "known_bad":
        severity = min(100, severity + config.KNOWN_BAD_ALERT_BONUS)
    return severity


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
    success_access: bool = False,
) -> Alert:
    return Alert(
        timestamp=timestamp,
        alert=AlertRef(id=uuid.uuid4()),
        rule=RuleRef(id=rule_id),
        threat=ThreatTechnique(technique=TechniqueRef(id=technique)),
        severity=adjust_severity(severity, otx_status, success_access),
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
