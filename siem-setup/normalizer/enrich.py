"""Threat-intel tagging for normalized events.

Block 2 scope: every event is tagged `unknown` (the schema default), severity
unchanged. The real OTX IPv4 lookup (load the cached set, tag `known_bad` and
add 20 to severity) is added in block 4; it plugs in here without touching the
normalizer loop or the parsers.
"""
from __future__ import annotations

from common.schema import Event


def tag(event: Event) -> Event:
    """Set threat.indicator.status. Block 2: always `unknown`."""
    event.threat.indicator.status = "unknown"
    return event
