"""Threat-intel tagging for normalized events (OTX, block 4).

Loads the OTX IPv4 set from a local JSON file (written in bulk by intel-updater)
and tags each event in memory — there is NO per-event or per-IP OTX call
(CLAUDE.md hard rule 6). The file is reloaded when its modification time changes.

  * `known_bad` when source.ip is in the set; add 20 to event.severity.
  * `unknown` otherwise (every private lab IP included). Not on the list means
    not known, not safe.

No key / no file / empty set: everything is tagged `unknown` and the pipeline
never blocks. The file is intentionally ephemeral (pulled on demand, deleted on
shutdown — see the project note), so "file missing" is a normal state.
"""
from __future__ import annotations

import json
import os

from common import config
from common.schema import Event

KNOWN_BAD_SEVERITY_BONUS = 20


class OtxTagger:
    def __init__(self, path: str = config.OTX_FILE) -> None:
        self.path = path
        self.ips: set[str] = set()
        self._mtime: float | None = None
        self.reload_if_changed()

    def reload_if_changed(self) -> None:
        """Reload the IP set if the file appeared, changed, or disappeared."""
        try:
            mtime = os.stat(self.path).st_mtime
        except OSError:
            if self.ips or self._mtime is not None:
                print(
                    f"[enrich] OTX file {self.path} gone; tagging all 'unknown'",
                    flush=True,
                )
            self.ips = set()
            self._mtime = None
            return

        if mtime == self._mtime:
            return
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                self.ips = set(json.load(handle))
            self._mtime = mtime
            print(f"[enrich] loaded {len(self.ips)} OTX IPv4 indicators", flush=True)
        except (OSError, ValueError) as exc:
            print(f"[enrich] failed to load OTX file: {exc}; keeping prior set", flush=True)

    def tag(self, event: Event) -> Event:
        self.reload_if_changed()
        if event.source.ip in self.ips:
            event.threat.indicator.status = "known_bad"
            event.event.severity = min(100, event.event.severity + KNOWN_BAD_SEVERITY_BONUS)
        else:
            event.threat.indicator.status = "unknown"
        return event
