"""Per-IP detection state.

One `IpState` per source IP holds:
  * a sliding deque of (timestamp, username) for SSH failure events,
  * per-(rule, technique) cooldown timestamps,
  * named flags with the time they were set (e.g. `bruteforce_seen`).

Every "now" is the current event's `@timestamp` — never the wall clock
(CLAUDE.md hard rule 2). `StateStore` creates state on first sight of an IP and
evicts IPs idle longer than EVICT_IDLE_S, measured in event time, so memory
stays flat without a background thread.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta

from common import config

# Keep failures only as long as the widest window that reads them needs.
_PRUNE_WINDOW_S = max(config.BF_WINDOW_S, config.SPRAY_WINDOW_S)


class IpState:
    def __init__(self) -> None:
        # (timestamp, username) for each SSH failure, oldest first.
        self._failures: deque[tuple[datetime, str | None]] = deque()
        # (rule_id, technique) -> time the alert last fired for this IP.
        self._cooldowns: dict[tuple[str, str], datetime] = {}
        # flag name -> time it was set.
        self._flags: dict[str, datetime] = {}
        self.last_seen: datetime | None = None

    # --- bookkeeping -------------------------------------------------------
    def touch(self, now: datetime) -> None:
        """Advance last_seen for eviction (called for every event)."""
        if self.last_seen is None or now > self.last_seen:
            self.last_seen = now

    def record_failure(self, now: datetime, username: str | None) -> None:
        """Add a failure and drop ones older than the widest window."""
        self._failures.append((now, username))
        cutoff = now - timedelta(seconds=_PRUNE_WINDOW_S)
        while self._failures and self._failures[0][0] < cutoff:
            self._failures.popleft()

    # --- windows over failures --------------------------------------------
    def user_failure_times(
        self, username: str | None, seconds: int, now: datetime
    ) -> list[datetime]:
        """Failure timestamps for one username within `seconds` of now."""
        cutoff = now - timedelta(seconds=seconds)
        return [ts for ts, user in self._failures if user == username and ts >= cutoff]

    def failures_within(
        self, seconds: int, now: datetime
    ) -> list[tuple[datetime, str | None]]:
        """All (ts, username) failures within `seconds` of now."""
        cutoff = now - timedelta(seconds=seconds)
        return [(ts, user) for ts, user in self._failures if ts >= cutoff]

    # --- flags -------------------------------------------------------------
    def mark(self, name: str, now: datetime) -> None:
        self._flags[name] = now

    def seen_within(self, name: str, seconds: int, now: datetime) -> bool:
        set_at = self._flags.get(name)
        return set_at is not None and set_at >= now - timedelta(seconds=seconds)

    # --- cooldowns ---------------------------------------------------------
    def cooldown_active(
        self, key: tuple[str, str], seconds: int, now: datetime
    ) -> bool:
        fired_at = self._cooldowns.get(key)
        return fired_at is not None and fired_at > now - timedelta(seconds=seconds)

    def set_cooldown(self, key: tuple[str, str], now: datetime) -> None:
        self._cooldowns[key] = now


class StateStore:
    """IP -> IpState, with event-time eviction of idle IPs."""

    # How often (in events) to sweep for idle IPs; cheap and bounded.
    _EVICT_EVERY = 1000

    def __init__(self, idle_seconds: int = config.EVICT_IDLE_S) -> None:
        self._states: dict[str, IpState] = {}
        self._idle_seconds = idle_seconds
        self._since_sweep = 0

    def get(self, ip: str, now: datetime) -> IpState:
        state = self._states.get(ip)
        if state is None:
            state = IpState()
            self._states[ip] = state
        state.touch(now)
        return state

    def maybe_evict(self, now: datetime) -> None:
        self._since_sweep += 1
        if self._since_sweep < self._EVICT_EVERY:
            return
        self._since_sweep = 0
        self.evict(now)

    def evict(self, now: datetime) -> int:
        cutoff = now - timedelta(seconds=self._idle_seconds)
        stale = [
            ip
            for ip, st in self._states.items()
            if st.last_seen is not None and st.last_seen < cutoff
        ]
        for ip in stale:
            del self._states[ip]
        return len(stale)

    def __len__(self) -> int:
        return len(self._states)
