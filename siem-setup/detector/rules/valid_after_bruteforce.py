"""ssh-valid-after-bruteforce: T1078 Valid Accounts.

Fires when an SSH login SUCCEEDS from an IP whose `bruteforce_seen` flag was set
within the last VALID_LOOKBACK_S seconds — i.e. a guessing/spraying run against
that IP was followed by a successful login. This rule only READS the flag;
ssh-bruteforce is what sets it.
"""
from __future__ import annotations

from common import config
from common.schema import Alert, Event
from detector.rules.base import build_alert
from detector.state import IpState

RULE_ID = "ssh-valid-after-bruteforce"
SEVERITY = 80
TECHNIQUE = "T1078"


class SshValidAfterBruteForce:
    id = RULE_ID
    severity = SEVERITY

    def applies(self, ev: Event) -> bool:
        return ev.observer.type == "ssh" and ev.event.outcome == "success"

    def evaluate(self, ev: Event, st: IpState) -> list[Alert]:
        now = ev.timestamp
        if not st.seen_within("bruteforce_seen", config.VALID_LOOKBACK_S, now):
            return []

        key = (RULE_ID, TECHNIQUE)
        if st.cooldown_active(key, config.COOLDOWN_S, now):
            return []
        st.set_cooldown(key, now)

        user = ev.user.name
        return [
            build_alert(
                rule_id=RULE_ID,
                technique=TECHNIQUE,
                severity=SEVERITY,
                source_ip=ev.source.ip,
                timestamp=now,
                first_seen=now,
                last_seen=now,
                event_count=1,
                usernames=[user],
                otx_status=ev.threat.indicator.status,
                reason=f"successful SSH login for '{user}' after recent brute force",
            )
        ]
