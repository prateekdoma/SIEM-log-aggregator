"""ssh-bruteforce: T1110.001 Password Guessing and T1110.003 Password Spraying.

One rule, two techniques, each with its own cooldown so an IP doing both raises
one of each (SPEC "Detection engine"):

  * T1110.001 fires on >= BF_FAIL_COUNT failures against the SAME
    (source.ip, user.name) within BF_WINDOW_S seconds.
  * T1110.003 fires on failures against >= SPRAY_USERS distinct user.name from
    one IP within SPRAY_WINDOW_S seconds.

Either firing sets the `bruteforce_seen` flag, which ssh-valid-after-bruteforce
reads. All times come from the event's @timestamp via IpState.
"""
from __future__ import annotations

from common import config
from common.schema import Alert, Event
from detector.rules.base import build_alert
from detector.state import IpState

RULE_ID = "ssh-bruteforce"
SEVERITY = 50
TECH_GUESSING = "T1110.001"
TECH_SPRAYING = "T1110.003"


class SshBruteForce:
    id = RULE_ID
    severity = SEVERITY

    def applies(self, ev: Event) -> bool:
        return ev.observer.type == "ssh" and ev.event.outcome == "failure"

    def evaluate(self, ev: Event, st: IpState) -> list[Alert]:
        now = ev.timestamp
        user = ev.user.name
        st.record_failure(now, user)

        alerts: list[Alert] = []

        # --- T1110.001: repeated failures against one username --------------
        user_fail_times = st.user_failure_times(user, config.BF_WINDOW_S, now)
        if len(user_fail_times) >= config.BF_FAIL_COUNT:
            key = (RULE_ID, TECH_GUESSING)
            if not st.cooldown_active(key, config.COOLDOWN_S, now):
                st.set_cooldown(key, now)
                st.mark("bruteforce_seen", now)
                span = int((max(user_fail_times) - min(user_fail_times)).total_seconds())
                alerts.append(
                    build_alert(
                        rule_id=RULE_ID,
                        technique=TECH_GUESSING,
                        severity=SEVERITY,
                        source_ip=ev.source.ip,
                        timestamp=now,
                        first_seen=min(user_fail_times),
                        last_seen=max(user_fail_times),
                        event_count=len(user_fail_times),
                        usernames=[user],
                        otx_status=ev.threat.indicator.status,
                        reason=(
                            f"{len(user_fail_times)} failed SSH logins for "
                            f"'{user}' within {span}s"
                        ),
                    )
                )

        # --- T1110.003: failures spread across many usernames ---------------
        window_fails = st.failures_within(config.SPRAY_WINDOW_S, now)
        distinct_users = {u for _, u in window_fails}
        if len(distinct_users) >= config.SPRAY_USERS:
            key = (RULE_ID, TECH_SPRAYING)
            if not st.cooldown_active(key, config.COOLDOWN_S, now):
                st.set_cooldown(key, now)
                st.mark("bruteforce_seen", now)
                times = [ts for ts, _ in window_fails]
                span = int((max(times) - min(times)).total_seconds())
                alerts.append(
                    build_alert(
                        rule_id=RULE_ID,
                        technique=TECH_SPRAYING,
                        severity=SEVERITY,
                        source_ip=ev.source.ip,
                        timestamp=now,
                        first_seen=min(times),
                        last_seen=max(times),
                        event_count=len(window_fails),
                        usernames=sorted(u for u in distinct_users if u is not None),
                        otx_status=ev.threat.indicator.status,
                        reason=(
                            f"SSH failures against {len(distinct_users)} distinct "
                            f"users within {span}s"
                        ),
                    )
                )

        return alerts
