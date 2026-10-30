"""Alert-severity adjustments: known_bad bonus (+20, cap 100) and the
successful-access floor (>= 80)."""
from __future__ import annotations

from tests.unit.factories import at, run, ssh_event


def _alert(alerts, technique):
    return next(a for a in alerts if a.threat.technique.id == technique)


def test_t1110_unknown_stays_50():
    events = [ssh_event(at(i * 2), user="admin") for i in range(10)]
    assert _alert(run(events), "T1110.001").severity == 50


def test_t1110_known_bad_bumped_to_70():
    events = [ssh_event(at(i * 2), ip="203.0.113.9", user="admin", otx="known_bad") for i in range(10)]
    assert _alert(run(events), "T1110.001").severity == 70


def test_t1078_unknown_floored_at_80():
    events = [ssh_event(at(i * 2), ip="203.0.113.9", user="admin") for i in range(10)]
    events.append(ssh_event(at(40), ip="203.0.113.9", user="admin", outcome="success"))
    assert _alert(run(events), "T1078").severity == 80


def test_t1078_known_bad_is_critical_100():
    events = [ssh_event(at(i * 2), ip="203.0.113.9", user="admin", otx="known_bad") for i in range(10)]
    events.append(
        ssh_event(at(40), ip="203.0.113.9", user="admin", outcome="success", otx="known_bad")
    )
    assert _alert(run(events), "T1078").severity == 100
