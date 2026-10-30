"""T1078 Valid Accounts unit cases (SPEC Testing section)."""
from __future__ import annotations

from tests.unit.factories import at, run, ssh_event, techniques


def test_bruteforce_then_success_same_ip_t1078():
    events = [ssh_event(at(i * 2), ip="203.0.113.9", user="admin") for i in range(10)]
    events.append(ssh_event(at(60), ip="203.0.113.9", user="admin", outcome="success"))
    techs = techniques(run(events))
    assert "T1110.001" in techs
    assert "T1078" in techs
    t1078 = [a for a in run(events) if a.threat.technique.id == "T1078"][0]
    assert t1078.severity == 80


def test_success_from_other_ip_no_t1078():
    # Brute force on one IP; the success comes from a different IP.
    events = [ssh_event(at(i * 2), ip="203.0.113.9", user="admin") for i in range(10)]
    events.append(ssh_event(at(60), ip="203.0.113.99", user="admin", outcome="success"))
    assert "T1078" not in techniques(run(events))


def test_success_with_no_prior_failures_none():
    events = [ssh_event(at(0), user="admin", outcome="success")]
    assert run(events) == []


def test_one_typo_then_success_none():
    # C1 control: a single failure never sets bruteforce_seen.
    events = [
        ssh_event(at(0), user="admin", outcome="failure"),
        ssh_event(at(2), user="admin", outcome="success"),
    ]
    assert run(events) == []


def test_success_after_lookback_window_no_t1078():
    # Brute force fires, but the success comes > VALID_LOOKBACK_S (600s) later.
    events = [ssh_event(at(i * 2), ip="203.0.113.9", user="admin") for i in range(10)]
    events.append(ssh_event(at(700), ip="203.0.113.9", user="admin", outcome="success"))
    assert "T1078" not in techniques(run(events))
