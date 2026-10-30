"""T1110.001 / T1110.003 unit cases (SPEC Testing section, as revised)."""
from __future__ import annotations

from tests.unit.factories import at, run, ssh_event, techniques


def test_ten_failures_same_user_within_59s_one_alert():
    events = [ssh_event(at(i * 6), user="admin") for i in range(10)]  # 0..54s
    alerts = run(events)
    assert techniques(alerts) == ["T1110.001"]
    assert alerts[0].severity == 50
    assert alerts[0].event_count == 10
    assert alerts[0].details["usernames"] == ["admin"]


def test_nine_failures_no_alert():
    events = [ssh_event(at(i * 6), user="admin") for i in range(9)]
    assert run(events) == []


def test_failures_spread_over_5min_no_alert():
    # One failure every 40s: never 10 within a 60s window (C2 blind spot).
    events = [ssh_event(at(i * 40), user="admin") for i in range(10)]
    assert run(events) == []


def test_25_failures_in_a_row_still_one_alert_cooldown():
    events = [ssh_event(at(i * 2), user="admin") for i in range(25)]  # 0..48s
    assert techniques(run(events)) == ["T1110.001"]


def test_five_distinct_users_within_5min_spray():
    events = [ssh_event(at(i * 10), user=f"u{i}") for i in range(5)]  # 0..40s
    alerts = run(events)
    assert techniques(alerts) == ["T1110.003"]
    assert alerts[0].severity == 50
    assert sorted(alerts[0].details["usernames"]) == ["u0", "u1", "u2", "u3", "u4"]


def test_twelve_failures_twelve_users_only_spraying():
    # 12 different users, one failure each: spray fires, guessing does not.
    events = [ssh_event(at(i * 3), user=f"user{i}") for i in range(12)]
    assert techniques(run(events)) == ["T1110.003"]


def test_ten_failures_one_user_only_guessing():
    events = [ssh_event(at(i * 5), user="admin") for i in range(10)]  # 0..45s
    assert techniques(run(events)) == ["T1110.001"]


def test_one_ip_doing_both_one_alert_of_each():
    # 10 failures vs admin (guessing) then 5 more distinct users (spraying).
    events = [ssh_event(at(i * 2), user="admin") for i in range(10)]  # 0..18s
    events += [ssh_event(at(20 + i * 3), user=f"spray{i}") for i in range(5)]  # 20..32s
    techs = techniques(run(events))
    assert sorted(techs) == ["T1110.001", "T1110.003"]
