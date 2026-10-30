"""injector: write a scenario's raw SSH log lines straight to syslog-raw.

    python -m injector.inject <scenario> [--ip IP] [--user USER]

Each scenario emits synthetic sshd lines carrying the same timestamp prefix the
real openssh image writes, so the normalizer parses them exactly like live logs
and the detector windows them by those @timestamps. The timestamps are spaced to
drive (or deliberately not drive) each detection, so `make pipeline` is fast and
deterministic — nothing waits on a real timer.

Scenarios mirror the Attack lab table:
  bruteforce-fail     (A1) many failures vs one user   -> T1110.001
  bruteforce-success  (A2) A1 then a success           -> T1110.001 then T1078
  password-spray      (A3) failures vs >=5 users        -> T1110.003
  normal-typo         (C1) one failure then success     -> no alert
  slow-guess          (C2) one failure / 30s for 5 min  -> no alert (blind spot)

--ip sets the source IP (use one copied from otx_ipv4.json to show known_bad in
block 4). Default is a documentation-range (TEST-NET-3) address.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone

from common import config
from common.kafka import make_producer

# (offset_seconds, outcome, username) steps. outcome: "failure" | "success".
SPRAY_USERS = ["spray1", "spray2", "spray3", "spray4", "spray5", "spray6"]


def _steps(scenario: str, admin_user: str) -> list[tuple[float, str, str]]:
    if scenario == "bruteforce-fail":                     # A1 -> T1110.001
        return [(i * 2.0, "failure", admin_user) for i in range(20)]

    if scenario == "bruteforce-success":                  # A2 -> T1110.001, T1078
        steps = [(i * 2.0, "failure", admin_user) for i in range(20)]
        steps.append((42.0, "success", admin_user))       # within 600s lookback
        return steps

    if scenario == "password-spray":                      # A3 -> T1110.003
        return [(i * 5.0, "failure", user) for i, user in enumerate(SPRAY_USERS)]

    if scenario == "normal-typo":                         # C1 -> no alert
        return [(0.0, "failure", admin_user), (2.0, "success", admin_user)]

    if scenario == "slow-guess":                          # C2 -> no alert
        return [(i * 30.0, "failure", admin_user) for i in range(10)]

    raise SystemExit(f"unknown scenario: {scenario}")


def _line(ts: datetime, outcome: str, user: str, ip: str, port: int) -> str:
    verb = "Accepted" if outcome == "success" else "Failed"
    msg = f"{verb} password for {user} from {ip} port {port} ssh2"
    return f"{ts:%Y-%m-%d %H:%M:%S.%f}  {msg}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Inject scenario SSH lines")
    parser.add_argument("scenario")
    parser.add_argument("--ip", default="203.0.113.50")
    parser.add_argument("--user", default="admin", help="the brute-force target user")
    args = parser.parse_args()

    steps = _steps(args.scenario, args.user)
    base = datetime.now(timezone.utc)

    producer = make_producer("injector")
    for i, (offset, outcome, user) in enumerate(steps):
        ts = base + timedelta(seconds=offset)
        line = _line(ts, outcome, user, args.ip, 40000 + i)
        # Key the raw lines by source IP (SPEC allows it when the producer knows
        # the IP) so a burst stays on one partition and reaches the detector in
        # order — otherwise a trailing success can overtake its failures.
        producer.produce(config.TOPIC_SYSLOG_RAW, key=args.ip, value=line.encode("utf-8"))
        producer.poll(0)
    producer.flush()

    print(
        f"[injector] {args.scenario}: sent {len(steps)} lines from {args.ip}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
