"""intel-updater: pull OTX IPv4 indicators in bulk into an ephemeral cache file.

On startup and every OTX_REFRESH_S seconds, use the official OTXv2 SDK to read
the pulses this account subscribes to, modified in the last OTX_LOOKBACK_DAYS,
keep only IPv4 indicators (cap OTX_MAX_IPS, newest pulses first), and write them
to OTX_FILE as a JSON list. The normalizer loads that file and reloads on change.

Ephemeral by design (see the project note): the file is NOT a host bind-mount,
it is deleted on startup before the first pull and on shutdown (SIGTERM/SIGINT),
and `make reset` wipes its volume. It must never persist on the laptop.

No key / SDK error / no subscribed pulses: log and carry on — the pipeline keeps
tagging `unknown` and never blocks (CLAUDE.md hard rule 6).
"""
from __future__ import annotations

import json
import os
import signal
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

from common import config

try:
    from OTXv2 import OTXv2
except ImportError:  # image without the SDK still runs (tags stay unknown)
    OTXv2 = None

IPV4_TYPE = "IPv4"
_running = True


def _stop(*_: object) -> None:
    global _running
    _running = False


def _remove_file() -> None:
    try:
        os.remove(config.OTX_FILE)
        print(f"[intel] removed {config.OTX_FILE}", flush=True)
    except FileNotFoundError:
        pass
    except OSError as exc:
        print(f"[intel] could not remove {config.OTX_FILE}: {exc}", flush=True)


def pull_ipv4(api_key: str) -> set[str]:
    """Collect up to OTX_MAX_IPS unique IPv4 indicators from recent pulses.

    The subscribed-pulses endpoint yields pulses newest-first (ordered by
    `modified` descending — verified against the live API), so stopping once the
    set reaches OTX_MAX_IPS keeps the newest indicators, as the spec requires
    ("newest pulses first"). A warning is logged if that order is ever violated.
    """
    otx = OTXv2(api_key)
    since = datetime.now(timezone.utc) - timedelta(days=config.OTX_LOOKBACK_DAYS)
    ips: set[str] = set()
    prev_modified: str | None = None

    for pulse in otx.getall_iter(modified_since=since):
        modified = pulse.get("modified", "")
        if prev_modified is not None and modified > prev_modified:
            print("[intel] WARNING: pulses not newest-first; cap may drop newest", flush=True)
        prev_modified = modified
        for indicator in pulse.get("indicators", []):
            if indicator.get("type") == IPV4_TYPE and indicator.get("indicator"):
                ips.add(indicator["indicator"])
        if len(ips) >= config.OTX_MAX_IPS:
            return ips
    return ips


def _write_atomic(ips: set[str]) -> None:
    directory = os.path.dirname(config.OTX_FILE)
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(sorted(ips), handle)
        os.replace(tmp, config.OTX_FILE)       # atomic; bumps mtime for reload
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def refresh() -> None:
    api_key = config.OTX_API_KEY.strip()
    if not api_key:
        print("[intel] OTX_API_KEY not set; skipping pull (events stay 'unknown')", flush=True)
        return
    if OTXv2 is None:
        print("[intel] OTXv2 SDK not installed; skipping pull", flush=True)
        return
    try:
        ips = pull_ipv4(api_key)
    except Exception as exc:  # network/auth/SDK — never crash the pipeline
        print(f"[intel] OTX pull failed: {exc}; keeping any existing file", flush=True)
        return
    _write_atomic(ips)
    size = os.path.getsize(config.OTX_FILE)
    print(
        f"[intel] pulled {len(ips)} IPv4 indicators -> {config.OTX_FILE} "
        f"({size} bytes)",
        flush=True,
    )


def main() -> int:
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    _remove_file()                              # clear any stale cache on startup
    print(
        f"[intel] started (refresh {config.OTX_REFRESH_S}s, "
        f"last {config.OTX_LOOKBACK_DAYS}d, cap {config.OTX_MAX_IPS})",
        flush=True,
    )

    while _running:
        refresh()
        waited = 0
        while _running and waited < config.OTX_REFRESH_S:
            time.sleep(1)
            waited += 1

    _remove_file()                              # delete on shutdown
    print("[intel] stopped", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
