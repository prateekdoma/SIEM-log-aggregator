"""producer-ssh / producer-web: tail a lab log file into its raw Kafka topic.

    python -m producers.tail --source ssh --file /logs/ssh/current --topic syslog-raw
    python -m producers.tail --source web --file /logs/web/access.log --topic web-logs-raw

Reads the file from the start, then follows it for new lines. If the file shrinks
or its inode changes (e.g. after `make reset` recreates the volume), it reopens
from the start. Re-sent lines are harmless: event.id is a deterministic UUIDv5,
so Postgres drops duplicates via ON CONFLICT DO NOTHING.

Raw lines are published without a key (SPEC rule 3 allows "no key" on raw topics);
the normalizer sets the source.ip key on the normalized events.
"""
from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from collections.abc import Iterator

from common import config
from common.kafka import make_producer

_running = True


def _stop(*_: object) -> None:
    global _running
    _running = False


def follow(path: str, poll_interval: float = 0.25) -> Iterator[str]:
    """Yield lines from `path`, from the start, following appends.

    Waits for the file to appear, and reopens from the start if it is truncated
    or replaced (size shrank below our position, or the inode changed).
    """
    while _running and not os.path.exists(path):
        print(f"[producer] waiting for {path}", flush=True)
        time.sleep(1.0)

    handle = open(path, "r", encoding="utf-8", errors="replace")
    inode = os.fstat(handle.fileno()).st_ino
    try:
        while _running:
            line = handle.readline()
            if line:
                if line.endswith("\n"):
                    yield line
                else:
                    # Partial line still being written; rewind and retry.
                    handle.seek(handle.tell() - len(line))
                    time.sleep(poll_interval)
                continue

            time.sleep(poll_interval)
            try:
                stat = os.stat(path)
            except FileNotFoundError:
                continue
            if stat.st_ino != inode or stat.st_size < handle.tell():
                print(f"[producer] {path} rotated/truncated; reopening", flush=True)
                handle.close()
                handle = open(path, "r", encoding="utf-8", errors="replace")
                inode = os.fstat(handle.fileno()).st_ino
    finally:
        handle.close()


def main() -> int:
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    parser = argparse.ArgumentParser(description="Tail a log file into a Kafka topic")
    parser.add_argument("--source", required=True, choices=["ssh", "web"])
    parser.add_argument("--file", required=True, help="log file path to tail")
    parser.add_argument("--topic", required=True, help="destination raw topic")
    args = parser.parse_args()

    producer = make_producer(f"producer-{args.source}")
    print(
        f"[producer-{args.source}] tailing {args.file} -> {args.topic}",
        flush=True,
    )

    count = 0
    for line in follow(args.file):
        producer.produce(args.topic, value=line.rstrip("\n").encode("utf-8"))
        producer.poll(0)
        count += 1
        if count % 500 == 0:
            producer.flush()

    producer.flush()
    print(f"[producer-{args.source}] stopped after {count} lines", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
