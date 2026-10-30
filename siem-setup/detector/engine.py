"""detector: offer each normalized event to every rule, publish alerts.

Consumes normalized-security-events (group `detectors`), keeps per-IP state in
memory, and produces any resulting alerts to security-alerts keyed by source.ip.
Runs as 2 replicas; because events are keyed by source.ip, every event from one
IP reaches the same replica and its time windows stay correct. State is lost if a
replica restarts (an accepted limitation).
"""
from __future__ import annotations

import signal
import sys

from confluent_kafka import KafkaError

from common import config
from common.kafka import make_consumer, make_producer
from common.schema import Event
from detector.rules import RULES
from detector.state import StateStore

_running = True


def _stop(*_: object) -> None:
    global _running
    _running = False


def main() -> int:
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    consumer = make_consumer(config.GROUP_DETECTORS, [config.TOPIC_NORMALIZED])
    producer = make_producer("detector")
    store = StateStore()
    print(f"[detector] started with {len(RULES)} rules", flush=True)

    try:
        while _running:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    print(f"[detector] consume error: {msg.error()}", flush=True)
                continue

            ev = Event.from_json(msg.value())
            st = store.get(ev.source.ip, ev.timestamp)
            for rule in RULES:
                if rule.applies(ev):
                    for alert in rule.evaluate(ev, st):
                        producer.produce(
                            config.TOPIC_ALERTS,
                            key=ev.source.ip,
                            value=alert.to_json(),
                        )
                        print(
                            f"[detector] ALERT {alert.rule.id} "
                            f"{alert.threat.technique.id} ip={ev.source.ip}",
                            flush=True,
                        )
                        producer.poll(0)

            # Hand alerts to the broker before committing the source offset.
            producer.flush()
            consumer.commit(msg, asynchronous=False)
            store.maybe_evict(ev.timestamp)
    finally:
        producer.flush()
        consumer.close()
        print("[detector] stopped", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
