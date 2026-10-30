"""normalizer: consume raw log topics, parse to the ECS schema, publish normalized.

Reads syslog-raw and web-logs-raw (group `normalizers`), picks the parser by
topic, tags OTX status, and produces each Event to normalized-security-events
keyed by `source.ip` so one IP always lands on the same partition. Offsets are
committed only after the normalized message is produced.

Runs as 2 replicas; the consumer group splits the raw partitions between them.
"""
from __future__ import annotations

import signal
import sys

from confluent_kafka import KafkaError

from common import config
from common.kafka import make_consumer, make_producer
from normalizer.enrich import OtxTagger
from normalizer.parsers.nginx import parse_nginx_line
from normalizer.parsers.ssh import parse_ssh_line

# Which parser handles which raw topic.
_PARSERS = {
    config.TOPIC_SYSLOG_RAW: parse_ssh_line,
    config.TOPIC_WEB_LOGS_RAW: parse_nginx_line,
}

_running = True


def _stop(*_: object) -> None:
    global _running
    _running = False


def main() -> None:
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    consumer = make_consumer(
        config.GROUP_NORMALIZERS,
        [config.TOPIC_SYSLOG_RAW, config.TOPIC_WEB_LOGS_RAW],
    )
    producer = make_producer("normalizer")
    tagger = OtxTagger()
    print("[normalizer] started", flush=True)

    try:
        while _running:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                print(f"[normalizer] consume error: {msg.error()}", flush=True)
                continue

            parser = _PARSERS.get(msg.topic())
            if parser is None:
                consumer.commit(msg, asynchronous=False)
                continue

            raw = msg.value().decode("utf-8", errors="replace")
            event = parser(raw)
            if event is not None:
                event = tagger.tag(event)
                producer.produce(
                    config.TOPIC_NORMALIZED,
                    key=event.source.ip,
                    value=event.to_json(),
                )
                producer.poll(0)

            # Make sure the normalized message is handed to the broker before we
            # commit the source offset, so a crash never drops an event.
            producer.flush()
            consumer.commit(msg, asynchronous=False)
    finally:
        producer.flush()
        consumer.close()
        print("[normalizer] stopped", flush=True)


if __name__ == "__main__":
    sys.exit(main())
