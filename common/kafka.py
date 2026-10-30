"""Thin confluent-kafka helpers shared by every service.

Consumers use manual offset commits (`enable.auto.commit=false`): each service
commits only after it has fully processed a message, so a crash replays rather
than drops. `auto.offset.reset` is `earliest` everywhere except the api (block 5),
which passes `latest`.
"""
from __future__ import annotations

from confluent_kafka import Consumer, Producer

from common import config


def make_producer(client_id: str) -> Producer:
    return Producer(
        {
            "bootstrap.servers": config.KAFKA_BOOTSTRAP,
            "client.id": client_id,
            "enable.idempotence": True,          # no duplicate produces on retry
            "acks": "all",
        }
    )


def make_consumer(
    group_id: str,
    topics: list[str],
    offset_reset: str = "earliest",
) -> Consumer:
    consumer = Consumer(
        {
            "bootstrap.servers": config.KAFKA_BOOTSTRAP,
            "group.id": group_id,
            "enable.auto.commit": False,
            "auto.offset.reset": offset_reset,
        }
    )
    consumer.subscribe(topics)
    return consumer
