"""Kafka settings loaded from the environment.

Local PLAINTEXT development only. There are no credentials, no SASL, and no TLS.
Missing variables fall back to the documented local defaults rather than failing
at import time, so unit tests do not require a ``.env`` file.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Final

DEFAULT_BOOTSTRAP_SERVERS: Final = "localhost:9092"
DEFAULT_RAW_TOPIC: Final = "soc.raw.events"
DEFAULT_NORMALIZED_TOPIC: Final = "soc.normalized.events"
DEFAULT_EVIDENCE_TOPIC: Final = "soc.evidence.events"
DEFAULT_DLQ_TOPIC: Final = "soc.deadletter"
DEFAULT_NORMALIZER_GROUP: Final = "soc-normalizer-v1"
DEFAULT_EVIDENCE_GROUP: Final = "soc-evidence-v1"
DEFAULT_PRODUCER_CLIENT_ID: Final = "soc-kafka-producer"
DEFAULT_NORMALIZER_CLIENT_ID: Final = "soc-normalizer-consumer"
DEFAULT_EVIDENCE_CLIENT_ID: Final = "soc-evidence-consumer"


def _env(name: str, default: str) -> str:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    return value.strip()


@dataclass(frozen=True)
class KafkaSettings:
    """Runtime Kafka configuration. All values are strings from the environment."""

    bootstrap_servers: str = DEFAULT_BOOTSTRAP_SERVERS
    raw_topic: str = DEFAULT_RAW_TOPIC
    normalized_topic: str = DEFAULT_NORMALIZED_TOPIC
    evidence_topic: str = DEFAULT_EVIDENCE_TOPIC
    dlq_topic: str = DEFAULT_DLQ_TOPIC
    normalizer_group: str = DEFAULT_NORMALIZER_GROUP
    evidence_group: str = DEFAULT_EVIDENCE_GROUP
    producer_client_id: str = DEFAULT_PRODUCER_CLIENT_ID
    normalizer_client_id: str = DEFAULT_NORMALIZER_CLIENT_ID
    evidence_client_id: str = DEFAULT_EVIDENCE_CLIENT_ID

    @classmethod
    def from_env(cls) -> KafkaSettings:
        """Build settings from ``KAFKA_*`` environment variables."""
        return cls(
            bootstrap_servers=_env("KAFKA_BOOTSTRAP_SERVERS", DEFAULT_BOOTSTRAP_SERVERS),
            raw_topic=_env("KAFKA_RAW_TOPIC", DEFAULT_RAW_TOPIC),
            normalized_topic=_env("KAFKA_NORMALIZED_TOPIC", DEFAULT_NORMALIZED_TOPIC),
            evidence_topic=_env("KAFKA_EVIDENCE_TOPIC", DEFAULT_EVIDENCE_TOPIC),
            dlq_topic=_env("KAFKA_DLQ_TOPIC", DEFAULT_DLQ_TOPIC),
            normalizer_group=_env("KAFKA_NORMALIZER_GROUP", DEFAULT_NORMALIZER_GROUP),
            evidence_group=_env("KAFKA_EVIDENCE_GROUP", DEFAULT_EVIDENCE_GROUP),
            producer_client_id=_env("KAFKA_PRODUCER_CLIENT_ID", DEFAULT_PRODUCER_CLIENT_ID),
            normalizer_client_id=_env(
                "KAFKA_NORMALIZER_CLIENT_ID", DEFAULT_NORMALIZER_CLIENT_ID
            ),
            evidence_client_id=_env(
                "KAFKA_EVIDENCE_CLIENT_ID", DEFAULT_EVIDENCE_CLIENT_ID
            ),
        )


def producer_config(settings: KafkaSettings) -> dict[str, str]:
    """confluent-kafka producer configuration for local PLAINTEXT Kafka."""
    return {
        "bootstrap.servers": settings.bootstrap_servers,
        "client.id": settings.producer_client_id,
        "acks": "all",
        "enable.idempotence": "true",
        "retries": "5",
        "linger.ms": "5",
    }


def consumer_config(
    settings: KafkaSettings, *, group_id: str, client_id: str
) -> dict[str, str | bool]:
    """confluent-kafka consumer configuration.

    Auto-commit is off. The caller must commit after a successful downstream
    publish (or a successful DLQ publish) so processing is at-least-once, not
    at-most-once.
    """
    return {
        "bootstrap.servers": settings.bootstrap_servers,
        "group.id": group_id,
        "client.id": client_id,
        "enable.auto.commit": False,
        "auto.offset.reset": "earliest",
        "enable.partition.eof": False,
    }
