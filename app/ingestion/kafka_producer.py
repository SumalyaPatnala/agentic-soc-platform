"""Reusable Kafka producer for SOC pipeline topics.

Usage:
    python -m app.ingestion.kafka_producer <json-or-jsonl-file>

Publishes each record as a ``KafkaEventEnvelope`` onto ``soc.raw.events`` (or
``--topic``). Reuses ``load_raw_records`` from the file normalizer so Splunk export
shapes are accepted unchanged.

This module talks to local Apache Kafka over PLAINTEXT. It does not use Confluent
Cloud, MSK, or any cloud broker.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from app.ingestion.normalize_file import InputFormatError, load_raw_records
from app.models.evidence import EvidenceRecord
from app.models.kafka_envelope import DeadLetterRecord, KafkaEventEnvelope, utc_now
from app.models.security_event import SecurityEvent
from app.streaming.config import KafkaSettings, producer_config
from app.streaming.jsonutil import dump_bytes
from app.streaming.log import kafka_log
from app.streaming.provenance import derive_event_id, provenance_from_raw

logger = logging.getLogger(__name__)


class KafkaPublishError(RuntimeError):
    """Raised when a produce call is not acknowledged by the broker."""


class ProducerClient(Protocol):
    """Minimal producer surface so unit tests can inject a fake."""

    def produce(
        self,
        topic: str,
        value: bytes | str | None = None,
        key: bytes | str | None = None,
        on_delivery: Callable[..., Any] | None = None,
        **kwargs: Any,
    ) -> None: ...

    def poll(self, timeout: float) -> int: ...

    def flush(self, timeout: float | None = None) -> int: ...


@dataclass
class _DeliveryOutcome:
    errors: list[str] = field(default_factory=list)
    delivered: int = 0

    def callback(self, err: Any, _msg: Any) -> None:
        if err is not None:
            self.errors.append(str(err))
        else:
            self.delivered += 1


def _envelope_dict(envelope: KafkaEventEnvelope) -> dict[str, Any]:
    return envelope.model_dump(mode="json")


class EventProducer:
    """Reusable producer. Do not construct a new one per event."""

    def __init__(
        self,
        settings: KafkaSettings | None = None,
        client: ProducerClient | None = None,
        *,
        flush_timeout: float = 10.0,
    ) -> None:
        self.settings = settings or KafkaSettings.from_env()
        self.flush_timeout = flush_timeout
        if client is not None:
            self._client = client
        else:
            from confluent_kafka import Producer

            self._client = Producer(producer_config(self.settings))

    def close(self) -> None:
        """Flush outstanding deliveries. Safe to call more than once."""
        remaining = self._client.flush(self.flush_timeout)
        if remaining:
            raise KafkaPublishError(
                f"{remaining} message(s) still in flight after flush timeout "
                f"{self.flush_timeout}s"
            )

    def publish(
        self,
        topic: str,
        envelope: KafkaEventEnvelope,
        *,
        key: str | None = None,
    ) -> KafkaEventEnvelope:
        """Serialize ``envelope`` and wait for broker acknowledgement."""
        body = dump_bytes(_envelope_dict(envelope))
        outcome = _DeliveryOutcome()
        try:
            self._client.produce(
                topic,
                value=body,
                key=key or envelope.event_id,
                on_delivery=outcome.callback,
            )
        except BufferError as exc:
            raise KafkaPublishError(f"producer queue is full: {exc}") from exc

        remaining = self._client.flush(self.flush_timeout)
        if remaining:
            raise KafkaPublishError(
                f"flush timed out with {remaining} message(s) still in flight"
            )
        if outcome.errors:
            raise KafkaPublishError(
                f"delivery failed for topic {topic!r}: {outcome.errors[0]}"
            )

        kafka_log(
            "published",
            topic=topic,
            event_id=envelope.event_id,
            source=envelope.source,
            processing_stage="produce",
            success="true",
        )
        return envelope

    def publish_raw_event(
        self,
        payload: Mapping[str, Any],
        *,
        source: str,
        event_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        produced_at: datetime | None = None,
        topic: str | None = None,
    ) -> KafkaEventEnvelope:
        """Wrap a raw Splunk-shaped dict and publish it to the raw topic."""
        extra = dict(metadata) if metadata else {}
        copied = provenance_from_raw(payload)
        merged = {**copied, **extra}
        envelope = KafkaEventEnvelope(
            event_id=derive_event_id(payload, explicit=event_id),
            source=source,
            source_type=_optional_str(payload.get("sourcetype")),
            produced_at=produced_at or utc_now(),
            payload=dict(payload),
            metadata=merged,
        )
        return self.publish(topic or self.settings.raw_topic, envelope)

    def publish_normalized_event(
        self,
        event: SecurityEvent,
        *,
        event_id: str,
        source: str,
        metadata: Mapping[str, Any] | None = None,
        produced_at: datetime | None = None,
        topic: str | None = None,
    ) -> KafkaEventEnvelope:
        """Publish a normalized ``SecurityEvent`` onto the normalized topic."""
        envelope = KafkaEventEnvelope(
            event_id=event_id,
            source=source,
            source_type=event.sourcetype,
            produced_at=produced_at or utc_now(),
            payload=event.model_dump(mode="json"),
            metadata=dict(metadata) if metadata else {},
        )
        return self.publish(topic or self.settings.normalized_topic, envelope)

    def publish_evidence_event(
        self,
        record: EvidenceRecord,
        *,
        event_id: str,
        source: str,
        metadata: Mapping[str, Any] | None = None,
        produced_at: datetime | None = None,
        topic: str | None = None,
    ) -> KafkaEventEnvelope:
        """Publish an ``EvidenceRecord`` onto the evidence topic."""
        extra = dict(metadata) if metadata else {}
        extra.setdefault("evidence_id", record.evidence_id)
        if record.order is not None:
            extra.setdefault("order", record.order)
        envelope = KafkaEventEnvelope(
            event_id=event_id,
            source=source,
            source_type=record.normalized_event.sourcetype,
            produced_at=produced_at or utc_now(),
            payload=record.model_dump(mode="json"),
            metadata=extra,
        )
        return self.publish(topic or self.settings.evidence_topic, envelope)

    def publish_dead_letter(self, record: DeadLetterRecord) -> DeadLetterRecord:
        """Publish a failed record onto the DLQ topic. Never silently dropped."""
        envelope = KafkaEventEnvelope(
            event_id=str(record.metadata.get("event_id") or "unknown"),
            source=str(record.metadata.get("source") or "deadletter"),
            source_type=record.failed_stage,
            produced_at=utc_now(),
            payload=record.model_dump(mode="json"),
            metadata=dict(record.metadata),
        )
        self.publish(self.settings.dlq_topic, envelope)
        return record


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def publish_export_file(
    path: Path,
    *,
    producer: EventProducer | None = None,
    source: str = "file-export",
    topic: str | None = None,
) -> tuple[int, int]:
    """Read a Splunk export and publish each object to the raw topic.

    Returns ``(published, failed_to_parse)``. Parse failures are not published;
    they are counted so the caller can see them. The file is never modified.
    """
    producer = producer or EventProducer()
    records = load_raw_records(path.read_text(encoding="utf-8"))
    published = 0
    failed = 0
    for record in records:
        if record.payload is None:
            failed += 1
            kafka_log(
                "skipped unparsable export record",
                level=logging.WARNING,
                processing_stage="produce",
                success="false",
                export_row_number=record.index,
                error=record.error,
            )
            continue
        producer.publish_raw_event(
            record.payload,
            source=source,
            metadata={"export_row_number": record.index, "export_path": str(path)},
            topic=topic,
        )
        published += 1
    producer.close()
    return published, failed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.ingestion.kafka_producer",
        description=(
            "Publish exported Splunk JSON/JSONL (or a labeled test fixture) to "
            "soc.raw.events. Does not query Splunk and does not modify the file."
        ),
    )
    parser.add_argument("path", type=Path, help="JSON or JSON Lines file to publish")
    parser.add_argument(
        "--source",
        default="file-export",
        help=(
            "transport source label stored on the envelope "
            "(use 'test-fixture' for schema fixtures, never for real BOTS data)"
        ),
    )
    parser.add_argument(
        "--topic",
        default=None,
        help="override dest topic; defaults to KAFKA_RAW_TOPIC",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    args = build_parser().parse_args(argv)
    path: Path = args.path
    if not path.is_file():
        print(f"error: no such file: {path}", file=sys.stderr)
        return 2

    settings = KafkaSettings.from_env()
    producer = EventProducer(settings)
    try:
        published, failed = publish_export_file(
            path, producer=producer, source=args.source, topic=args.topic
        )
    except FileNotFoundError:
        print(f"error: no such file: {path}", file=sys.stderr)
        return 2
    except UnicodeDecodeError:
        print(f"error: {path} is not UTF-8 text", file=sys.stderr)
        return 2
    except InputFormatError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KafkaPublishError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"published: {published}")
    print(f"failed_to_parse: {failed}")
    print(f"topic: {args.topic or settings.raw_topic}")
    print(f"bootstrap: {settings.bootstrap_servers}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
