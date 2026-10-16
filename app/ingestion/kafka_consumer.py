"""Kafka consumers that reuse the existing normalizer and evidence models.

Usage:
    python -m app.ingestion.kafka_consumer normalizer
    python -m app.ingestion.kafka_consumer evidence
    python -m app.ingestion.kafka_consumer inspect <topic>

Delivery is at-least-once: a message is processed, the downstream (or DLQ)
publish is acknowledged, and only then is the consumed offset committed. Duplicates
are therefore possible. Evidence ids stay ``ev-{offset:06d}`` on a given partition
so reprocessing the same offset yields the same id.

This talks to local Apache Kafka over PLAINTEXT. It does not use Confluent Cloud.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from pydantic import ValidationError

from app.ingestion.kafka_producer import EventProducer, KafkaPublishError
from app.ingestion.splunk import NormalizationError, SplunkBOTSEventNormalizer
from app.investigation.correlation import CORRELATABLE_FIELDS, field_value
from app.models.evidence import EvidenceRecord, format_evidence_id
from app.models.kafka_envelope import DeadLetterRecord, KafkaEventEnvelope, utc_now
from app.models.security_event import SecurityEvent
from app.streaming.config import KafkaSettings, consumer_config
from app.streaming.jsonutil import loads
from app.streaming.log import kafka_log
from app.streaming.provenance import derive_event_id, provenance_from_raw

logger = logging.getLogger(__name__)


class KafkaConsumeError(RuntimeError):
    """Raised when a Kafka consumer cannot be constructed or polled."""


class ConsumerClient(Protocol):
    """Minimal consumer surface so unit tests can inject a fake."""

    def subscribe(self, topics: list[str]) -> None: ...

    def poll(self, timeout: float) -> Any: ...

    def commit(self, message: Any = None, asynchronous: bool = False) -> None: ...

    def close(self) -> None: ...


def looks_like_envelope(data: Mapping[str, Any]) -> bool:
    """Whether ``data`` is a transport envelope rather than a raw payload."""
    return (
        isinstance(data.get("payload"), dict)
        and isinstance(data.get("event_id"), str)
        and "schema_version" in data
    )


def parse_message_value(raw: bytes | str) -> KafkaEventEnvelope:
    """Decode a Kafka value into an envelope.

    A wrapped envelope is validated as-is. A bare JSON object is treated as the
    payload and wrapped without inventing Splunk identifiers.
    """
    decoded = loads(raw)
    if not isinstance(decoded, dict):
        raise KafkaConsumeError(
            f"expected a JSON object, got {type(decoded).__name__!r}"
        )
    if looks_like_envelope(decoded):
        return KafkaEventEnvelope.model_validate(decoded)
    return KafkaEventEnvelope(
        event_id=derive_event_id(decoded),
        source="unwrapped",
        source_type=_optional_str(decoded.get("sourcetype")),
        produced_at=utc_now(),
        payload=decoded,
        metadata=provenance_from_raw(decoded),
    )


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _message_coords(message: Any) -> dict[str, Any]:
    coords: dict[str, Any] = {}
    topic = getattr(message, "topic", None)
    partition = getattr(message, "partition", None)
    offset = getattr(message, "offset", None)
    coords["topic"] = topic() if callable(topic) else topic
    coords["partition"] = partition() if callable(partition) else partition
    coords["offset"] = offset() if callable(offset) else offset
    return coords


def _original_event_for_dlq(raw: bytes, envelope: KafkaEventEnvelope | None) -> dict[str, Any]:
    if envelope is not None:
        return envelope.model_dump(mode="json")
    try:
        decoded = loads(raw)
        return decoded if isinstance(decoded, dict) else {"value": decoded}
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        try:
            text = raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
        except UnicodeDecodeError:
            text = repr(raw)
        return {"unparsed": text}


class PipelineProcessor:
    """Pure routing: raw → normalizer → normalized → evidence, with DLQ on failure.

    Downstream publishes go through ``EventProducer``. Kafka poll/commit live in
    :class:`TopicConsumer`.
    """

    def __init__(
        self,
        producer: EventProducer,
        settings: KafkaSettings | None = None,
        normalizer: SplunkBOTSEventNormalizer | None = None,
    ) -> None:
        self.producer = producer
        self.settings = settings or KafkaSettings.from_env()
        self.normalizer = normalizer or SplunkBOTSEventNormalizer()

    def process_raw(
        self,
        raw_value: bytes,
        *,
        topic: str,
        partition: int,
        offset: int,
        consumer_group: str,
    ) -> str:
        """Normalize one raw message. Returns ``normalized`` or ``deadletter``."""
        envelope: KafkaEventEnvelope | None = None
        try:
            envelope = parse_message_value(raw_value)
            event = self.normalizer.normalize(envelope.payload)
        except (NormalizationError, KafkaConsumeError, ValidationError, ValueError) as exc:
            self._dead_letter(
                raw_value,
                envelope,
                failed_stage="normalization",
                error=exc,
                topic=topic,
                partition=partition,
                offset=offset,
                consumer_group=consumer_group,
            )
            return "deadletter"

        metadata = {
            **envelope.metadata,
            "raw_topic": topic,
            "raw_partition": partition,
            "raw_offset": offset,
        }
        self.producer.publish_normalized_event(
            event,
            event_id=envelope.event_id,
            source=envelope.source,
            metadata=metadata,
        )
        kafka_log(
            "normalized",
            topic=topic,
            partition=partition,
            offset=offset,
            event_id=envelope.event_id,
            source=envelope.source,
            consumer_group=consumer_group,
            processing_stage="normalization",
            success="true",
        )
        return "normalized"

    def process_normalized(
        self,
        raw_value: bytes,
        *,
        topic: str,
        partition: int,
        offset: int,
        consumer_group: str,
    ) -> str:
        """Wrap one normalized event as evidence. Returns ``evidence`` or ``deadletter``."""
        envelope: KafkaEventEnvelope | None = None
        try:
            envelope = parse_message_value(raw_value)
            event = SecurityEvent.model_validate(envelope.payload)
        except (KafkaConsumeError, ValidationError, ValueError) as exc:
            self._dead_letter(
                raw_value,
                envelope,
                failed_stage="evidence",
                error=exc,
                topic=topic,
                partition=partition,
                offset=offset,
                consumer_group=consumer_group,
            )
            return "deadletter"

        record = EvidenceRecord(
            evidence_id=format_evidence_id(offset),
            normalized_event=event,
            order=offset,
        )
        correlation_keys: dict[str, str] = {}
        for name in CORRELATABLE_FIELDS:
            value = field_value(record, name)
            if value is not None:
                correlation_keys[name] = value

        metadata = {
            **envelope.metadata,
            "normalized_topic": topic,
            "normalized_partition": partition,
            "normalized_offset": offset,
            "evidence_id": record.evidence_id,
            "order": offset,
            "correlation_keys": correlation_keys,
        }
        self.producer.publish_evidence_event(
            record,
            event_id=envelope.event_id,
            source=envelope.source,
            metadata=metadata,
        )
        kafka_log(
            "evidence_published",
            topic=topic,
            partition=partition,
            offset=offset,
            event_id=envelope.event_id,
            source=envelope.source,
            consumer_group=consumer_group,
            processing_stage="evidence",
            success="true",
            evidence_id=record.evidence_id,
        )
        return "evidence"

    def _dead_letter(
        self,
        raw_value: bytes,
        envelope: KafkaEventEnvelope | None,
        *,
        failed_stage: str,
        error: Exception,
        topic: str,
        partition: int,
        offset: int,
        consumer_group: str,
    ) -> None:
        logger.exception(
            "pipeline stage failed stage=%s topic=%s partition=%s offset=%s",
            failed_stage,
            topic,
            partition,
            offset,
        )
        event_id = envelope.event_id if envelope is not None else "unknown"
        source = envelope.source if envelope is not None else "unknown"
        record = DeadLetterRecord(
            failed_stage=failed_stage,
            error_type=type(error).__name__,
            error_message=str(error),
            original_event=_original_event_for_dlq(raw_value, envelope),
            metadata={
                "event_id": event_id,
                "source": source,
                "topic": topic,
                "partition": partition,
                "offset": offset,
                "consumer_group": consumer_group,
            },
        )
        self.producer.publish_dead_letter(record)
        kafka_log(
            "deadletter",
            level=logging.WARNING,
            topic=topic,
            partition=partition,
            offset=offset,
            event_id=event_id,
            source=source,
            consumer_group=consumer_group,
            processing_stage=failed_stage,
            success="false",
            error_type=type(error).__name__,
        )


class TopicConsumer:
    """Poll loop: process then commit. At-least-once, not exactly-once."""

    def __init__(
        self,
        *,
        settings: KafkaSettings,
        group_id: str,
        client_id: str,
        topic: str,
        processor: PipelineProcessor,
        stage: str,
        client: ConsumerClient | None = None,
        poll_timeout: float = 1.0,
    ) -> None:
        self.settings = settings
        self.group_id = group_id
        self.topic = topic
        self.processor = processor
        self.stage = stage
        self.poll_timeout = poll_timeout
        if client is not None:
            self._client = client
        else:
            from confluent_kafka import Consumer

            self._client = Consumer(
                consumer_config(settings, group_id=group_id, client_id=client_id)
            )
        self._client.subscribe([topic])

    def close(self) -> None:
        self._client.close()

    def run_forever(self) -> None:
        kafka_log(
            "consumer_started",
            topic=self.topic,
            consumer_group=self.group_id,
            processing_stage=self.stage,
        )
        try:
            while True:
                self.poll_once()
        except KeyboardInterrupt:
            kafka_log(
                "consumer_stopped",
                topic=self.topic,
                consumer_group=self.group_id,
                processing_stage=self.stage,
            )
        finally:
            self.close()

    def poll_once(self) -> str | None:
        """Poll one message. Returns the processor result, or ``None`` if idle."""
        message = self._client.poll(self.poll_timeout)
        if message is None:
            return None
        error = getattr(message, "error", None)
        err = error() if callable(error) else error
        if err:
            kafka_log(
                "consumer_error",
                level=logging.ERROR,
                topic=self.topic,
                consumer_group=self.group_id,
                processing_stage=self.stage,
                success="false",
                error=str(err),
            )
            return None

        coords = _message_coords(message)
        value = message.value()
        if value is None:
            self._client.commit(message=message, asynchronous=False)
            return None

        kwargs = {
            "topic": coords.get("topic") or self.topic,
            "partition": int(coords.get("partition") or 0),
            "offset": int(coords.get("offset") or 0),
            "consumer_group": self.group_id,
        }
        try:
            if self.stage == "normalization":
                result = self.processor.process_raw(value, **kwargs)
            else:
                result = self.processor.process_normalized(value, **kwargs)
        except KafkaPublishError:
            kafka_log(
                "downstream_publish_failed",
                level=logging.ERROR,
                topic=self.topic,
                partition=kwargs["partition"],
                offset=kwargs["offset"],
                consumer_group=self.group_id,
                processing_stage=self.stage,
                success="false",
            )
            raise

        self._client.commit(message=message, asynchronous=False)
        return result


def inspect_topic(
    topic: str,
    *,
    settings: KafkaSettings | None = None,
    max_messages: int = 10,
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    """Read up to ``max_messages`` from ``topic`` from the beginning, then stop.

    Uses a throwaway consumer group so it does not steal work from the pipeline
    groups. For debugging only.
    """
    from confluent_kafka import Consumer

    settings = settings or KafkaSettings.from_env()
    group_id = f"soc-inspect-{topic}"
    config = consumer_config(
        settings, group_id=group_id, client_id=f"soc-inspect-{topic}"
    )
    config["auto.offset.reset"] = "earliest"
    consumer = Consumer(config)
    consumer.subscribe([topic])
    collected: list[dict[str, Any]] = []
    idle = 0
    try:
        while len(collected) < max_messages and idle < 10:
            message = consumer.poll(timeout)
            if message is None:
                idle += 1
                continue
            if message.error():
                idle += 1
                continue
            idle = 0
            value = message.value()
            try:
                body: Any = loads(value) if value is not None else None
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                body = {"unparsed": repr(value)}
            collected.append(
                {
                    "topic": message.topic(),
                    "partition": message.partition(),
                    "offset": message.offset(),
                    "value": body,
                }
            )
    finally:
        consumer.close()
    return collected


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.ingestion.kafka_consumer",
        description=(
            "Run a pipeline consumer (normalizer or evidence) or inspect a topic. "
            "At-least-once delivery; duplicates are possible."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("normalizer", help="consume soc.raw.events and publish normalized")
    sub.add_parser("evidence", help="consume soc.normalized.events and publish evidence")

    inspect = sub.add_parser("inspect", help="print messages from a topic and exit")
    inspect.add_argument("topic")
    inspect.add_argument("--max", type=int, default=10, dest="max_messages")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    args = build_parser().parse_args(argv)
    settings = KafkaSettings.from_env()

    if args.command == "inspect":
        try:
            messages = inspect_topic(
                args.topic, settings=settings, max_messages=args.max_messages
            )
        except Exception as exc:  # noqa: BLE001 — CLI boundary
            print(f"error: {exc}", file=sys.stderr)
            return 2
        for item in messages:
            print(json.dumps(item, sort_keys=True, default=str))
        print(f"count: {len(messages)}")
        return 0

    producer = EventProducer(settings)
    processor = PipelineProcessor(producer, settings)

    if args.command == "normalizer":
        consumer = TopicConsumer(
            settings=settings,
            group_id=settings.normalizer_group,
            client_id=settings.normalizer_client_id,
            topic=settings.raw_topic,
            processor=processor,
            stage="normalization",
        )
    else:
        consumer = TopicConsumer(
            settings=settings,
            group_id=settings.evidence_group,
            client_id=settings.evidence_client_id,
            topic=settings.normalized_topic,
            processor=processor,
            stage="evidence",
        )

    consumer.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
