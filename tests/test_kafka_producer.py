"""Unit tests for EventProducer using a fake client. No broker required.

Fixture payloads are TEST FIXTURE — NOT BOTS DATA.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.ingestion.kafka_producer import EventProducer, KafkaPublishError, publish_export_file
from app.models.evidence import EvidenceRecord, format_evidence_id
from app.models.kafka_envelope import DeadLetterRecord
from app.models.security_event import SecurityEvent
from app.streaming.jsonutil import loads
from tests.kafka_fakes import FakeProducer
from tests.splunk_fixtures import CLOUDTRAIL_FIXTURE


def _producer(fake: FakeProducer | None = None) -> tuple[EventProducer, FakeProducer]:
    client = fake or FakeProducer()
    return EventProducer(client=client), client


def test_publish_raw_uses_documented_topic_and_preserves_payload() -> None:
    producer, fake = _producer()

    envelope = producer.publish_raw_event(CLOUDTRAIL_FIXTURE, source="test-fixture")

    assert len(fake.published) == 1
    message = fake.published[0]
    assert message["topic"] == "soc.raw.events"
    assert message["key"] == envelope.event_id
    body = loads(message["value"])
    assert body["source"] == "test-fixture"
    assert body["payload"] == CLOUDTRAIL_FIXTURE
    assert body["source_type"] == "aws:cloudtrail"
    assert "index" not in CLOUDTRAIL_FIXTURE
    assert "splunk_index" not in body["metadata"]


def test_publish_raw_copies_real_splunk_identifiers_when_present() -> None:
    producer, fake = _producer()
    payload = {**CLOUDTRAIL_FIXTURE, "index": "botsv3", "_cd": "8:21"}

    envelope = producer.publish_raw_event(payload, source="splunk-export")
    body = loads(fake.published[0]["value"])

    assert envelope.event_id == "splunk-cd:8:21"
    assert body["metadata"]["splunk_index"] == "botsv3"
    assert body["metadata"]["splunk_event_identifier"] == "8:21"
    assert body["metadata"]["original_timestamp"] == payload["_time"]


def test_publish_normalized_keeps_event_id_and_security_event() -> None:
    producer, fake = _producer()
    event = SecurityEvent.model_validate(
        {
            "timestamp": "2018-08-20T13:01:46Z",
            "source": "example",
            "sourcetype": "aws:cloudtrail",
            "event_name": "DescribeInstances",
            "raw_event": CLOUDTRAIL_FIXTURE,
        }
    )

    producer.publish_normalized_event(
        event, event_id="sha256:abc", source="test-fixture", metadata={"raw_offset": 4}
    )
    body = loads(fake.published[0]["value"])

    assert fake.published[0]["topic"] == "soc.normalized.events"
    assert body["event_id"] == "sha256:abc"
    assert body["payload"]["event_name"] == "DescribeInstances"
    assert body["payload"]["raw_event"] == CLOUDTRAIL_FIXTURE
    assert body["metadata"]["raw_offset"] == 4


def test_publish_evidence_includes_deterministic_evidence_id() -> None:
    producer, fake = _producer()
    event = SecurityEvent(
        timestamp=datetime(2018, 8, 20, 13, 1, 46, tzinfo=timezone.utc),
        source="example",
        sourcetype="aws:cloudtrail",
        event_name="DescribeInstances",
        raw_event=CLOUDTRAIL_FIXTURE,
    )
    record = EvidenceRecord(
        evidence_id=format_evidence_id(7),
        normalized_event=event,
        order=7,
    )

    producer.publish_evidence_event(record, event_id="sha256:abc", source="test-fixture")
    body = loads(fake.published[0]["value"])

    assert fake.published[0]["topic"] == "soc.evidence.events"
    assert body["payload"]["evidence_id"] == "ev-000007"
    assert body["payload"]["order"] == 7
    assert body["metadata"]["evidence_id"] == "ev-000007"


def test_delivery_error_is_not_swallowed() -> None:
    producer, _ = _producer(FakeProducer(fail_with="Local: Message timed out"))

    with pytest.raises(KafkaPublishError, match="delivery failed"):
        producer.publish_raw_event(CLOUDTRAIL_FIXTURE, source="test-fixture")


def test_flush_timeout_raises() -> None:
    producer, _ = _producer(FakeProducer(remaining_after_flush=1))

    with pytest.raises(KafkaPublishError, match="still in flight"):
        producer.publish_raw_event(CLOUDTRAIL_FIXTURE, source="test-fixture")


def test_produce_buffer_error_raises() -> None:
    producer, _ = _producer(FakeProducer(raise_on_produce=BufferError("queue full")))

    with pytest.raises(KafkaPublishError, match="producer queue is full"):
        producer.publish_raw_event(CLOUDTRAIL_FIXTURE, source="test-fixture")


def test_publish_dead_letter_goes_to_dlq_topic() -> None:
    producer, fake = _producer()
    record = DeadLetterRecord(
        failed_stage="normalization",
        error_type="NormalizationError",
        error_message="could not resolve required field 'timestamp'",
        original_event={"source": "x"},
        metadata={"event_id": "sha256:abc"},
    )

    producer.publish_dead_letter(record)

    assert fake.published[0]["topic"] == "soc.deadletter"
    body = loads(fake.published[0]["value"])
    assert body["payload"]["failed_stage"] == "normalization"
    assert "traceback" not in body["payload"]


def test_publish_export_file_records_row_numbers(tmp_path: Path) -> None:
    path = tmp_path / "export.jsonl"
    path.write_text(
        '{"_time":"2018-08-20T13:01:46Z","source":"example","sourcetype":"aws:cloudtrail","eventName":"DescribeInstances"}\n'
        "not json\n",
        encoding="utf-8",
    )
    producer, fake = _producer()

    published, failed = publish_export_file(
        path, producer=producer, source="test-fixture"
    )

    assert (published, failed) == (1, 1)
    body = loads(fake.published[0]["value"])
    assert body["metadata"]["export_row_number"] == 1
    assert body["source"] == "test-fixture"
