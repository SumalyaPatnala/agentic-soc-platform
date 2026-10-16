"""Unit tests for Kafka pipeline routing. No broker required.

Fixture payloads are TEST FIXTURE — NOT BOTS DATA.
"""

from __future__ import annotations

import pytest

from app.ingestion.kafka_consumer import (
    PipelineProcessor,
    TopicConsumer,
    looks_like_envelope,
    parse_message_value,
)
from app.ingestion.kafka_producer import EventProducer, KafkaPublishError
from app.models.kafka_envelope import KafkaEventEnvelope, utc_now
from app.streaming.jsonutil import dump_bytes, loads
from tests.kafka_fakes import FakeConsumer, FakeMessage, FakeProducer
from tests.splunk_fixtures import CLOUDTRAIL_FIXTURE


def _processor(fake: FakeProducer | None = None) -> tuple[PipelineProcessor, FakeProducer]:
    client = fake or FakeProducer()
    producer = EventProducer(client=client)
    return PipelineProcessor(producer), client


def test_parse_envelope_and_unwrapped_payload() -> None:
    wrapped = KafkaEventEnvelope(
        event_id="given",
        source="test-fixture",
        produced_at=utc_now(),
        payload=CLOUDTRAIL_FIXTURE,
    )
    parsed = parse_message_value(dump_bytes(wrapped.model_dump(mode="json")))
    assert parsed.event_id == "given"
    assert parsed.payload == CLOUDTRAIL_FIXTURE

    unwrapped = parse_message_value(dump_bytes(CLOUDTRAIL_FIXTURE))
    assert unwrapped.source == "unwrapped"
    assert unwrapped.payload == CLOUDTRAIL_FIXTURE
    assert looks_like_envelope(wrapped.model_dump()) is True
    assert looks_like_envelope(CLOUDTRAIL_FIXTURE) is False


def test_raw_success_routes_to_normalized_topic() -> None:
    processor, fake = _processor()

    result = processor.process_raw(
        dump_bytes(CLOUDTRAIL_FIXTURE),
        topic="soc.raw.events",
        partition=0,
        offset=3,
        consumer_group="soc-normalizer-v1",
    )

    assert result == "normalized"
    assert fake.published[0]["topic"] == "soc.normalized.events"
    body = loads(fake.published[0]["value"])
    assert body["payload"]["event_name"] == "DescribeInstances"
    assert body["payload"]["raw_event"] == CLOUDTRAIL_FIXTURE
    assert body["metadata"]["raw_offset"] == 3
    assert body["source"] == "unwrapped"


def test_raw_failure_routes_to_dlq_without_normalized_publish() -> None:
    processor, fake = _processor()
    bad = {key: value for key, value in CLOUDTRAIL_FIXTURE.items() if key != "_time"}
    del bad["eventTime"]

    result = processor.process_raw(
        dump_bytes(bad),
        topic="soc.raw.events",
        partition=0,
        offset=1,
        consumer_group="soc-normalizer-v1",
    )

    assert result == "deadletter"
    assert [item["topic"] for item in fake.published] == ["soc.deadletter"]
    body = loads(fake.published[0]["value"])
    assert body["payload"]["failed_stage"] == "normalization"
    assert body["payload"]["error_type"] == "NormalizationError"
    assert "timestamp" in body["payload"]["error_message"]
    assert "Traceback" not in body["payload"]["error_message"]


def test_malformed_json_goes_to_dlq() -> None:
    processor, fake = _processor()

    result = processor.process_raw(
        b"not json",
        topic="soc.raw.events",
        partition=0,
        offset=0,
        consumer_group="soc-normalizer-v1",
    )

    assert result == "deadletter"
    body = loads(fake.published[0]["value"])
    assert body["payload"]["original_event"]["unparsed"] == "not json"


def test_normalized_success_routes_to_evidence_with_offset_id() -> None:
    processor, fake = _processor()
    processor.process_raw(
        dump_bytes(CLOUDTRAIL_FIXTURE),
        topic="soc.raw.events",
        partition=0,
        offset=9,
        consumer_group="soc-normalizer-v1",
    )
    normalized_value = fake.published[0]["value"]
    fake.published.clear()

    result = processor.process_normalized(
        normalized_value,
        topic="soc.normalized.events",
        partition=0,
        offset=9,
        consumer_group="soc-evidence-v1",
    )

    assert result == "evidence"
    body = loads(fake.published[0]["value"])
    assert fake.published[0]["topic"] == "soc.evidence.events"
    assert body["payload"]["evidence_id"] == "ev-000009"
    assert body["payload"]["order"] == 9
    assert body["payload"]["normalized_event"]["raw_event"] == CLOUDTRAIL_FIXTURE
    assert body["metadata"]["correlation_keys"]["user"] == "example-user"
    assert body["metadata"]["correlation_keys"]["src_ip"] == "203.0.113.25"


def test_same_offset_yields_same_evidence_id() -> None:
    processor, fake = _processor()
    value = dump_bytes(
        KafkaEventEnvelope(
            event_id="stable",
            source="test-fixture",
            produced_at=utc_now(),
            payload={
                "timestamp": "2018-08-20T13:01:46Z",
                "source": "example",
                "sourcetype": "aws:cloudtrail",
                "event_name": "DescribeInstances",
                "raw_event": CLOUDTRAIL_FIXTURE,
            },
        ).model_dump(mode="json")
    )

    processor.process_normalized(
        value,
        topic="soc.normalized.events",
        partition=0,
        offset=42,
        consumer_group="soc-evidence-v1",
    )
    first = loads(fake.published[0]["value"])["payload"]["evidence_id"]
    fake.published.clear()
    processor.process_normalized(
        value,
        topic="soc.normalized.events",
        partition=0,
        offset=42,
        consumer_group="soc-evidence-v1",
    )
    second = loads(fake.published[0]["value"])["payload"]["evidence_id"]

    assert first == second == "ev-000042"


def test_invalid_normalized_payload_goes_to_dlq() -> None:
    processor, fake = _processor()

    result = processor.process_normalized(
        dump_bytes({"event_name": "incomplete"}),
        topic="soc.normalized.events",
        partition=0,
        offset=0,
        consumer_group="soc-evidence-v1",
    )

    assert result == "deadletter"
    body = loads(fake.published[0]["value"])
    assert body["payload"]["failed_stage"] == "evidence"


def test_consumer_commits_after_successful_process() -> None:
    processor, fake = _processor()
    incoming = FakeMessage(
        _topic="soc.raw.events",
        _partition=0,
        _offset=5,
        _value=dump_bytes(CLOUDTRAIL_FIXTURE),
    )
    consumer_client = FakeConsumer([incoming])
    topic_consumer = TopicConsumer(
        settings=processor.settings,
        group_id="soc-normalizer-v1",
        client_id="test",
        topic="soc.raw.events",
        processor=processor,
        stage="normalization",
        client=consumer_client,
    )

    result = topic_consumer.poll_once()

    assert result == "normalized"
    assert consumer_client.committed == [incoming]
    assert fake.published[0]["topic"] == "soc.normalized.events"


def test_consumer_commits_after_dlq_so_poison_pills_do_not_loop() -> None:
    processor, _ = _processor()
    incoming = FakeMessage(
        _topic="soc.raw.events",
        _partition=0,
        _offset=5,
        _value=b"{",
    )
    consumer_client = FakeConsumer([incoming])
    topic_consumer = TopicConsumer(
        settings=processor.settings,
        group_id="soc-normalizer-v1",
        client_id="test",
        topic="soc.raw.events",
        processor=processor,
        stage="normalization",
        client=consumer_client,
    )

    result = topic_consumer.poll_once()

    assert result == "deadletter"
    assert consumer_client.committed == [incoming]


def test_consumer_does_not_commit_when_downstream_publish_fails() -> None:
    processor, _ = _processor(FakeProducer(fail_with="broker down"))
    incoming = FakeMessage(
        _topic="soc.raw.events",
        _partition=0,
        _offset=5,
        _value=dump_bytes(CLOUDTRAIL_FIXTURE),
    )
    consumer_client = FakeConsumer([incoming])
    topic_consumer = TopicConsumer(
        settings=processor.settings,
        group_id="soc-normalizer-v1",
        client_id="test",
        topic="soc.raw.events",
        processor=processor,
        stage="normalization",
        client=consumer_client,
    )

    with pytest.raises(KafkaPublishError):
        topic_consumer.poll_once()

    assert consumer_client.committed == []


def test_event_error_does_not_commit_or_crash() -> None:
    processor, _ = _processor()
    incoming = FakeMessage(
        _topic="soc.raw.events",
        _partition=0,
        _offset=5,
        _value=None,
        _error="Broker: Unknown topic or partition",
    )
    consumer_client = FakeConsumer([incoming])
    topic_consumer = TopicConsumer(
        settings=processor.settings,
        group_id="soc-normalizer-v1",
        client_id="test",
        topic="soc.raw.events",
        processor=processor,
        stage="normalization",
        client=consumer_client,
    )

    assert topic_consumer.poll_once() is None
    assert consumer_client.committed == []
