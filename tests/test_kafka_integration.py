"""Optional Kafka integration tests.

Skipped unless RUN_KAFKA_INTEGRATION=1. These talk to local Apache Kafka at
localhost:9092. They use TEST FIXTURE payloads, not BOTS v3 evidence, and must
not be reported as real BOTS streaming validation.
"""

from __future__ import annotations

import os
import uuid

import pytest

from app.ingestion.kafka_producer import EventProducer
from app.streaming.config import KafkaSettings, consumer_config
from app.streaming.jsonutil import loads
from tests.splunk_fixtures import CLOUDTRAIL_FIXTURE

pytestmark = pytest.mark.kafka_integration

RUN = os.environ.get("RUN_KAFKA_INTEGRATION") == "1"


@pytest.fixture
def settings() -> KafkaSettings:
    suffix = uuid.uuid4().hex[:8]
    return KafkaSettings(
        bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
        producer_client_id=f"soc-itest-producer-{suffix}",
    )


@pytest.mark.skipif(not RUN, reason="set RUN_KAFKA_INTEGRATION=1 against local Kafka")
def test_publish_and_consume_fixture_from_live_broker(settings: KafkaSettings) -> None:
    from confluent_kafka import Consumer

    marker = uuid.uuid4().hex
    payload = {**CLOUDTRAIL_FIXTURE, "userAgent": f"TEST FIXTURE — NOT BOTS DATA {marker}"}
    producer = EventProducer(settings, flush_timeout=15.0)
    envelope = producer.publish_raw_event(payload, source="test-fixture")
    producer.close()

    group = f"soc-itest-{marker[:12]}"
    consumer = Consumer(consumer_config(settings, group_id=group, client_id=group))
    consumer.subscribe([settings.raw_topic])
    found = None
    try:
        for _ in range(40):
            message = consumer.poll(1.0)
            if message is None or message.error():
                continue
            body = loads(message.value())
            if body.get("event_id") == envelope.event_id:
                found = body
                break
    finally:
        consumer.close()

    assert found is not None
    assert found["source"] == "test-fixture"
    assert found["payload"]["userAgent"].startswith("TEST FIXTURE — NOT BOTS DATA")
    assert found["payload"]["eventName"] == "DescribeInstances"