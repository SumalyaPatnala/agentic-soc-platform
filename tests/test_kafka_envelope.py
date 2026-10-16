"""Tests for KafkaEventEnvelope and DeadLetterRecord.

These are transport-schema tests. They do not stream real BOTS v3 data.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.models.kafka_envelope import DeadLetterRecord, KafkaEventEnvelope
from app.streaming.jsonutil import dump_bytes, dumps, loads
from app.streaming.provenance import derive_event_id, provenance_from_raw


def test_envelope_round_trip() -> None:
    original = KafkaEventEnvelope(
        event_id="sha256:abc",
        source="test-fixture",
        source_type="aws:cloudtrail",
        produced_at=datetime(2018, 8, 20, 13, 1, 46, tzinfo=timezone.utc),
        payload={"eventName": "DescribeInstances"},
        metadata={"host": "111111111111"},
    )

    encoded = dump_bytes(original.model_dump(mode="json"))
    restored = KafkaEventEnvelope.model_validate(loads(encoded))

    assert restored.event_id == original.event_id
    assert restored.source == "test-fixture"
    assert restored.payload["eventName"] == "DescribeInstances"
    assert restored.metadata["host"] == "111111111111"
    assert restored.schema_version == "1.0"


def test_dumps_is_key_sorted() -> None:
    assert dumps({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_provenance_copies_only_present_fields() -> None:
    payload = {
        "index": "botsv3",
        "sourcetype": "aws:cloudtrail",
        "source": "s3://example",
        "_time": "2018-08-20T13:01:46Z",
        "_cd": "12:34",
        "host": "111111111111",
    }

    meta = provenance_from_raw(payload)

    assert meta == {
        "splunk_index": "botsv3",
        "sourcetype": "aws:cloudtrail",
        "source": "s3://example",
        "host": "111111111111",
        "original_timestamp": "2018-08-20T13:01:46Z",
        "splunk_event_identifier": "12:34",
    }


def test_provenance_omits_missing_fields_instead_of_fabricating() -> None:
    meta = provenance_from_raw({"sourcetype": "aws:cloudtrail"})

    assert meta == {"sourcetype": "aws:cloudtrail"}
    assert "splunk_index" not in meta
    assert "splunk_event_identifier" not in meta
    assert "host" not in meta


def test_event_id_prefers_splunk_cd() -> None:
    assert derive_event_id({"_cd": "99:1", "eventName": "x"}) == "splunk-cd:99:1"


def test_event_id_is_deterministic_hash_without_cd() -> None:
    payload = {"eventName": "DescribeInstances", "source": "example"}

    first = derive_event_id(payload)
    second = derive_event_id(dict(reversed(list(payload.items()))))

    assert first == second
    assert first.startswith("sha256:")


def test_event_id_explicit_wins() -> None:
    assert derive_event_id({"_cd": "99:1"}, explicit="given") == "given"


def test_dead_letter_has_no_traceback_field() -> None:
    record = DeadLetterRecord(
        failed_stage="normalization",
        error_type="NormalizationError",
        error_message="could not resolve required field 'timestamp'",
        original_event={"source": "example"},
    )

    dumped = record.model_dump()
    assert "traceback" not in dumped
    assert "stack" not in dumped
    assert set(dumped) == {
        "schema_version",
        "failed_stage",
        "error_type",
        "error_message",
        "original_event",
        "metadata",
    }
