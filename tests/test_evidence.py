"""Tests for the EvidenceRecord model.

Events are built by ``tests.evidence_factory`` and are not BOTS v3 evidence.
"""

from __future__ import annotations

from app.models import EvidenceRecord, SecurityEvent, build_evidence, format_evidence_id
from tests.evidence_factory import make_event


def test_format_evidence_id_is_zero_padded() -> None:
    assert format_evidence_id(0) == "ev-000000"
    assert format_evidence_id(42) == "ev-000042"
    assert format_evidence_id(1234567) == "ev-1234567"


def test_build_evidence_numbers_records_in_order() -> None:
    events = [make_event(user="alpha"), make_event(user="beta")]

    records = build_evidence(events)

    assert [record.evidence_id for record in records] == ["ev-000000", "ev-000001"]
    assert [record.order for record in records] == [0, 1]
    assert [record.normalized_event.user for record in records] == ["alpha", "beta"]


def test_build_evidence_honours_start_offset() -> None:
    records = build_evidence([make_event()], start=7)

    assert records[0].evidence_id == "ev-000007"
    assert records[0].order == 7


def test_build_evidence_of_nothing_is_empty() -> None:
    assert build_evidence([]) == []


def test_order_is_optional() -> None:
    record = EvidenceRecord(
        evidence_id="ev-000000", normalized_event=make_event(), order=None
    )

    assert record.order is None


def test_evidence_reaches_the_original_raw_event() -> None:
    raw = {"_time": "2018-08-20T13:01:46Z", "eventName": "DescribeInstances"}

    record = build_evidence([make_event(raw_event=raw)])[0]

    assert record.normalized_event.raw_event == raw


def test_evidence_carries_no_judgement_fields() -> None:
    # Guards requirement 7: evidence adds provenance only, never verdicts or labels.
    assert set(EvidenceRecord.model_fields) == {
        "evidence_id",
        "normalized_event",
        "order",
    }


def test_security_event_contract_is_unchanged() -> None:
    assert set(SecurityEvent.model_fields) == {
        "timestamp",
        "source",
        "sourcetype",
        "host",
        "user",
        "src_ip",
        "dest_ip",
        "event_name",
        "severity",
        "raw_event",
    }
