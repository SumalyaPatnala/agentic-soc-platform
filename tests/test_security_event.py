"""Tests for the SecurityEvent model."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.models import SecurityEvent


def test_valid_event_with_all_fields() -> None:
    event = SecurityEvent(
        timestamp=datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc),
        source="botsv3",
        sourcetype="aws:cloudtrail",
        host="ip-10-0-1-42",
        user="bstoll",
        src_ip="203.0.113.10",
        dest_ip="10.0.1.42",
        event_name="ConsoleLogin",
        severity="high",
        raw_event={"eventSource": "signin.amazonaws.com", "errorMessage": "Failed"},
    )

    assert event.sourcetype == "aws:cloudtrail"
    assert event.severity == "high"
    assert event.raw_event["eventSource"] == "signin.amazonaws.com"


def test_optional_fields_default_to_none() -> None:
    event = SecurityEvent(
        timestamp=datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc),
        source="okta",
        sourcetype="okta:system",
        event_name="user.session.start",
    )

    assert event.host is None
    assert event.user is None
    assert event.src_ip is None
    assert event.dest_ip is None
    assert event.severity is None
    assert event.raw_event == {}


def test_iso8601_timestamp_string_is_parsed() -> None:
    event = SecurityEvent(
        timestamp="2026-09-29T12:00:00Z",
        source="crowdstrike",
        sourcetype="crowdstrike:falcon:detection",
        event_name="ProcessRollup2",
    )

    assert event.timestamp == datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)


def test_invalid_timestamp_raises_validation_error() -> None:
    with pytest.raises(ValidationError) as exc_info:
        SecurityEvent(
            timestamp="not-a-timestamp",
            source="firewall",
            sourcetype="pan:traffic",
            event_name="deny",
        )

    assert exc_info.value.error_count() == 1
    assert exc_info.value.errors()[0]["loc"] == ("timestamp",)


def test_missing_required_field_raises_validation_error() -> None:
    with pytest.raises(ValidationError):
        SecurityEvent(source="guardduty", sourcetype="aws:guardduty", event_name="Recon")
