"""Tests for SplunkBOTSEventNormalizer.

The event dictionaries come from ``tests.splunk_fixtures`` and are schema-shape test
fixtures, not BOTS v3 evidence.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from app.ingestion.splunk import (
    NormalizationError,
    SplunkBOTSEventNormalizer,
    parse_timestamp,
)
from tests.splunk_fixtures import (
    CLOUDTRAIL_FIXTURE,
    GUARDDUTY_FIXTURE,
    SYSMON_FIXTURE,
)


@pytest.fixture
def normalizer() -> SplunkBOTSEventNormalizer:
    return SplunkBOTSEventNormalizer()


def test_cloudtrail_shape(normalizer: SplunkBOTSEventNormalizer) -> None:
    event = normalizer.normalize(CLOUDTRAIL_FIXTURE)

    assert event.timestamp == datetime(2018, 8, 20, 13, 1, 46, tzinfo=timezone.utc)
    assert event.sourcetype == "aws:cloudtrail"
    assert event.event_name == "DescribeInstances"
    assert event.user == "example-user"
    assert event.src_ip == "203.0.113.25"
    assert event.host == "111111111111"
    assert event.dest_ip is None
    assert event.severity is None


def test_guardduty_shape(normalizer: SplunkBOTSEventNormalizer) -> None:
    event = normalizer.normalize(GUARDDUTY_FIXTURE)

    assert event.timestamp == datetime(2018, 8, 20, 13, 1, 46, tzinfo=timezone.utc)
    assert event.sourcetype == "aws:cloudwatch:guardduty"
    # `signature` is the event-name alias GuardDuty rows carry.
    assert event.event_name == "Recon:EC2/PortProbeUnprotectedPort"
    # No `host` field, so the `instance_id` alias is used.
    assert event.host == "i-0example1234abcd"
    assert event.src_ip == "198.51.100.14"
    assert event.dest_ip == "10.0.1.42"
    # Numeric severities are stringified, never graded into a label.
    assert event.severity == "2.0"
    assert event.user is None


def test_sysmon_shape(normalizer: SplunkBOTSEventNormalizer) -> None:
    event = normalizer.normalize(SYSMON_FIXTURE)

    # No UTC offset in the source value, so the timestamp stays naive.
    assert event.timestamp == datetime(2018, 8, 20, 13, 1, 46)
    assert event.timestamp.tzinfo is None
    assert event.host == "EXAMPLE-WKS01.example.local"
    assert event.user == "example.user"
    # `EventCode` is the last-resort event-name alias for Windows telemetry.
    assert event.event_name == "1"
    assert event.src_ip is None


@pytest.mark.parametrize(
    "fixture",
    [CLOUDTRAIL_FIXTURE, GUARDDUTY_FIXTURE, SYSMON_FIXTURE],
    ids=["cloudtrail", "guardduty", "sysmon"],
)
def test_raw_event_preserves_original_payload(
    normalizer: SplunkBOTSEventNormalizer, fixture: dict[str, object]
) -> None:
    event = normalizer.normalize(fixture)

    assert event.raw_event == fixture
    assert event.raw_event is not fixture


def test_nested_user_is_read_via_dotted_path(
    normalizer: SplunkBOTSEventNormalizer,
) -> None:
    payload = {key: value for key, value in CLOUDTRAIL_FIXTURE.items() if key != "userName"}

    event = normalizer.normalize(payload)

    assert event.user == "AIDAEXAMPLEPRINCIPALID"


def test_flattened_dotted_key_is_read_literally(
    normalizer: SplunkBOTSEventNormalizer,
) -> None:
    event = normalizer.normalize(
        {
            "_time": "2018-08-20T13:01:46Z",
            "source": "example",
            "sourcetype": "aws:cloudtrail",
            "eventName": "DescribeInstances",
            "userIdentity.principalId": "AIDAFLATTENEDKEY",
        }
    )

    assert event.user == "AIDAFLATTENEDKEY"


def test_fields_fall_back_to_json_raw(normalizer: SplunkBOTSEventNormalizer) -> None:
    event = normalizer.normalize(
        {
            "_time": "2018-08-20T13:01:46Z",
            "source": "example",
            "sourcetype": "aws:cloudtrail",
            "_raw": json.dumps(
                {"eventName": "DescribeInstances", "sourceIPAddress": "203.0.113.25"}
            ),
        }
    )

    assert event.event_name == "DescribeInstances"
    assert event.src_ip == "203.0.113.25"


def test_extracted_field_wins_over_json_raw(
    normalizer: SplunkBOTSEventNormalizer,
) -> None:
    event = normalizer.normalize(
        {
            "_time": "2018-08-20T13:01:46Z",
            "source": "example",
            "sourcetype": "aws:cloudtrail",
            "eventName": "ExtractedValue",
            "_raw": json.dumps({"eventName": "RawValue"}),
        }
    )

    assert event.event_name == "ExtractedValue"


def test_multivalue_field_takes_first_usable_member(
    normalizer: SplunkBOTSEventNormalizer,
) -> None:
    event = normalizer.normalize(
        {
            "_time": "2018-08-20T13:01:46Z",
            "source": "example",
            "sourcetype": "pan:traffic",
            "action": "allowed",
            "src_ip": ["", "198.51.100.14", "198.51.100.15"],
        }
    )

    assert event.src_ip == "198.51.100.14"


def test_blank_optional_fields_become_none(
    normalizer: SplunkBOTSEventNormalizer,
) -> None:
    event = normalizer.normalize(
        {
            "_time": "2018-08-20T13:01:46Z",
            "source": "example",
            "sourcetype": "pan:traffic",
            "action": "allowed",
            "host": "   ",
            "user": "",
        }
    )

    assert event.host is None
    assert event.user is None


def test_missing_timestamp_raises(normalizer: SplunkBOTSEventNormalizer) -> None:
    payload = {key: value for key, value in CLOUDTRAIL_FIXTURE.items()}
    del payload["_time"]
    del payload["eventTime"]

    with pytest.raises(NormalizationError, match="required field 'timestamp'"):
        normalizer.normalize(payload)


def test_unparseable_timestamp_raises(normalizer: SplunkBOTSEventNormalizer) -> None:
    with pytest.raises(NormalizationError, match="could not parse timestamp"):
        normalizer.normalize({**CLOUDTRAIL_FIXTURE, "_time": "not-a-timestamp"})


def test_missing_event_name_raises(normalizer: SplunkBOTSEventNormalizer) -> None:
    with pytest.raises(NormalizationError, match="required field 'event_name'"):
        normalizer.normalize(
            {
                "_time": "2018-08-20T13:01:46Z",
                "source": "example",
                "sourcetype": "aws:cloudtrail",
            }
        )


def test_missing_sourcetype_raises(normalizer: SplunkBOTSEventNormalizer) -> None:
    with pytest.raises(NormalizationError, match="required field 'sourcetype'"):
        normalizer.normalize(
            {
                "_time": "2018-08-20T13:01:46Z",
                "source": "example",
                "eventName": "DescribeInstances",
            }
        )


def test_non_mapping_input_raises(normalizer: SplunkBOTSEventNormalizer) -> None:
    with pytest.raises(NormalizationError, match="expected a JSON object"):
        normalizer.normalize(["not", "an", "object"])  # type: ignore[arg-type]


def test_epoch_string_is_parsed_as_utc() -> None:
    assert parse_timestamp("1534770106.000") == datetime(
        2018, 8, 20, 13, 1, 46, tzinfo=timezone.utc
    )


def test_short_numeric_string_is_not_treated_as_epoch() -> None:
    # "2018" must not silently become 1970-01-01T00:33:38Z.
    with pytest.raises(NormalizationError, match="could not parse timestamp"):
        parse_timestamp("2018")


def test_boolean_is_not_a_timestamp() -> None:
    with pytest.raises(NormalizationError, match="is not a timestamp"):
        parse_timestamp(True)


def test_out_of_range_epoch_raises() -> None:
    with pytest.raises(NormalizationError, match="out of range"):
        parse_timestamp(1e20)
