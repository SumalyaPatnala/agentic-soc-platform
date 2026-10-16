"""Tests for evidence timeline ordering, summarizing, filtering, and rendering.

Events are built by ``tests.evidence_factory`` and are not BOTS v3 evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.investigation.timeline import (
    MAX_LISTED_VALUES,
    EvidenceFilter,
    MixedTimezoneError,
    apply_filter,
    is_aware,
    load_evidence,
    parse_timezone,
    partition_by_awareness,
    render_summary,
    render_timeline,
    resolve_ordering_timestamps,
    sort_events,
    sort_evidence,
    summarize,
)
from app.models import EvidenceRecord
from tests.evidence_factory import make_evidence, make_event, write_normalized_jsonl

AWARE_EARLY = "2018-08-20T13:00:00+00:00"
AWARE_LATE = "2018-08-20T15:00:00+00:00"
NAIVE_EARLY = "2018-08-20T13:00:00"
NAIVE_LATE = "2018-08-20T15:00:00"


def test_sort_events_orders_by_timestamp() -> None:
    events = [
        make_event(timestamp=AWARE_LATE, event_name="third"),
        make_event(timestamp=AWARE_EARLY, event_name="first"),
        make_event(timestamp="2018-08-20T14:00:00+00:00", event_name="second"),
    ]

    assert [event.event_name for event in sort_events(events)] == [
        "first",
        "second",
        "third",
    ]


def test_sort_events_is_stable_for_equal_timestamps() -> None:
    events = [
        make_event(timestamp=AWARE_EARLY, event_name="a"),
        make_event(timestamp=AWARE_EARLY, event_name="b"),
        make_event(timestamp=AWARE_EARLY, event_name="c"),
    ]

    assert [event.event_name for event in sort_events(events)] == ["a", "b", "c"]


def test_sort_evidence_breaks_ties_on_source_order() -> None:
    records = make_evidence(
        make_event(timestamp=AWARE_EARLY, event_name="a"),
        make_event(timestamp=AWARE_EARLY, event_name="b"),
        make_event(timestamp=AWARE_EARLY, event_name="c"),
    )

    # Shuffling the input must not change the output, because `order` decides ties.
    shuffled = [records[2], records[0], records[1]]

    assert [record.evidence_id for record in sort_evidence(shuffled)] == [
        "ev-000000",
        "ev-000001",
        "ev-000002",
    ]


def test_records_without_order_sort_first_within_a_tie() -> None:
    known = EvidenceRecord(
        evidence_id="ev-000000",
        normalized_event=make_event(timestamp=AWARE_EARLY, event_name="known"),
        order=0,
    )
    unknown = EvidenceRecord(
        evidence_id="ev-unknown",
        normalized_event=make_event(timestamp=AWARE_EARLY, event_name="unknown"),
        order=None,
    )

    ordered = sort_evidence([known, unknown])

    assert [record.evidence_id for record in ordered] == ["ev-unknown", "ev-000000"]


def test_all_naive_timestamps_sort_without_a_timezone() -> None:
    records = make_evidence(
        make_event(timestamp=NAIVE_LATE, event_name="second"),
        make_event(timestamp=NAIVE_EARLY, event_name="first"),
    )

    ordered = sort_evidence(records)

    assert [r.normalized_event.event_name for r in ordered] == ["first", "second"]


def test_differing_offsets_are_compared_as_absolute_instants() -> None:
    records = make_evidence(
        # 13:00-07:00 is 20:00Z, so it is the later of the two.
        make_event(timestamp="2018-08-20T13:00:00-07:00", event_name="later"),
        make_event(timestamp="2018-08-20T19:00:00+00:00", event_name="earlier"),
    )

    ordered = sort_evidence(records)

    assert [r.normalized_event.event_name for r in ordered] == ["earlier", "later"]


def test_mixed_awareness_refuses_to_sort() -> None:
    records = make_evidence(
        make_event(timestamp=AWARE_EARLY), make_event(timestamp=NAIVE_LATE)
    )

    with pytest.raises(MixedTimezoneError, match="cannot order 1 timezone-aware and 1 naive"):
        sort_evidence(records)


def test_mixed_awareness_sorts_once_a_timezone_is_stated() -> None:
    records = make_evidence(
        make_event(timestamp="2018-08-20T15:00:00+00:00", event_name="second"),
        make_event(timestamp="2018-08-20T13:00:00", event_name="first"),
    )

    ordered = sort_evidence(records, assume_timezone=timezone.utc)

    assert [r.normalized_event.event_name for r in ordered] == ["first", "second"]


def test_assumed_timezone_changes_ordering_not_stored_timestamps() -> None:
    records = make_evidence(make_event(timestamp=NAIVE_EARLY))

    ordered = sort_evidence(records, assume_timezone=timezone.utc)

    # The naive value is used for comparison only; the event is left as it was read.
    assert ordered[0].normalized_event.timestamp == datetime(2018, 8, 20, 13, 0)
    assert ordered[0].normalized_event.timestamp.tzinfo is None


def test_assumed_offset_is_applied_to_naive_values() -> None:
    records = make_evidence(
        # Naive 13:00 read as -07:00 is 20:00Z, later than the aware 19:00Z event.
        make_event(timestamp=NAIVE_EARLY, event_name="later"),
        make_event(timestamp="2018-08-20T19:00:00+00:00", event_name="earlier"),
    )

    ordered = sort_evidence(records, assume_timezone=parse_timezone("-07:00"))

    assert [r.normalized_event.event_name for r in ordered] == ["earlier", "later"]


def test_resolve_ordering_timestamps_preserves_input_order() -> None:
    records = make_evidence(
        make_event(timestamp=AWARE_LATE), make_event(timestamp=AWARE_EARLY)
    )

    resolved = resolve_ordering_timestamps(records)

    assert resolved == [
        datetime(2018, 8, 20, 15, 0, tzinfo=timezone.utc),
        datetime(2018, 8, 20, 13, 0, tzinfo=timezone.utc),
    ]


def test_sorting_nothing_yields_nothing() -> None:
    assert sort_evidence([]) == []
    assert sort_events([]) == []


def test_is_aware() -> None:
    assert is_aware(datetime(2018, 8, 20, tzinfo=timezone.utc))
    assert not is_aware(datetime(2018, 8, 20))


def test_partition_by_awareness() -> None:
    records = make_evidence(
        make_event(timestamp=AWARE_EARLY, event_name="aware"),
        make_event(timestamp=NAIVE_EARLY, event_name="naive"),
    )

    aware, naive = partition_by_awareness(records)

    assert [r.normalized_event.event_name for r in aware] == ["aware"]
    assert [r.normalized_event.event_name for r in naive] == ["naive"]


@pytest.mark.parametrize("value", ["UTC", "utc", "Z", "+00:00"])
def test_parse_timezone_accepts_utc_spellings(value: str) -> None:
    resolved = parse_timezone(value)

    assert resolved.utcoffset(datetime(2018, 8, 20)) == timezone.utc.utcoffset(None)


def test_parse_timezone_accepts_an_offset() -> None:
    resolved = parse_timezone("-07:00")

    assert resolved.utcoffset(datetime(2018, 8, 20)).total_seconds() == -25200


def test_parse_timezone_accepts_an_iana_name() -> None:
    resolved = parse_timezone("America/Los_Angeles")

    # August is daylight saving time in Los Angeles, hence -07:00.
    assert resolved.utcoffset(datetime(2018, 8, 20)).total_seconds() == -25200


@pytest.mark.parametrize("value", ["Mars/Olympus", "nonsense", "+99:99"])
def test_parse_timezone_rejects_unknown_zones(value: str) -> None:
    with pytest.raises(ValueError):
        parse_timezone(value)


def test_summarize_reports_counts_and_inventories() -> None:
    ordered = sort_evidence(
        make_evidence(
            make_event(timestamp=AWARE_EARLY, user="alpha", host="wks01", src_ip="203.0.113.25"),
            make_event(timestamp=AWARE_LATE, user="beta", host="wks01", dest_ip="10.0.1.42"),
        )
    )

    summary = summarize(ordered)

    assert summary.total == 2
    assert summary.earliest == datetime(2018, 8, 20, 13, 0, tzinfo=timezone.utc)
    assert summary.latest == datetime(2018, 8, 20, 15, 0, tzinfo=timezone.utc)
    assert summary.users == ("alpha", "beta")
    assert summary.hosts == ("wks01",)
    assert summary.src_ips == ("203.0.113.25",)
    assert summary.dest_ips == ("10.0.1.42",)


def test_summarize_of_nothing_has_no_bounds() -> None:
    summary = summarize([])

    assert summary.total == 0
    assert summary.earliest is None
    assert summary.latest is None
    assert summary.users == ()


def test_summarize_keeps_naive_bounds_naive() -> None:
    ordered = sort_evidence(
        make_evidence(
            make_event(timestamp=NAIVE_EARLY), make_event(timestamp=NAIVE_LATE)
        )
    )

    summary = summarize(ordered)

    assert summary.earliest == datetime(2018, 8, 20, 13, 0)
    assert summary.latest == datetime(2018, 8, 20, 15, 0)


def test_empty_filter_matches_everything() -> None:
    records = make_evidence(make_event(user="alpha"), make_event(user=None))

    assert EvidenceFilter().is_empty
    assert apply_filter(records, EvidenceFilter()) == records


def test_filter_matches_exactly() -> None:
    records = make_evidence(
        make_event(user="alpha", event_name="keep"),
        make_event(user="alphabet", event_name="drop"),
    )

    selected = apply_filter(records, EvidenceFilter(user="alpha"))

    assert [r.normalized_event.event_name for r in selected] == ["keep"]


def test_filters_combine_with_and() -> None:
    records = make_evidence(
        make_event(user="alpha", host="wks01", event_name="keep"),
        make_event(user="alpha", host="wks02", event_name="drop"),
        make_event(user="beta", host="wks01", event_name="drop"),
    )

    selected = apply_filter(records, EvidenceFilter(user="alpha", host="wks01"))

    assert [r.normalized_event.event_name for r in selected] == ["keep"]


def test_records_missing_the_filtered_field_never_match() -> None:
    records = make_evidence(make_event(user=None, host="wks01"))

    assert apply_filter(records, EvidenceFilter(user="alpha")) == []


def test_filter_on_src_and_dest_ip() -> None:
    records = make_evidence(
        make_event(src_ip="203.0.113.25", dest_ip="10.0.1.42", event_name="keep"),
        make_event(src_ip="203.0.113.25", dest_ip="10.0.1.43", event_name="drop"),
    )

    selected = apply_filter(
        records, EvidenceFilter(src_ip="203.0.113.25", dest_ip="10.0.1.42")
    )

    assert [r.normalized_event.event_name for r in selected] == ["keep"]


def test_render_timeline_leads_with_provenance() -> None:
    records = make_evidence(
        make_event(timestamp=AWARE_EARLY, user="alpha", src_ip="203.0.113.25")
    )

    rows = render_timeline(sort_evidence(records))

    assert len(rows) == 1
    assert rows[0].startswith("2018-08-20T13:00:00+00:00  ev-000000  ")
    assert "aws:cloudtrail" in rows[0]
    assert "DescribeInstances" in rows[0]
    assert "user=alpha" in rows[0]
    assert "src=203.0.113.25" in rows[0]


def test_render_timeline_omits_unset_identifiers() -> None:
    rows = render_timeline(make_evidence(make_event(user="alpha")))

    assert "user=alpha" in rows[0]
    assert "host=" not in rows[0]
    assert "dest=" not in rows[0]


def test_render_timeline_displays_vendor_severity_verbatim() -> None:
    # Severity is copied from the event; nothing here grades or assigns it.
    rows = render_timeline(make_evidence(make_event(severity="2.0")))

    assert "severity=2.0" in rows[0]


def test_render_timeline_aligns_columns() -> None:
    records = make_evidence(
        make_event(sourcetype="aws:cloudtrail", event_name="a"),
        make_event(
            sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            event_name="b",
        ),
    )

    rows = render_timeline(sort_evidence(records))

    assert rows[0].index("ev-000000") == rows[1].index("ev-000001")


def test_render_timeline_of_nothing_is_empty() -> None:
    assert render_timeline([]) == []


def test_render_summary_lines() -> None:
    ordered = sort_evidence(make_evidence(make_event(timestamp=AWARE_EARLY, user="alpha")))

    lines = render_summary(summarize(ordered))

    assert lines[0] == "total events: 1"
    assert lines[1] == "earliest timestamp: 2018-08-20T13:00:00+00:00"
    assert lines[2] == "latest timestamp: 2018-08-20T13:00:00+00:00"
    assert lines[3] == "unique users: 1 (alpha)"
    assert lines[4] == "unique hosts: 0"


def test_render_summary_truncates_long_inventories() -> None:
    count = MAX_LISTED_VALUES + 3
    records = make_evidence(*(make_event(user=f"user{n:02d}") for n in range(count)))

    lines = render_summary(summarize(sort_evidence(records)))

    assert f"unique users: {count} (" in lines[3]
    assert "+3 more" in lines[3]


def test_render_summary_of_nothing() -> None:
    lines = render_summary(summarize([]))

    assert lines[0] == "total events: 0"
    assert lines[1] == "earliest timestamp: -"


def test_load_evidence_maps_ids_to_source_lines(tmp_path: Path) -> None:
    path = write_normalized_jsonl(
        tmp_path / "normalized.jsonl",
        [make_event(user="alpha"), make_event(user="beta")],
    )

    records, failures = load_evidence(path)

    assert failures == []
    assert [record.evidence_id for record in records] == ["ev-000000", "ev-000001"]
    assert [record.order for record in records] == [0, 1]
    assert records[1].normalized_event.user == "beta"


def test_load_evidence_preserves_raw_event(tmp_path: Path) -> None:
    raw = {"_time": "2018-08-20T13:00:00Z", "eventName": "DescribeInstances"}
    path = write_normalized_jsonl(
        tmp_path / "normalized.jsonl", [make_event(raw_event=raw)]
    )

    records, _ = load_evidence(path)

    assert records[0].normalized_event.raw_event == raw


def test_load_evidence_reports_bad_lines_without_dropping_good_ones(
    tmp_path: Path,
) -> None:
    path = tmp_path / "normalized.jsonl"
    good = make_event(user="alpha").model_dump_json()
    path.write_text(
        f"{good}\nnot json\n[1, 2]\n{{\"source\": \"x\"}}\n", encoding="utf-8"
    )

    records, failures = load_evidence(path)

    assert [record.evidence_id for record in records] == ["ev-000000"]
    assert [failure.index for failure in failures] == [2, 3, 4]
    assert "malformed JSON" in failures[0].reason
    assert "expected a JSON object" in failures[1].reason
    assert "not a normalized SecurityEvent" in failures[2].reason


def test_load_evidence_skips_blank_lines_but_keeps_line_numbering(
    tmp_path: Path,
) -> None:
    path = tmp_path / "normalized.jsonl"
    path.write_text(
        f"\n{make_event(user='alpha').model_dump_json()}\n", encoding="utf-8"
    )

    records, failures = load_evidence(path)

    assert failures == []
    # The event is on line 2, so its id points at line 2 rather than line 1.
    assert records[0].evidence_id == "ev-000001"
    assert records[0].order == 1


def test_load_evidence_of_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "normalized.jsonl"
    path.write_text("", encoding="utf-8")

    assert load_evidence(path) == ([], [])
