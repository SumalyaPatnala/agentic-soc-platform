"""Tests for the `python -m app.ingestion.normalize_file` CLI.

Input payloads are built from the schema-shape fixtures in ``tests.splunk_fixtures``
and are not BOTS v3 evidence.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.ingestion.normalize_file import (
    InputFormatError,
    load_raw_records,
    main,
    normalize_text,
    resolve_output_path,
)
from tests.splunk_fixtures import (
    CLOUDTRAIL_FIXTURE,
    GUARDDUTY_FIXTURE,
    SYSMON_FIXTURE,
)

ALL_FIXTURES = [CLOUDTRAIL_FIXTURE, GUARDDUTY_FIXTURE, SYSMON_FIXTURE]


def _jsonl(*records: dict[str, object]) -> str:
    return "".join(f"{json.dumps(record)}\n" for record in records)


def test_json_lines_input() -> None:
    report = normalize_text(_jsonl(*ALL_FIXTURES))

    assert (report.total, report.normalized, report.failed) == (3, 3, 0)
    assert [event.sourcetype for event in report.events] == [
        "aws:cloudtrail",
        "aws:cloudwatch:guardduty",
        "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    ]


def test_json_array_input() -> None:
    report = normalize_text(json.dumps(ALL_FIXTURES))

    assert (report.total, report.normalized, report.failed) == (3, 3, 0)


def test_single_json_object_input() -> None:
    report = normalize_text(json.dumps(CLOUDTRAIL_FIXTURE))

    assert (report.total, report.normalized, report.failed) == (1, 1, 0)
    assert report.events[0].event_name == "DescribeInstances"


def test_results_envelope_from_search_api() -> None:
    report = normalize_text(json.dumps({"preview": False, "results": ALL_FIXTURES}))

    assert (report.total, report.normalized, report.failed) == (3, 3, 0)


def test_streaming_export_result_wrapper() -> None:
    report = normalize_text(
        _jsonl(
            {"preview": False, "result": CLOUDTRAIL_FIXTURE},
            {"preview": False, "result": GUARDDUTY_FIXTURE},
        )
    )

    assert (report.total, report.normalized, report.failed) == (2, 2, 0)
    assert report.events[0].event_name == "DescribeInstances"


def test_one_malformed_line_does_not_abort_the_import() -> None:
    text = (
        f"{json.dumps(CLOUDTRAIL_FIXTURE)}\n"
        "{ this is not json\n"
        f"{json.dumps(GUARDDUTY_FIXTURE)}\n"
    )

    report = normalize_text(text)

    assert (report.total, report.normalized, report.failed) == (3, 2, 1)
    assert report.failures[0].index == 2
    assert "malformed JSON" in report.failures[0].reason


def test_unnormalizable_record_is_counted_as_failed() -> None:
    without_timestamp = {
        key: value
        for key, value in CLOUDTRAIL_FIXTURE.items()
        if key not in {"_time", "eventTime"}
    }

    report = normalize_text(_jsonl(CLOUDTRAIL_FIXTURE, without_timestamp))

    assert (report.total, report.normalized, report.failed) == (2, 1, 1)
    assert "required field 'timestamp'" in report.failures[0].reason


def test_non_object_record_is_counted_as_failed() -> None:
    report = normalize_text(json.dumps([CLOUDTRAIL_FIXTURE, "not-an-object"]))

    assert (report.total, report.normalized, report.failed) == (2, 1, 1)
    assert "expected a JSON object" in report.failures[0].reason


def test_empty_file_yields_empty_report() -> None:
    report = normalize_text("   \n\n")

    assert (report.total, report.normalized, report.failed) == (0, 0, 0)


def test_blank_lines_are_skipped() -> None:
    report = normalize_text(f"\n{json.dumps(CLOUDTRAIL_FIXTURE)}\n\n")

    assert (report.total, report.normalized, report.failed) == (1, 1, 0)


def test_broken_pretty_printed_json_raises_input_format_error() -> None:
    text = '[\n  {"_time": "2018-08-20T13:01:46Z",\n   "source": \n]'

    with pytest.raises(InputFormatError, match="neither valid JSON nor valid JSON Lines"):
        load_raw_records(text)


def test_top_level_scalar_raises_input_format_error() -> None:
    with pytest.raises(InputFormatError, match="expected a JSON object or array"):
        load_raw_records("42")


@pytest.mark.parametrize(
    ("out", "expected"),
    [
        (Path("data/normalized"), Path("data/normalized/export.normalized.jsonl")),
        (Path("out/events.jsonl"), Path("out/events.jsonl")),
    ],
    ids=["directory", "explicit-file"],
)
def test_resolve_output_path(out: Path, expected: Path) -> None:
    assert resolve_output_path(out, Path("/tmp/export.json")) == expected


def test_main_reports_summary_and_writes_jsonl(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "export.json"
    source.write_text(_jsonl(*ALL_FIXTURES), encoding="utf-8")
    out_dir = tmp_path / "normalized"

    exit_code = main([str(source), "--out", str(out_dir)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "total: 3" in captured.out
    assert "normalized: 3" in captured.out
    assert "failed: 0" in captured.out

    destination = out_dir / "export.normalized.jsonl"
    lines = destination.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 3
    assert json.loads(lines[0])["event_name"] == "DescribeInstances"


def test_main_returns_one_when_records_fail(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "export.jsonl"
    source.write_text(
        f"{json.dumps(CLOUDTRAIL_FIXTURE)}\nnot json\n", encoding="utf-8"
    )

    exit_code = main([str(source)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "failed: 1" in captured.out
    assert "record 2: malformed JSON" in captured.err


def test_main_returns_two_when_file_is_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main([str(tmp_path / "absent.json")])

    assert exit_code == 2
    assert "no such file" in capsys.readouterr().err


def test_main_returns_two_on_unreadable_format(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "broken.json"
    source.write_text('[\n  {"a": \n]', encoding="utf-8")

    exit_code = main([str(source)])

    assert exit_code == 2
    assert "error:" in capsys.readouterr().err


def test_main_without_out_flag_writes_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "export.json"
    source.write_text(json.dumps(CLOUDTRAIL_FIXTURE), encoding="utf-8")

    exit_code = main([str(source)])

    assert exit_code == 0
    assert "wrote" not in capsys.readouterr().out
    assert list(tmp_path.iterdir()) == [source]
