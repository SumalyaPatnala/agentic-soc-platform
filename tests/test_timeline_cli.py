"""Tests for the `python -m app.investigation.timeline` CLI.

Events are built by ``tests.evidence_factory`` and are not BOTS v3 evidence.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.investigation.timeline import main
from tests.evidence_factory import make_event, write_normalized_jsonl

AWARE_EARLY = "2018-08-20T13:00:00+00:00"
AWARE_MID = "2018-08-20T14:00:00+00:00"
AWARE_LATE = "2018-08-20T15:00:00+00:00"


@pytest.fixture
def export(tmp_path: Path) -> Path:
    return write_normalized_jsonl(
        tmp_path / "normalized.jsonl",
        [
            make_event(
                timestamp=AWARE_LATE,
                user="beta",
                host="wks02",
                src_ip="203.0.113.26",
                event_name="DescribeVolumes",
            ),
            make_event(
                timestamp=AWARE_EARLY,
                user="alpha",
                host="wks01",
                src_ip="203.0.113.25",
                event_name="DescribeInstances",
            ),
            make_event(
                timestamp=AWARE_MID,
                user="alpha",
                host="wks01",
                dest_ip="10.0.1.42",
                event_name="ListBuckets",
            ),
        ],
    )


def test_prints_summary_then_chronological_timeline(
    export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main([str(export)])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "total events: 3" in out
    assert f"earliest timestamp: {AWARE_EARLY}" in out
    assert f"latest timestamp: {AWARE_LATE}" in out
    assert "unique users: 2 (alpha, beta)" in out
    assert "unique hosts: 2 (wks01, wks02)" in out
    assert "unique source IPs: 2 (203.0.113.25, 203.0.113.26)" in out
    assert "unique destination IPs: 1 (10.0.1.42)" in out

    timeline = out.split("timeline:\n")[1].strip().splitlines()
    assert [row.split()[3] for row in timeline] == [
        "DescribeInstances",
        "ListBuckets",
        "DescribeVolumes",
    ]


def test_every_row_carries_its_evidence_id(
    export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main([str(export)])
    timeline = capsys.readouterr().out.split("timeline:\n")[1].strip().splitlines()

    # ev-000001 is line 2 of the export, which is the earliest event.
    assert timeline[0].split()[1] == "ev-000001"
    assert {row.split()[1] for row in timeline} == {
        "ev-000000",
        "ev-000001",
        "ev-000002",
    }


def test_user_filter(export: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main([str(export), "--user", "alpha"])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "filtered 3 loaded events down to 2" in out
    assert "total events: 2" in out
    assert "unique users: 1 (alpha)" in out
    assert "DescribeVolumes" not in out


def test_host_filter(export: Path, capsys: pytest.CaptureFixture[str]) -> None:
    main([str(export), "--host", "wks02"])
    out = capsys.readouterr().out

    assert "total events: 1" in out
    assert "DescribeVolumes" in out


def test_src_ip_filter(export: Path, capsys: pytest.CaptureFixture[str]) -> None:
    main([str(export), "--src-ip", "203.0.113.25"])
    out = capsys.readouterr().out

    assert "total events: 1" in out
    assert "DescribeInstances" in out


def test_dest_ip_filter(export: Path, capsys: pytest.CaptureFixture[str]) -> None:
    main([str(export), "--dest-ip", "10.0.1.42"])
    out = capsys.readouterr().out

    assert "total events: 1" in out
    assert "ListBuckets" in out


def test_filters_combine(export: Path, capsys: pytest.CaptureFixture[str]) -> None:
    main([str(export), "--user", "alpha", "--host", "wks02"])
    out = capsys.readouterr().out

    assert "filtered 3 loaded events down to 0" in out
    assert "total events: 0" in out
    assert "earliest timestamp: -" in out


def test_no_filter_message_when_no_filters_given(
    export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main([str(export)])

    assert "filtered" not in capsys.readouterr().out


def test_bad_line_is_reported_and_exit_code_is_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "normalized.jsonl"
    path.write_text(
        f"{make_event(user='alpha').model_dump_json()}\nnot json\n", encoding="utf-8"
    )

    exit_code = main([str(path)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "line 2: malformed JSON" in captured.err
    assert "total events: 1" in captured.out


def test_missing_file_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main([str(tmp_path / "absent.jsonl")])

    assert exit_code == 2
    assert "no such file" in capsys.readouterr().err


def test_directory_exits_two(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main([str(tmp_path)])

    assert exit_code == 2
    assert "is a directory" in capsys.readouterr().err


def test_mixed_timestamps_exit_two_with_a_hint(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_normalized_jsonl(
        tmp_path / "normalized.jsonl",
        [
            make_event(timestamp=AWARE_EARLY),
            make_event(timestamp="2018-08-20T14:00:00"),
        ],
    )

    exit_code = main([str(path)])
    err = capsys.readouterr().err

    assert exit_code == 2
    assert "cannot order" in err
    assert "--assume-timezone UTC" in err


def test_mixed_timestamps_succeed_with_assume_timezone(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_normalized_jsonl(
        tmp_path / "normalized.jsonl",
        [
            make_event(timestamp=AWARE_LATE, event_name="second"),
            make_event(timestamp="2018-08-20T14:00:00", event_name="first"),
        ],
    )

    exit_code = main([str(path), "--assume-timezone", "UTC"])
    out = capsys.readouterr().out

    assert exit_code == 0
    timeline = out.split("timeline:\n")[1].strip().splitlines()
    assert [row.split()[3] for row in timeline] == ["first", "second"]
    # The naive timestamp is still rendered exactly as it was recorded.
    assert "2018-08-20T14:00:00  " in timeline[0]


def test_unknown_timezone_exits_two(
    export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main([str(export), "--assume-timezone", "Mars/Olympus"])

    assert exit_code == 2
    assert "not a recognized timezone" in capsys.readouterr().err


def test_empty_export(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "normalized.jsonl"
    path.write_text("", encoding="utf-8")

    exit_code = main([str(path)])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "total events: 0" in out
    assert out.rstrip().endswith("timeline:")
