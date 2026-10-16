"""Tests for the BOTS v3 pipeline validation report.

These are schema-level tooling tests built from ``tests.splunk_fixtures``. They verify
that the report counts and provenance checks behave correctly; they are NOT real BOTS
v3 validation, and the report itself refuses to claim otherwise for any file outside
``data/botsv3/raw/``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.ingestion.normalize_file import main as normalize_main
from app.services.validation import (
    build_report,
    count_sourcetypes,
    describe_source,
    digest_file,
    is_documented_raw_location,
    main,
    render_report,
    verify_evidence_line_mapping,
)
from tests.evidence_factory import make_event, write_normalized_jsonl
from tests.splunk_fixtures import (
    CLOUDTRAIL_FIXTURE,
    GUARDDUTY_FIXTURE,
    SYSMON_FIXTURE,
)


def _write_raw(path: Path, records: list[dict[str, object]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(f"{json.dumps(record)}\n" for record in records), encoding="utf-8"
    )
    return path


@pytest.fixture
def pipeline(tmp_path: Path) -> tuple[Path, Path]:
    """Run the two documented commands over aware-timestamp records."""
    raw = _write_raw(
        tmp_path / "export.json", [CLOUDTRAIL_FIXTURE, GUARDDUTY_FIXTURE]
    )
    normalized = tmp_path / "export.jsonl"
    assert normalize_main([str(raw), "-o", str(normalized)]) == 0
    return raw, normalized


def test_digest_file_matches_hashlib(tmp_path: Path) -> None:
    import hashlib

    path = tmp_path / "blob.bin"
    path.write_bytes(b"real bots v3 bytes")

    assert digest_file(path) == hashlib.sha256(b"real bots v3 bytes").hexdigest()


def test_documented_location_detection(tmp_path: Path) -> None:
    real = tmp_path / "data" / "botsv3" / "raw" / "real_export_001.json"
    real.parent.mkdir(parents=True)
    real.write_text("{}", encoding="utf-8")

    elsewhere = tmp_path / "real_export_001.json"
    elsewhere.write_text("{}", encoding="utf-8")

    assert is_documented_raw_location(real)
    assert not is_documented_raw_location(elsewhere)


def test_describe_source_records_the_exact_bytes(tmp_path: Path) -> None:
    path = tmp_path / "export.json"
    path.write_text("{}", encoding="utf-8")

    source = describe_source(path)

    assert source.path == path.resolve()
    assert source.sha256 == digest_file(path)
    assert source.size_bytes == 2
    assert source.is_documented_location is False


def test_count_sourcetypes_orders_by_frequency_then_name() -> None:
    from tests.evidence_factory import make_evidence

    records = make_evidence(
        make_event(sourcetype="aws:cloudtrail"),
        make_event(sourcetype="aws:cloudtrail"),
        make_event(sourcetype="zeta"),
        make_event(sourcetype="alpha"),
    )

    assert count_sourcetypes(records) == {"aws:cloudtrail": 2, "alpha": 1, "zeta": 1}


def test_count_sourcetypes_of_nothing() -> None:
    assert count_sourcetypes([]) == {}


def test_report_counts_a_clean_run(pipeline: tuple[Path, Path]) -> None:
    raw, normalized = pipeline

    report = build_report(raw, normalized)

    assert report.total_raw_records == 2
    assert report.total_normalized == 2
    assert report.failed_normalization == 0
    assert report.load_failures == ()
    assert report.sourcetype_counts == {
        "aws:cloudtrail": 1,
        "aws:cloudwatch:guardduty": 1,
    }
    assert report.summary.total == 2
    assert report.is_clean


def test_report_provenance_checks_all_pass(pipeline: tuple[Path, Path]) -> None:
    raw, normalized = pipeline

    checks = build_report(raw, normalized).provenance

    assert checks.raw_unchanged
    assert checks.disk_matches_memory
    assert checks.records_with_raw_event == 2
    assert checks.evidence_lines_verified == 2
    assert checks.all_passed


def test_report_leaves_the_raw_export_untouched(pipeline: tuple[Path, Path]) -> None:
    raw, normalized = pipeline
    before = digest_file(raw)

    build_report(raw, normalized)

    assert digest_file(raw) == before


def test_report_counts_normalization_failures(tmp_path: Path) -> None:
    without_timestamp = {
        key: value
        for key, value in CLOUDTRAIL_FIXTURE.items()
        if key not in {"_time", "eventTime"}
    }
    raw = _write_raw(tmp_path / "export.json", [CLOUDTRAIL_FIXTURE, without_timestamp])
    normalized = tmp_path / "export.jsonl"
    assert normalize_main([str(raw), "-o", str(normalized)]) == 1

    report = build_report(raw, normalized)

    assert report.total_raw_records == 2
    assert report.total_normalized == 1
    assert report.failed_normalization == 1
    assert "required field 'timestamp'" in report.failures[0].reason
    assert not report.is_clean


def test_report_detects_a_tampered_normalized_file(
    pipeline: tuple[Path, Path],
) -> None:
    raw, normalized = pipeline
    lines = normalized.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["user"] = "someone-else"
    normalized.write_text(
        f"{json.dumps(tampered)}\n{lines[1]}\n", encoding="utf-8"
    )

    report = build_report(raw, normalized)

    # The JSONL no longer matches what re-normalizing the raw export produces.
    assert not report.provenance.disk_matches_memory
    assert report.provenance.evidence_lines_verified == 2  # each line still self-maps
    assert not report.is_clean


def test_report_detects_a_dropped_raw_event(tmp_path: Path) -> None:
    raw = _write_raw(tmp_path / "export.json", [CLOUDTRAIL_FIXTURE])
    normalized = write_normalized_jsonl(
        tmp_path / "export.jsonl", [make_event(raw_event={})]
    )

    checks = build_report(raw, normalized).provenance

    assert checks.records_with_raw_event == 0
    assert not checks.all_passed


def test_verify_evidence_line_mapping_rejects_reordered_lines(
    tmp_path: Path,
) -> None:
    from app.investigation.timeline import load_evidence

    normalized = write_normalized_jsonl(
        tmp_path / "export.jsonl",
        [make_event(user="alpha"), make_event(user="beta")],
    )
    records, _ = load_evidence(normalized)

    # Swap the file's lines under the already-loaded records.
    lines = normalized.read_text(encoding="utf-8").splitlines()
    normalized.write_text(f"{lines[1]}\n{lines[0]}\n", encoding="utf-8")

    assert verify_evidence_line_mapping(records, normalized) == 0


def test_report_flags_an_undocumented_source_location(
    pipeline: tuple[Path, Path],
) -> None:
    raw, normalized = pipeline

    lines = render_report(build_report(raw, normalized))

    assert lines[0] == "BOTS v3 PIPELINE VALIDATION -- UNVERIFIED SOURCE LOCATION"
    assert any("NOT a verified real BOTS v3 export" in line for line in lines)
    assert any("NOT as real-data validation" in line for line in lines)


def test_report_claims_real_data_only_from_the_documented_location(
    tmp_path: Path,
) -> None:
    raw = _write_raw(
        tmp_path / "data" / "botsv3" / "raw" / "real_export_001.json",
        [CLOUDTRAIL_FIXTURE],
    )
    normalized = tmp_path / "data" / "normalized" / "real_export_001.jsonl"
    normalized.parent.mkdir(parents=True)
    assert normalize_main([str(raw), "-o", str(normalized)]) == 0

    lines = render_report(build_report(raw, normalized))

    assert lines[0] == "REAL BOTS v3 EXPORT VALIDATION"
    assert any(
        "source classification: REAL Splunk BOTS v3 export" in line for line in lines
    )


def test_rendered_report_contains_every_required_field(
    pipeline: tuple[Path, Path],
) -> None:
    raw, normalized = pipeline

    text = "\n".join(render_report(build_report(raw, normalized)))

    for expected in (
        "total raw records:",
        "total normalized records:",
        "failed normalization count:",
        "sourcetypes present:",
        "earliest timestamp:",
        "latest timestamp:",
        "unique users:",
        "unique hosts:",
        "unique source IPs:",
        "unique destination IPs:",
        "raw export unchanged after processing:",
        "records retaining raw_event:",
        "evidence ids map to normalized lines:",
    ):
        assert expected in text, expected

    assert "sha256:" in text
    assert "no classification, severity grading, risk scoring, or framework mapping" in text


def test_main_exit_zero_on_clean_run(
    pipeline: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    raw, normalized = pipeline

    exit_code = main(["--raw", str(raw), "--normalized", str(normalized)])

    assert exit_code == 0
    assert "total raw records:          2" in capsys.readouterr().out


def test_main_exit_one_when_records_failed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    raw = _write_raw(tmp_path / "export.json", [CLOUDTRAIL_FIXTURE, {"source": "x"}])
    normalized = tmp_path / "export.jsonl"
    normalize_main([str(raw), "-o", str(normalized)])

    exit_code = main(["--raw", str(raw), "--normalized", str(normalized)])

    assert exit_code == 1
    assert "failed normalization count: 1" in capsys.readouterr().out


def test_main_exit_two_on_missing_raw_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(
        ["--raw", str(tmp_path / "absent.json"), "--normalized", str(tmp_path / "a.jsonl")]
    )

    assert exit_code == 2
    assert "no such file" in capsys.readouterr().err


def test_main_exit_two_on_mixed_timestamps_then_succeeds_when_stated(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # CloudTrail carries an offset, the Sysmon shape does not: the real BOTS v3 mix.
    raw = _write_raw(tmp_path / "export.json", [CLOUDTRAIL_FIXTURE, SYSMON_FIXTURE])
    normalized = tmp_path / "export.jsonl"
    normalize_main([str(raw), "-o", str(normalized)])
    args = ["--raw", str(raw), "--normalized", str(normalized)]

    assert main(args) == 2
    err = capsys.readouterr().err
    assert "cannot order" in err
    assert "--assume-timezone UTC" in err

    assert main([*args, "--assume-timezone", "UTC"]) == 0
    assert "total normalized records:   2" in capsys.readouterr().out


def test_main_exit_two_on_unknown_timezone(
    pipeline: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    raw, normalized = pipeline

    exit_code = main(
        [
            "--raw",
            str(raw),
            "--normalized",
            str(normalized),
            "--assume-timezone",
            "Mars/Olympus",
        ]
    )

    assert exit_code == 2
    assert "not a recognized timezone" in capsys.readouterr().err


def test_main_exit_two_on_unparsable_raw_export(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    raw = tmp_path / "export.json"
    raw.write_text('[\n  {"a": \n]', encoding="utf-8")
    normalized = write_normalized_jsonl(tmp_path / "export.jsonl", [make_event()])

    exit_code = main(["--raw", str(raw), "--normalized", str(normalized)])

    assert exit_code == 2
    assert "error:" in capsys.readouterr().err
