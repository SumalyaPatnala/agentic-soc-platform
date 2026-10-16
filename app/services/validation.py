"""Validation report for a real Splunk BOTS v3 export passing through the pipeline.

Usage:
    python -m app.services.validation --raw <raw-export> --normalized <jsonl> [--assume-timezone TZ]

This coordinates the two existing boundaries rather than reimplementing them: it
re-runs ``app.ingestion.normalize_file`` in memory to recover per-record failure
reasons, then cross-checks that result against the normalized JSONL actually written
to disk, then orders the evidence with ``app.investigation.timeline``.

It performs no classification, scoring, or framework mapping. Every value it prints is
either copied from the events or counted from them.

The raw export is opened read-only and its SHA-256 is taken before and after
processing, so the report can state rather than assume that the export was untouched.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from dataclasses import dataclass
from datetime import datetime, tzinfo
from pathlib import Path

from app.ingestion.normalize_file import (
    InputFormatError,
    RecordFailure,
    load_raw_records,
    normalize_records,
)
from app.investigation.correlation import distinct_values
from app.investigation.timeline import (
    MixedTimezoneError,
    TimelineSummary,
    load_evidence,
    parse_timezone,
    render_summary,
    sort_evidence,
    summarize,
)
from app.models import EvidenceRecord, SecurityEvent

#: The documented location for untouched real exports. Anything outside it is flagged.
RAW_EXPORT_DIR_PARTS = ("data", "botsv3", "raw")

_CHUNK_SIZE = 1 << 20


def digest_file(path: Path) -> str:
    """SHA-256 of a file, read in chunks and never modified."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def is_documented_raw_location(path: Path) -> bool:
    """Whether the file sits in ``data/botsv3/raw/``."""
    return path.resolve().parent.parts[-3:] == RAW_EXPORT_DIR_PARTS


@dataclass(frozen=True)
class SourceProvenance:
    """Identity of the raw export, precise enough to be audited later."""

    path: Path
    sha256: str
    size_bytes: int
    modified: datetime
    is_documented_location: bool


def describe_source(path: Path) -> SourceProvenance:
    """Record what exactly was read, so the report cites specific bytes."""
    stat = path.stat()
    return SourceProvenance(
        path=path.resolve(),
        sha256=digest_file(path),
        size_bytes=stat.st_size,
        modified=datetime.fromtimestamp(stat.st_mtime).astimezone(),
        is_documented_location=is_documented_raw_location(path),
    )


@dataclass(frozen=True)
class ProvenanceChecks:
    """Evidence that nothing was lost or mutated between the stages."""

    raw_unchanged: bool
    total_records: int
    records_with_raw_event: int
    disk_matches_memory: bool
    evidence_lines_verified: int

    @property
    def all_passed(self) -> bool:
        return (
            self.raw_unchanged
            and self.disk_matches_memory
            and self.records_with_raw_event == self.total_records
            and self.evidence_lines_verified == self.total_records
        )


def count_sourcetypes(records: list[EvidenceRecord]) -> dict[str, int]:
    """Count events per sourcetype, most frequent first, ties broken by name."""
    counts: dict[str, int] = {}
    for record in records:
        sourcetype = record.normalized_event.sourcetype
        counts[sourcetype] = counts.get(sourcetype, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def verify_evidence_line_mapping(
    records: list[EvidenceRecord], normalized_path: Path
) -> int:
    """Count records whose ``order`` really does index their own source line."""
    lines = normalized_path.read_text(encoding="utf-8").splitlines()
    verified = 0
    for record in records:
        if record.order is None or not 0 <= record.order < len(lines):
            continue
        try:
            on_disk = SecurityEvent.model_validate_json(lines[record.order])
        except ValueError:
            continue
        if on_disk == record.normalized_event:
            verified += 1
    return verified


@dataclass(frozen=True)
class ValidationReport:
    """Everything the report prints, computed and nothing inferred."""

    source: SourceProvenance
    normalized_path: Path
    total_raw_records: int
    total_normalized: int
    failures: tuple[RecordFailure, ...]
    load_failures: tuple[RecordFailure, ...]
    sourcetype_counts: dict[str, int]
    summary: TimelineSummary
    provenance: ProvenanceChecks

    @property
    def failed_normalization(self) -> int:
        return len(self.failures)

    @property
    def is_clean(self) -> bool:
        return (
            not self.failures and not self.load_failures and self.provenance.all_passed
        )


def build_report(
    raw_path: Path, normalized_path: Path, assume_timezone: tzinfo | None = None
) -> ValidationReport:
    """Validate a raw export against the normalized JSONL produced from it.

    Raises:
        InputFormatError: If the raw export is neither JSON nor JSON Lines.
        MixedTimezoneError: If the evidence mixes naive and aware timestamps and no
            ``assume_timezone`` was named.
    """
    source = describe_source(raw_path)

    raw_records = load_raw_records(raw_path.read_text(encoding="utf-8"))
    in_memory = normalize_records(raw_records)

    evidence, load_failures = load_evidence(normalized_path)
    ordered = sort_evidence(evidence, assume_timezone)

    checks = ProvenanceChecks(
        raw_unchanged=digest_file(raw_path) == source.sha256,
        total_records=len(evidence),
        records_with_raw_event=sum(
            1 for record in evidence if record.normalized_event.raw_event
        ),
        disk_matches_memory=[record.normalized_event for record in evidence]
        == in_memory.events,
        evidence_lines_verified=verify_evidence_line_mapping(evidence, normalized_path),
    )

    return ValidationReport(
        source=source,
        normalized_path=normalized_path.resolve(),
        total_raw_records=len(raw_records),
        total_normalized=in_memory.normalized,
        failures=tuple(in_memory.failures),
        load_failures=tuple(load_failures),
        sourcetype_counts=count_sourcetypes(ordered),
        summary=summarize(ordered),
        provenance=checks,
    )


def _yes_no(value: bool) -> str:
    return "yes" if value else "NO"


def render_report(report: ValidationReport) -> list[str]:
    """Render the report, leading with what the source data actually is."""
    source = report.source
    lines: list[str] = []

    if source.is_documented_location:
        title = "REAL BOTS v3 EXPORT VALIDATION"
    else:
        title = "BOTS v3 PIPELINE VALIDATION -- UNVERIFIED SOURCE LOCATION"
    lines += [title, "=" * len(title), ""]

    if source.is_documented_location:
        lines.append(
            "source classification: REAL Splunk BOTS v3 export "
            f"({'/'.join(RAW_EXPORT_DIR_PARTS)}/)"
        )
    else:
        lines += [
            "source classification: NOT a verified real BOTS v3 export",
            f"  !! this file is not in {'/'.join(RAW_EXPORT_DIR_PARTS)}/, the documented",
            "  !! location for untouched real exports. Treat this run as a tooling",
            "  !! check, NOT as real-data validation.",
        ]

    lines += [
        f"  raw export:  {source.path}",
        f"  sha256:      {source.sha256}",
        f"  size:        {source.size_bytes} bytes",
        f"  modified:    {source.modified.isoformat()}",
        f"  normalized:  {report.normalized_path}",
        "",
        "ingestion:",
        f"  total raw records:          {report.total_raw_records}",
        f"  total normalized records:   {report.total_normalized}",
        f"  failed normalization count: {report.failed_normalization}",
    ]
    for failure in report.failures:
        lines.append(f"    record {failure.index}: {failure.reason}")
    for failure in report.load_failures:
        lines.append(f"    normalized line {failure.index}: {failure.reason}")

    lines += ["", "sourcetypes present:"]
    if report.sourcetype_counts:
        width = max(len(name) for name in report.sourcetype_counts)
        lines += [
            f"  {name:<{width}}  {count}"
            for name, count in report.sourcetype_counts.items()
        ]
    else:
        lines.append("  (none)")

    lines += ["", "timeline:"]
    lines += [f"  {line}" for line in render_summary(report.summary)]

    checks = report.provenance
    provenance_rows = (
        ("raw export unchanged after processing", _yes_no(checks.raw_unchanged)),
        (
            "records retaining raw_event",
            f"{checks.records_with_raw_event}/{checks.total_records}",
        ),
        (
            "normalized file matches re-normalization",
            _yes_no(checks.disk_matches_memory),
        ),
        (
            "evidence ids map to normalized lines",
            f"{checks.evidence_lines_verified}/{checks.total_records}",
        ),
    )
    label_width = max(len(label) for label, _ in provenance_rows) + 1
    lines += ["", "provenance:"]
    lines += [
        f"  {label + ':':<{label_width}} {value}" for label, value in provenance_rows
    ]
    lines += [
        "",
        "no classification, severity grading, risk scoring, or framework mapping is",
        "performed by this report.",
    ]
    return lines


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.services.validation",
        description=(
            "Validate a real Splunk BOTS v3 export against the normalized JSONL "
            "produced from it. Performs no classification or scoring."
        ),
    )
    parser.add_argument(
        "--raw",
        type=Path,
        required=True,
        metavar="PATH",
        help=f"untouched real export, expected in {'/'.join(RAW_EXPORT_DIR_PARTS)}/",
    )
    parser.add_argument(
        "--normalized",
        type=Path,
        required=True,
        metavar="PATH",
        help="normalized JSONL written by app.ingestion.normalize_file",
    )
    parser.add_argument(
        "--assume-timezone",
        dest="assume_timezone",
        default=None,
        metavar="TZ",
        help=(
            "zone that naive timestamps are recorded in, required only to order a "
            "mix of naive and offset-bearing timestamps"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entrypoint. Returns 0 when clean, 1 on failures, 2 on input errors."""
    args = build_parser().parse_args(argv)

    assume_timezone: tzinfo | None = None
    if args.assume_timezone is not None:
        try:
            assume_timezone = parse_timezone(args.assume_timezone)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    try:
        report = build_report(args.raw, args.normalized, assume_timezone)
    except FileNotFoundError as exc:
        print(f"error: no such file: {exc.filename}", file=sys.stderr)
        return 2
    except IsADirectoryError as exc:
        print(f"error: {exc.filename} is a directory", file=sys.stderr)
        return 2
    except UnicodeDecodeError:
        print("error: input is not UTF-8 text", file=sys.stderr)
        return 2
    except InputFormatError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except MixedTimezoneError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print(
            "hint: re-run with --assume-timezone UTC to order them explicitly",
            file=sys.stderr,
        )
        return 2

    for line in render_report(report):
        print(line)

    return 0 if report.is_clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
