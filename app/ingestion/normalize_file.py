"""CLI for normalizing a file of exported Splunk BOTS v3 events.

Usage:
    python -m app.ingestion.normalize_file <path> [--out [PATH]]

Accepts the shapes Splunk actually produces on export: a JSON array, a single
JSON object, a ``{"results": [...]}`` envelope from the search REST API, and
JSON Lines (including the ``{"preview": false, "result": {...}}`` wrapper from
the streaming export endpoint). A record that cannot be parsed or normalized is
reported and skipped; it never aborts the rest of the file.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.ingestion.splunk import NormalizationError, SplunkBOTSEventNormalizer
from app.models import SecurityEvent

DEFAULT_OUTPUT_DIR = Path("data/normalized")


class InputFormatError(ValueError):
    """Raised when a file is neither JSON nor JSON Lines."""


@dataclass(frozen=True)
class RecordFailure:
    """A single record that could not be parsed or normalized."""

    index: int
    reason: str


@dataclass(frozen=True)
class RawRecord:
    """One candidate record read from the input, parsed or failed."""

    index: int
    payload: dict[str, Any] | None = None
    error: str | None = None


@dataclass
class NormalizationReport:
    """Outcome of normalizing a batch of raw records."""

    events: list[SecurityEvent] = field(default_factory=list)
    failures: list[RecordFailure] = field(default_factory=list)

    @property
    def normalized(self) -> int:
        return len(self.events)

    @property
    def failed(self) -> int:
        return len(self.failures)

    @property
    def total(self) -> int:
        return self.normalized + self.failed


def _unwrap(record: dict[str, Any]) -> dict[str, Any]:
    """Unwrap the streaming-export envelope ``{"preview": ..., "result": {...}}``."""
    inner = record.get("result")
    if isinstance(inner, dict):
        return inner
    return record


def _records_from_list(items: Sequence[Any], offset: int = 0) -> list[RawRecord]:
    records: list[RawRecord] = []
    for position, item in enumerate(items, start=offset):
        if isinstance(item, dict):
            records.append(RawRecord(index=position, payload=_unwrap(item)))
        else:
            records.append(
                RawRecord(
                    index=position,
                    error=f"expected a JSON object, got {type(item).__name__!r}",
                )
            )
    return records


def _records_from_document(document: Any) -> list[RawRecord]:
    if isinstance(document, list):
        return _records_from_list(document)
    if isinstance(document, dict):
        results = document.get("results")
        if isinstance(results, list):
            return _records_from_list(results)
        return [RawRecord(index=0, payload=_unwrap(document))]
    raise InputFormatError(
        f"expected a JSON object or array of objects, got {type(document).__name__!r}"
    )


def _records_from_lines(text: str) -> list[RawRecord]:
    records: list[RawRecord] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError as exc:
            records.append(
                RawRecord(index=line_number, error=f"malformed JSON: {exc}")
            )
            continue
        records.extend(_records_from_list([decoded], offset=line_number))
    return records


def load_raw_records(text: str) -> list[RawRecord]:
    """Split raw file text into candidate records without normalizing them."""
    if not text.strip():
        return []

    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        pass
    else:
        return _records_from_document(document)

    records = _records_from_lines(text)
    if len(records) > 1 and all(record.payload is None for record in records):
        raise InputFormatError(
            "file is neither valid JSON nor valid JSON Lines; if this is a "
            "pretty-printed export, check it for a syntax error"
        )
    return records


def normalize_records(
    records: Sequence[RawRecord],
    normalizer: SplunkBOTSEventNormalizer | None = None,
) -> NormalizationReport:
    """Normalize parsed records, collecting per-record failures."""
    normalizer = normalizer or SplunkBOTSEventNormalizer()
    report = NormalizationReport()
    for record in records:
        if record.payload is None:
            report.failures.append(
                RecordFailure(index=record.index, reason=record.error or "unparsable")
            )
            continue
        try:
            report.events.append(normalizer.normalize(record.payload))
        except NormalizationError as exc:
            report.failures.append(RecordFailure(index=record.index, reason=str(exc)))
        except ValueError as exc:
            # Pydantic validation of the normalized values, e.g. a non-string host.
            report.failures.append(
                RecordFailure(index=record.index, reason=f"invalid event: {exc}")
            )
    return report


def normalize_text(
    text: str, normalizer: SplunkBOTSEventNormalizer | None = None
) -> NormalizationReport:
    """Normalize the full text of an export."""
    return normalize_records(load_raw_records(text), normalizer=normalizer)


def normalize_file(
    path: Path, normalizer: SplunkBOTSEventNormalizer | None = None
) -> NormalizationReport:
    """Normalize a file of exported Splunk events."""
    return normalize_text(path.read_text(encoding="utf-8"), normalizer=normalizer)


def resolve_output_path(out: Path, source: Path) -> Path:
    """Treat a ``.jsonl`` argument as a file and anything else as a directory."""
    if out.suffix == ".jsonl":
        return out
    return out / f"{source.stem}.normalized.jsonl"


def write_jsonl(events: Sequence[SecurityEvent], destination: Path) -> Path:
    """Write normalized events as one JSON object per line."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(f"{event.model_dump_json()}\n")
    return destination


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.ingestion.normalize_file",
        description="Normalize exported Splunk BOTS v3 events into SecurityEvent JSON.",
    )
    parser.add_argument("path", type=Path, help="exported JSON or JSON Lines file")
    parser.add_argument(
        "--out",
        "-o",
        type=Path,
        nargs="?",
        const=DEFAULT_OUTPUT_DIR,
        default=None,
        metavar="PATH",
        help=(
            "write normalized events as JSONL; bare flag writes to "
            f"{DEFAULT_OUTPUT_DIR}/, a directory writes <name>.normalized.jsonl "
            "inside it, and a .jsonl path is used as-is"
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entrypoint. Returns 0 on a clean run, 1 if records failed, 2 on input errors."""
    args = build_parser().parse_args(argv)
    path: Path = args.path

    try:
        report = normalize_file(path)
    except FileNotFoundError:
        print(f"error: no such file: {path}", file=sys.stderr)
        return 2
    except IsADirectoryError:
        print(f"error: {path} is a directory", file=sys.stderr)
        return 2
    except UnicodeDecodeError:
        print(f"error: {path} is not UTF-8 text", file=sys.stderr)
        return 2
    except InputFormatError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    for failure in report.failures:
        print(f"record {failure.index}: {failure.reason}", file=sys.stderr)

    print(f"total: {report.total}")
    print(f"normalized: {report.normalized}")
    print(f"failed: {report.failed}")

    if args.out is not None:
        destination = write_jsonl(report.events, resolve_output_path(args.out, path))
        print(f"wrote {report.normalized} events to {destination}")

    return 1 if report.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
