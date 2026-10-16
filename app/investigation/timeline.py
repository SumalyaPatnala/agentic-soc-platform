"""Deterministic evidence timelines over normalized BOTS v3 events.

Usage:
    python -m app.investigation.timeline <normalized-jsonl-file> [filters]

Input is the JSONL written by ``app.ingestion.normalize_file``: one ``SecurityEvent``
per line. This module orders that evidence and summarizes what identifiers appear in
it. It assigns no severity, reaches no verdict, and maps nothing to a framework --
every value printed is copied from the events themselves.

Ordering is the one genuinely dangerous operation here, because Python cannot compare
a naive datetime with an aware one and BOTS v3 mixes both (CloudTrail carries UTC
offsets, Windows telemetry frequently does not). Rather than quietly stamping UTC onto
naive values, a mixed set refuses to sort until the caller states which zone the naive
timestamps belong to.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone, tzinfo
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import ValidationError

from app.ingestion.normalize_file import RecordFailure
from app.investigation.correlation import (
    CORRELATABLE_FIELDS,
    distinct_values,
    field_value,
)
from app.models import EvidenceRecord, SecurityEvent, format_evidence_id

#: How many distinct values to name inline before summarizing the remainder.
MAX_LISTED_VALUES = 10


class MixedTimezoneError(ValueError):
    """Raised when naive and aware timestamps cannot be ordered against each other."""


def is_aware(moment: datetime) -> bool:
    """Whether a datetime carries a usable UTC offset."""
    return moment.tzinfo is not None and moment.tzinfo.utcoffset(moment) is not None


def partition_by_awareness(
    records: Iterable[EvidenceRecord],
) -> tuple[list[EvidenceRecord], list[EvidenceRecord]]:
    """Split records into (timezone-aware, naive) by their event timestamp."""
    aware: list[EvidenceRecord] = []
    naive: list[EvidenceRecord] = []
    for record in records:
        target = aware if is_aware(record.normalized_event.timestamp) else naive
        target.append(record)
    return aware, naive


def parse_timezone(value: str) -> tzinfo:
    """Parse ``UTC``, a ``+HH:MM`` offset, or an IANA zone name."""
    text = value.strip()
    if text.upper() in {"UTC", "Z"}:
        return timezone.utc
    if text[:1] in {"+", "-"}:
        try:
            parsed = datetime.fromisoformat(f"2000-01-01T00:00:00{text}")
        except ValueError as exc:
            raise ValueError(f"{value!r} is not a valid UTC offset") from exc
        if parsed.tzinfo is None:
            raise ValueError(f"{value!r} is not a valid UTC offset")
        return parsed.tzinfo
    try:
        return ZoneInfo(text)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(
            f"{value!r} is not a recognized timezone; use 'UTC', an offset such as "
            "'-07:00', or an IANA name such as 'America/Los_Angeles'"
        ) from exc


def resolve_ordering_timestamps(
    records: Sequence[EvidenceRecord], assume_timezone: tzinfo | None = None
) -> list[datetime]:
    """Return one comparable timestamp per record, in input order.

    Args:
        records: Evidence to derive ordering keys for.
        assume_timezone: Zone to attach to naive timestamps. Only ever applied when
            the caller names it explicitly.

    Raises:
        MixedTimezoneError: If the records mix naive and aware timestamps and no
            ``assume_timezone`` was given, since ordering them would require
            inventing an offset.
    """
    timestamps = [record.normalized_event.timestamp for record in records]
    naive_count = sum(1 for moment in timestamps if not is_aware(moment))

    if assume_timezone is None:
        if naive_count and naive_count != len(timestamps):
            raise MixedTimezoneError(
                f"cannot order {len(timestamps) - naive_count} timezone-aware and "
                f"{naive_count} naive timestamps together; state the zone the naive "
                "timestamps are recorded in to order them explicitly"
            )
        return timestamps

    return [
        moment if is_aware(moment) else moment.replace(tzinfo=assume_timezone)
        for moment in timestamps
    ]


def sort_evidence(
    records: Sequence[EvidenceRecord], assume_timezone: tzinfo | None = None
) -> list[EvidenceRecord]:
    """Order evidence chronologically.

    Equal timestamps keep source order: the sort key falls back to ``order``, so the
    result does not depend on how the caller happened to arrange the input. Records
    with an unknown source position sort first within a tie.
    """
    ordering = resolve_ordering_timestamps(records, assume_timezone)
    pairs = sorted(
        zip(ordering, records),
        key=lambda pair: (pair[0], -1 if pair[1].order is None else pair[1].order),
    )
    return [record for _, record in pairs]


def sort_events(
    events: Sequence[SecurityEvent], assume_timezone: tzinfo | None = None
) -> list[SecurityEvent]:
    """Order bare events chronologically, preserving input order within ties."""
    wrapped = [
        EvidenceRecord(
            evidence_id=format_evidence_id(order),
            normalized_event=event,
            order=order,
        )
        for order, event in enumerate(events)
    ]
    return [record.normalized_event for record in sort_evidence(wrapped, assume_timezone)]


@dataclass(frozen=True)
class EvidenceFilter:
    """Exact-match filters, combined with AND.

    A record that has no value for a filtered field never matches, consistent with
    correlation treating an unset field as "no shared identifier" rather than a value.
    """

    user: str | None = None
    host: str | None = None
    src_ip: str | None = None
    dest_ip: str | None = None

    @property
    def is_empty(self) -> bool:
        return all(getattr(self, field) is None for field in CORRELATABLE_FIELDS)

    def matches(self, record: EvidenceRecord) -> bool:
        for field in CORRELATABLE_FIELDS:
            wanted: str | None = getattr(self, field)
            if wanted is None:
                continue
            if field_value(record, field) != wanted:
                return False
        return True


def apply_filter(
    records: Iterable[EvidenceRecord], evidence_filter: EvidenceFilter
) -> list[EvidenceRecord]:
    """Keep only the records matching every populated filter field."""
    return [record for record in records if evidence_filter.matches(record)]


@dataclass(frozen=True)
class TimelineSummary:
    """Counts and identifier inventories for a set of evidence."""

    total: int
    earliest: datetime | None
    latest: datetime | None
    users: tuple[str, ...]
    hosts: tuple[str, ...]
    src_ips: tuple[str, ...]
    dest_ips: tuple[str, ...]


def summarize(ordered: Sequence[EvidenceRecord]) -> TimelineSummary:
    """Summarize evidence that has already been ordered by :func:`sort_evidence`.

    ``earliest`` and ``latest`` are the first and last timestamps as they appear in
    the events, not rewritten into a common zone.
    """
    return TimelineSummary(
        total=len(ordered),
        earliest=ordered[0].normalized_event.timestamp if ordered else None,
        latest=ordered[-1].normalized_event.timestamp if ordered else None,
        users=tuple(distinct_values(ordered, "user")),
        hosts=tuple(distinct_values(ordered, "host")),
        src_ips=tuple(distinct_values(ordered, "src_ip")),
        dest_ips=tuple(distinct_values(ordered, "dest_ip")),
    )


def load_evidence(path: Path) -> tuple[list[EvidenceRecord], list[RecordFailure]]:
    """Read normalized JSONL into evidence, reporting unusable lines individually.

    ``order`` is the zero-based source line, so ``ev-000004`` is line 5 of the file
    and every rendered row can be traced back to the record it came from.
    """
    records: list[EvidenceRecord] = []
    failures: list[RecordFailure] = []

    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            failures.append(
                RecordFailure(index=line_number, reason=f"malformed JSON: {exc}")
            )
            continue
        if not isinstance(payload, dict):
            failures.append(
                RecordFailure(
                    index=line_number,
                    reason=f"expected a JSON object, got {type(payload).__name__!r}",
                )
            )
            continue
        try:
            event = SecurityEvent.model_validate(payload)
        except ValidationError as exc:
            failures.append(
                RecordFailure(
                    index=line_number,
                    reason=f"not a normalized SecurityEvent: {exc.error_count()} "
                    f"validation error(s); first: {exc.errors()[0]['msg']}",
                )
            )
            continue

        order = line_number - 1
        records.append(
            EvidenceRecord(
                evidence_id=format_evidence_id(order),
                normalized_event=event,
                order=order,
            )
        )

    return records, failures


def _attributes(event: SecurityEvent) -> str:
    """Render the identifiers present on an event, skipping unset ones.

    ``severity`` is the vendor's own value copied through by normalization; it is
    displayed, never computed or graded here.
    """
    pairs = (
        ("user", event.user),
        ("host", event.host),
        ("src", event.src_ip),
        ("dest", event.dest_ip),
        ("severity", event.severity),
    )
    return " ".join(f"{name}={value}" for name, value in pairs if value)


def render_timeline(ordered: Sequence[EvidenceRecord]) -> list[str]:
    """Render one line per record, column-aligned to the widest value present.

    Each row leads with its ``evidence_id``, which identifies the source line of the
    normalized record and therefore its ``raw_event``.
    """
    if not ordered:
        return []

    rows = [
        (
            record.normalized_event.timestamp.isoformat(),
            record.evidence_id,
            record.normalized_event.sourcetype,
            record.normalized_event.event_name,
            _attributes(record.normalized_event),
        )
        for record in ordered
    ]
    time_width = max(len(row[0]) for row in rows)
    id_width = max(len(row[1]) for row in rows)
    type_width = max(len(row[2]) for row in rows)
    name_width = max(len(row[3]) for row in rows)

    return [
        (
            f"{moment:<{time_width}}  {evidence_id:<{id_width}}  "
            f"{sourcetype:<{type_width}}  {event_name:<{name_width}}  {attributes}"
        ).rstrip()
        for moment, evidence_id, sourcetype, event_name, attributes in rows
    ]


def _format_values(label: str, values: Sequence[str]) -> str:
    if not values:
        return f"{label}: 0"
    shown = ", ".join(values[:MAX_LISTED_VALUES])
    remainder = len(values) - MAX_LISTED_VALUES
    if remainder > 0:
        shown = f"{shown}, +{remainder} more"
    return f"{label}: {len(values)} ({shown})"


def render_summary(summary: TimelineSummary) -> list[str]:
    """Render the summary block printed above the timeline."""
    earliest = summary.earliest.isoformat() if summary.earliest else "-"
    latest = summary.latest.isoformat() if summary.latest else "-"
    return [
        f"total events: {summary.total}",
        f"earliest timestamp: {earliest}",
        f"latest timestamp: {latest}",
        _format_values("unique users", summary.users),
        _format_values("unique hosts", summary.hosts),
        _format_values("unique source IPs", summary.src_ips),
        _format_values("unique destination IPs", summary.dest_ips),
    ]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.investigation.timeline",
        description=(
            "Summarize and order normalized Splunk BOTS v3 evidence. Performs no "
            "classification, scoring, or inference."
        ),
    )
    parser.add_argument(
        "path", type=Path, help="normalized JSONL file of SecurityEvent records"
    )
    parser.add_argument("--user", default=None, help="keep only events for this user")
    parser.add_argument("--host", default=None, help="keep only events for this host")
    parser.add_argument(
        "--src-ip", dest="src_ip", default=None, help="keep only this source IP"
    )
    parser.add_argument(
        "--dest-ip", dest="dest_ip", default=None, help="keep only this destination IP"
    )
    parser.add_argument(
        "--assume-timezone",
        dest="assume_timezone",
        default=None,
        metavar="TZ",
        help=(
            "zone that naive timestamps are recorded in, required only to order a "
            "mix of naive and offset-bearing timestamps; accepts 'UTC', an offset "
            "such as '-07:00', or an IANA name such as 'America/Los_Angeles'"
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entrypoint. Returns 0 on a clean run, 1 if lines failed, 2 on input errors."""
    args = build_parser().parse_args(argv)
    path: Path = args.path

    assume_timezone: tzinfo | None = None
    if args.assume_timezone is not None:
        try:
            assume_timezone = parse_timezone(args.assume_timezone)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    try:
        records, failures = load_evidence(path)
    except FileNotFoundError:
        print(f"error: no such file: {path}", file=sys.stderr)
        return 2
    except IsADirectoryError:
        print(f"error: {path} is a directory", file=sys.stderr)
        return 2
    except UnicodeDecodeError:
        print(f"error: {path} is not UTF-8 text", file=sys.stderr)
        return 2

    for failure in failures:
        print(f"line {failure.index}: {failure.reason}", file=sys.stderr)

    evidence_filter = EvidenceFilter(
        user=args.user, host=args.host, src_ip=args.src_ip, dest_ip=args.dest_ip
    )
    selected = apply_filter(records, evidence_filter)

    try:
        ordered = sort_evidence(selected, assume_timezone)
    except MixedTimezoneError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print(
            "hint: re-run with --assume-timezone UTC to order them explicitly",
            file=sys.stderr,
        )
        return 2

    if not evidence_filter.is_empty:
        print(f"filtered {len(records)} loaded events down to {len(selected)}")

    for line in render_summary(summarize(ordered)):
        print(line)

    print()
    print("timeline:")
    for line in render_timeline(ordered):
        print(line)

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
