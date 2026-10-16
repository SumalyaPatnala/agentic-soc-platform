"""Deterministic correlation of normalized BOTS v3 evidence.

Correlation here means one thing only: grouping evidence by a shared identifier that
is literally present in the events. Nothing is inferred, scored, or classified. The
same input always produces the same output, which is what makes the result safe to
hand to a reasoning layer later -- an agent can be wrong about what a grouping
*means*, but it cannot be wrong about which events shared a value.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Final

from app.models import EvidenceRecord

#: Fields that identify an actor, asset, or endpoint and can therefore be pivoted on.
CORRELATABLE_FIELDS: Final[tuple[str, ...]] = ("user", "host", "src_ip", "dest_ip")


class UnknownCorrelationField(ValueError):
    """Raised when asked to correlate on a field that is not correlatable."""


def _validate_field(field: str) -> str:
    if field not in CORRELATABLE_FIELDS:
        raise UnknownCorrelationField(
            f"{field!r} is not correlatable; choose one of: "
            f"{', '.join(CORRELATABLE_FIELDS)}"
        )
    return field


def field_value(record: EvidenceRecord, field: str) -> str | None:
    """Read one correlatable field from a record, treating blanks as unset."""
    _validate_field(field)
    value: str | None = getattr(record.normalized_event, field)
    if value is None:
        return None
    return value.strip() or None


def group_by(
    records: Iterable[EvidenceRecord], field: str
) -> dict[str, list[EvidenceRecord]]:
    """Group records by one correlatable field.

    Records with no value for the field are omitted entirely rather than collected
    under a shared ``None`` key. Two events that both lack a username do not share a
    user, and bucketing them together would manufacture a correlation that the
    telemetry does not support.

    Group keys appear in order of first occurrence, and members keep their input
    order, so the result is reproducible.
    """
    _validate_field(field)
    groups: dict[str, list[EvidenceRecord]] = {}
    for record in records:
        value = field_value(record, field)
        if value is None:
            continue
        groups.setdefault(value, []).append(record)
    return groups


def group_by_user(
    records: Iterable[EvidenceRecord],
) -> dict[str, list[EvidenceRecord]]:
    """Group evidence by username."""
    return group_by(records, "user")


def group_by_host(
    records: Iterable[EvidenceRecord],
) -> dict[str, list[EvidenceRecord]]:
    """Group evidence by host."""
    return group_by(records, "host")


def group_by_src_ip(
    records: Iterable[EvidenceRecord],
) -> dict[str, list[EvidenceRecord]]:
    """Group evidence by source IP."""
    return group_by(records, "src_ip")


def group_by_dest_ip(
    records: Iterable[EvidenceRecord],
) -> dict[str, list[EvidenceRecord]]:
    """Group evidence by destination IP."""
    return group_by(records, "dest_ip")


def correlate(
    records: Sequence[EvidenceRecord],
) -> dict[str, dict[str, list[EvidenceRecord]]]:
    """Group the same evidence across every correlatable field at once."""
    return {field: group_by(records, field) for field in CORRELATABLE_FIELDS}


def distinct_values(records: Iterable[EvidenceRecord], field: str) -> list[str]:
    """Sorted distinct values present for a field, excluding unset ones."""
    return sorted(group_by(records, field))


def shared_value_groups(
    records: Iterable[EvidenceRecord], field: str, *, minimum: int = 2
) -> dict[str, list[EvidenceRecord]]:
    """Keep only the groups holding at least ``minimum`` records.

    These are the values that actually connect events to each other, as opposed to
    values seen exactly once.
    """
    if minimum < 1:
        raise ValueError(f"minimum must be at least 1, got {minimum}")
    return {
        value: members
        for value, members in group_by(records, field).items()
        if len(members) >= minimum
    }
