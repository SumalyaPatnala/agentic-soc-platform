"""Evidence wrapper around a normalized security event.

An ``EvidenceRecord`` is a citation: it pairs a ``SecurityEvent`` with the
deterministic metadata needed to point back at exactly where that event came from.
It deliberately carries no judgement -- no severity, no verdict, no labels -- so that
later milestones can reason over evidence without inheriting conclusions that were
never actually derived from the data.
"""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel

from app.models.security_event import SecurityEvent


def format_evidence_id(order: int) -> str:
    """Render a stable evidence id from a source position."""
    return f"ev-{order:06d}"


class EvidenceRecord(BaseModel):
    """A normalized event plus the metadata needed to cite it.

    Attributes:
        evidence_id: Stable identifier derived from ``order``, so the same export
            always produces the same ids.
        normalized_event: The event as produced by the ingestion normalizer,
            including its untouched ``raw_event``.
        order: Zero-based position of the record in its source, or ``None`` when the
            source position is unknown. For a normalized JSONL file this is the line
            number minus one, which makes the original line directly locatable.
    """

    evidence_id: str
    normalized_event: SecurityEvent
    order: int | None = None


def build_evidence(
    events: Iterable[SecurityEvent], *, start: int = 0
) -> list[EvidenceRecord]:
    """Wrap events as evidence, numbering them from ``start`` in the given order."""
    return [
        EvidenceRecord(
            evidence_id=format_evidence_id(order),
            normalized_event=event,
            order=order,
        )
        for order, event in enumerate(events, start=start)
    ]
