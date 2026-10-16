"""TEST HELPERS ONLY -- these build schema-shape events, not BOTS v3 evidence.

``make_event`` produces the minimum valid ``SecurityEvent`` with whichever identifiers
a test needs to pivot on. The values carry no narrative: identifiers are RFC 5737
documentation IPs and placeholder account names, and event names are read-only API
calls. Real investigations must use events exported from Splunk.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from app.models import EvidenceRecord, SecurityEvent, build_evidence


def make_event(
    *,
    timestamp: datetime | str = "2018-08-20T13:01:46Z",
    source: str = "example-export",
    sourcetype: str = "aws:cloudtrail",
    event_name: str = "DescribeInstances",
    host: str | None = None,
    user: str | None = None,
    src_ip: str | None = None,
    dest_ip: str | None = None,
    severity: str | None = None,
    raw_event: dict[str, Any] | None = None,
) -> SecurityEvent:
    """Build a valid SecurityEvent, defaulting every optional identifier to unset."""
    return SecurityEvent(
        timestamp=timestamp,  # type: ignore[arg-type]
        source=source,
        sourcetype=sourcetype,
        host=host,
        user=user,
        src_ip=src_ip,
        dest_ip=dest_ip,
        event_name=event_name,
        severity=severity,
        raw_event=raw_event if raw_event is not None else {},
    )


def make_evidence(*events: SecurityEvent) -> list[EvidenceRecord]:
    """Wrap events as evidence numbered from zero, mirroring a source export."""
    return build_evidence(events)


def write_normalized_jsonl(path: Path, events: list[SecurityEvent]) -> Path:
    """Write events in the JSONL shape produced by app.ingestion.normalize_file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(f"{event.model_dump_json()}\n" for event in events), encoding="utf-8"
    )
    return path


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Read JSONL back into dicts."""
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
