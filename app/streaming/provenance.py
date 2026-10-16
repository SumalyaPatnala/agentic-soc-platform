"""Copy provenance from a raw Splunk-shaped dict without inventing fields.

Only keys that are actually present and non-blank are kept. A missing Splunk
``_cd`` is omitted rather than replaced with a generated identifier.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from app.streaming.jsonutil import dumps

_PROVENANCE_ALIASES: tuple[tuple[str, str], ...] = (
    ("index", "splunk_index"),
    ("sourcetype", "sourcetype"),
    ("source", "source"),
    ("host", "host"),
    ("_time", "original_timestamp"),
    ("_cd", "splunk_event_identifier"),
)


def _scalar_string(value: Any) -> str | None:
    if value is None or isinstance(value, (dict, list)):
        return None
    text = str(value).strip()
    return text or None


def provenance_from_raw(payload: Mapping[str, Any]) -> dict[str, str]:
    """Return transport metadata copied from a raw event, omitting absent keys."""
    metadata: dict[str, str] = {}
    for source_key, dest_key in _PROVENANCE_ALIASES:
        if source_key not in payload:
            continue
        value = _scalar_string(payload[source_key])
        if value is None:
            continue
        metadata[dest_key] = value
    return metadata


def derive_event_id(
    payload: Mapping[str, Any], *, explicit: str | None = None
) -> str:
    """Choose a stable transport id.

    Preference order:
    1. An explicit id supplied by the caller.
    2. Splunk ``_cd`` when present (a real indexer compound identifier).
    3. A SHA-256 of the canonical payload JSON, prefixed ``sha256:`` so it is
       never mistaken for a Splunk identifier.
    """
    if explicit and explicit.strip():
        return explicit.strip()
    compound = _scalar_string(payload.get("_cd"))
    if compound is not None:
        return f"splunk-cd:{compound}"
    digest = hashlib.sha256(dumps(dict(payload)).encode("utf-8")).hexdigest()[:32]
    return f"sha256:{digest}"
