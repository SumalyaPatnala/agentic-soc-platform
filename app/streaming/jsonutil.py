"""Deterministic JSON helpers for Kafka payloads."""

from __future__ import annotations

import json
from typing import Any


def dumps(value: Any) -> str:
    """Serialize ``value`` to a stable JSON string.

    Keys are sorted so the same payload always produces the same bytes, which
    keeps SHA-256 event ids and test assertions reproducible.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def dump_bytes(value: Any) -> bytes:
    """UTF-8 bytes of :func:`dumps`."""
    return dumps(value).encode("utf-8")


def loads(raw: str | bytes) -> Any:
    """Parse JSON from text or UTF-8 bytes."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    return json.loads(raw)
