"""Structured log lines for Kafka processing. Never logs secrets."""

from __future__ import annotations

import logging
from typing import Any

_LOG = logging.getLogger("app.streaming")


def kafka_log(message: str, *, level: int = logging.INFO, **fields: Any) -> None:
    """Emit one log line with ``key=value`` fields after the message."""
    parts = [message]
    for key, value in fields.items():
        if value is None:
            continue
        parts.append(f"{key}={value}")
    _LOG.log(level, " ".join(parts))
