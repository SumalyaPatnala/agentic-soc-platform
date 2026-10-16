"""Kafka transport envelope. Not a domain model — ``SecurityEvent`` stays separate."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    """Timezone-aware UTC timestamp for ``produced_at``."""
    return datetime.now(timezone.utc)


class KafkaEventEnvelope(BaseModel):
    """Versioned wrapper around a payload moving between Kafka topics.

    ``payload`` is either a raw Splunk-shaped dict, a serialized ``SecurityEvent``,
    or a serialized ``EvidenceRecord``. Domain meaning lives in those models, not
    here.
    """

    schema_version: str = "1.0"
    event_id: str
    source: str
    source_type: str | None = None
    produced_at: datetime
    payload: dict[str, Any]
    metadata: dict[str, Any] = Field(default_factory=dict)


class DeadLetterRecord(BaseModel):
    """A record that could not be processed at a named pipeline stage.

    ``error_message`` is the exception text, not a stack trace. Stack traces stay
    in local logs.
    """

    schema_version: str = "1.0"
    failed_stage: str
    error_type: str
    error_message: str
    original_event: dict[str, Any]
    metadata: dict[str, Any] = Field(default_factory=dict)
