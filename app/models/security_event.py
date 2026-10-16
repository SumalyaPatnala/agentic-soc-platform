"""Vendor-neutral security event model.

This model is the common shape that every future ingestion adapter (Splunk,
CrowdStrike, Okta, AWS GuardDuty, firewalls) normalizes into. Vendor-specific
fields are preserved untouched in ``raw_event`` so no fidelity is lost.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SecurityEvent(BaseModel):
    """A single normalized security telemetry event."""

    timestamp: datetime
    source: str
    sourcetype: str
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dest_ip: str | None = None
    event_name: str
    severity: str | None = None
    raw_event: dict[str, Any] = Field(default_factory=dict)
