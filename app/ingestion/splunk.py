"""Normalization of real Splunk BOTS v3 events into the vendor-neutral model.

The input to this module is an event *exported from Splunk* (see the "Using real
Splunk BOTS v3 data" section of the README). Field names differ per sourcetype:
``aws:cloudtrail`` carries ``eventName``/``sourceIPAddress``, GuardDuty carries
``signature``/``severity``, and Windows telemetry carries ``Computer``/``EventCode``.
Rather than branching on sourcetype, each target field has an ordered list of
aliases and the first resolvable one wins. Anything we do not understand stays
available to later milestones because the untouched payload is kept in
``SecurityEvent.raw_event``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any, Final

from app.models import SecurityEvent


class NormalizationError(ValueError):
    """Raised when a raw event cannot be normalized into a ``SecurityEvent``."""


# Alias order is priority order. Dotted entries are traversed into nested objects,
# which covers payloads read back from `_raw` where Splunk did not flatten the JSON.
TIMESTAMP_FIELDS: Final[tuple[str, ...]] = (
    "_time",
    "timestamp",
    "eventTime",
    "event_time",
)
SOURCE_FIELDS: Final[tuple[str, ...]] = ("source",)
SOURCETYPE_FIELDS: Final[tuple[str, ...]] = ("sourcetype",)
HOST_FIELDS: Final[tuple[str, ...]] = ("host", "Computer", "hostname", "instance_id")
USER_FIELDS: Final[tuple[str, ...]] = (
    "user",
    "userName",
    "username",
    "Account_Name",
    "principalId",
    "userIdentity.userName",
    "userIdentity.principalId",
)
SRC_IP_FIELDS: Final[tuple[str, ...]] = (
    "src",
    "src_ip",
    "sourceIPAddress",
    "source_ip",
    "client_ip",
)
DEST_IP_FIELDS: Final[tuple[str, ...]] = ("dest", "dest_ip", "destination_ip", "dst")
EVENT_NAME_FIELDS: Final[tuple[str, ...]] = (
    "eventName",
    "signature",
    "action",
    "EventCode",
    "event_name",
)
SEVERITY_FIELDS: Final[tuple[str, ...]] = ("severity", "priority", "level")

# Splunk `_time` epochs are 10 digits. Requiring that many guards against reading a
# bare year like "2018" as an epoch second.
_EPOCH_PATTERN: Final = re.compile(r"^\d{9,11}(\.\d+)?$")


def lookup(payload: Mapping[str, Any], field: str) -> Any:
    """Read ``field`` from ``payload``, honouring dotted paths.

    A literal key wins over traversal because Splunk emits flattened JSON field
    names such as ``"userIdentity.principalId"`` as single keys.
    """
    if field in payload:
        return payload[field]
    if "." not in field:
        return None
    current: Any = payload
    for part in field.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current[part]
    return current


def coerce_scalar(value: Any) -> Any:
    """Reduce a Splunk value to a single usable scalar, or ``None``.

    Multivalue fields arrive as lists; empty strings mean "not set" in Splunk
    exports and must not become an empty ``host`` or ``user``.
    """
    if isinstance(value, (list, tuple)):
        for member in value:
            scalar = coerce_scalar(member)
            if scalar is not None:
                return scalar
        return None
    if isinstance(value, str) and not value.strip():
        return None
    return value


def first_value(payload: Mapping[str, Any], fields: Sequence[str]) -> Any | None:
    """Return the first alias in ``fields`` that resolves to a usable value."""
    for field in fields:
        value = coerce_scalar(lookup(payload, field))
        if value is not None:
            return value
    return None


def first_string(payload: Mapping[str, Any], fields: Sequence[str]) -> str | None:
    """Like :func:`first_value`, coerced to a trimmed string.

    Numbers are stringified rather than interpreted, so a GuardDuty ``severity``
    of ``5.0`` becomes ``"5.0"``; grading it as "medium" is an analyst judgement
    that belongs to a later milestone, not to normalization.
    """
    value = first_value(payload, fields)
    if value is None or isinstance(value, Mapping):
        return None
    if isinstance(value, str):
        return value.strip()
    return str(value)


def parse_timestamp(value: Any) -> datetime:
    """Parse a Splunk timestamp value, raising rather than guessing.

    Epoch values are UTC by definition. Timestamp strings without an offset are
    left naive instead of being assumed to be UTC.
    """
    scalar = coerce_scalar(value)
    if scalar is None:
        raise NormalizationError("timestamp value is empty")
    if isinstance(scalar, datetime):
        return scalar
    if isinstance(scalar, bool):
        raise NormalizationError(f"timestamp value {scalar!r} is not a timestamp")
    if isinstance(scalar, (int, float)):
        return _from_epoch(scalar)
    if isinstance(scalar, str):
        return _parse_timestamp_string(scalar)
    raise NormalizationError(
        f"unsupported timestamp type {type(scalar).__name__!r}"
    )


def _from_epoch(value: int | float) -> datetime:
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise NormalizationError(f"epoch timestamp {value!r} is out of range") from exc


def _parse_timestamp_string(value: str) -> datetime:
    text = value.strip()
    if _EPOCH_PATTERN.match(text):
        return _from_epoch(float(text))
    try:
        return datetime.fromisoformat(text)
    except ValueError as exc:
        raise NormalizationError(
            f"could not parse timestamp {text!r}; expected an epoch or an "
            "ISO-8601 timestamp"
        ) from exc


def _require_string(
    payload: Mapping[str, Any], fields: Sequence[str], label: str
) -> str:
    value = first_string(payload, fields)
    if not value:
        raise NormalizationError(
            f"could not resolve required field {label!r} from any of: "
            f"{', '.join(fields)}"
        )
    return value


def extract_timestamp(payload: Mapping[str, Any]) -> datetime:
    value = first_value(payload, TIMESTAMP_FIELDS)
    if value is None:
        raise NormalizationError(
            "could not resolve required field 'timestamp' from any of: "
            f"{', '.join(TIMESTAMP_FIELDS)}"
        )
    return parse_timestamp(value)


def extract_source(payload: Mapping[str, Any]) -> str:
    return _require_string(payload, SOURCE_FIELDS, "source")


def extract_sourcetype(payload: Mapping[str, Any]) -> str:
    return _require_string(payload, SOURCETYPE_FIELDS, "sourcetype")


def extract_event_name(payload: Mapping[str, Any]) -> str:
    return _require_string(payload, EVENT_NAME_FIELDS, "event_name")


def extract_host(payload: Mapping[str, Any]) -> str | None:
    return first_string(payload, HOST_FIELDS)


def extract_user(payload: Mapping[str, Any]) -> str | None:
    return first_string(payload, USER_FIELDS)


def extract_src_ip(payload: Mapping[str, Any]) -> str | None:
    return first_string(payload, SRC_IP_FIELDS)


def extract_dest_ip(payload: Mapping[str, Any]) -> str | None:
    return first_string(payload, DEST_IP_FIELDS)


def extract_severity(payload: Mapping[str, Any]) -> str | None:
    return first_string(payload, SEVERITY_FIELDS)


def parse_raw_field(value: Any) -> dict[str, Any] | None:
    """Return ``_raw`` decoded as a JSON object, or ``None``.

    Splunk keeps the untouched event in ``_raw``. For JSON sourcetypes it lets us
    recover fields a search did not return; for WinEventLog XML or syslog text it
    is simply not JSON and is skipped.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text.startswith("{"):
        return None
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError:
        return None
    return decoded if isinstance(decoded, dict) else None


class SplunkBOTSEventNormalizer:
    """Normalizes one exported Splunk BOTS v3 event into a ``SecurityEvent``."""

    def normalize(self, raw_event: Mapping[str, Any]) -> SecurityEvent:
        """Normalize a single raw event.

        Raises:
            NormalizationError: if the event is not an object, or if a required
                field (``timestamp``, ``source``, ``sourcetype``, ``event_name``)
                cannot be resolved.
        """
        if not isinstance(raw_event, Mapping):
            raise NormalizationError(
                f"expected a JSON object, got {type(raw_event).__name__!r}"
            )

        payload = self._searchable_payload(raw_event)
        return SecurityEvent(
            timestamp=extract_timestamp(payload),
            source=extract_source(payload),
            sourcetype=extract_sourcetype(payload),
            host=extract_host(payload),
            user=extract_user(payload),
            src_ip=extract_src_ip(payload),
            dest_ip=extract_dest_ip(payload),
            event_name=extract_event_name(payload),
            severity=extract_severity(payload),
            raw_event=dict(raw_event),
        )

    @staticmethod
    def _searchable_payload(raw_event: Mapping[str, Any]) -> Mapping[str, Any]:
        """Layer the event over a JSON ``_raw`` so both can be searched for aliases.

        Splunk-extracted fields take priority over anything read back from
        ``_raw``, since the extraction reflects the indexed interpretation.
        """
        nested = parse_raw_field(raw_event.get("_raw"))
        if nested is None:
            return raw_event
        return {**nested, **raw_event}
