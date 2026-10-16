"""Tests for POST /events/normalize.

Request bodies come from the schema-shape fixtures in ``tests.splunk_fixtures`` and
are not BOTS v3 evidence.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from tests.splunk_fixtures import CLOUDTRAIL_FIXTURE, GUARDDUTY_FIXTURE

client = TestClient(app)


def test_normalize_returns_security_event() -> None:
    response = client.post("/events/normalize", json=CLOUDTRAIL_FIXTURE)

    assert response.status_code == 200
    body = response.json()
    assert body["timestamp"] == "2018-08-20T13:01:46Z"
    assert body["sourcetype"] == "aws:cloudtrail"
    assert body["event_name"] == "DescribeInstances"
    assert body["user"] == "example-user"
    assert body["src_ip"] == "203.0.113.25"
    assert body["raw_event"] == CLOUDTRAIL_FIXTURE


def test_normalize_leaves_unresolved_optional_fields_null() -> None:
    response = client.post("/events/normalize", json=GUARDDUTY_FIXTURE)

    assert response.status_code == 200
    assert response.json()["user"] is None


def test_normalize_rejects_event_without_timestamp() -> None:
    payload = {
        key: value
        for key, value in CLOUDTRAIL_FIXTURE.items()
        if key not in {"_time", "eventTime"}
    }

    response = client.post("/events/normalize", json=payload)

    assert response.status_code == 422
    assert "required field 'timestamp'" in response.json()["detail"]


def test_normalize_rejects_unparseable_timestamp() -> None:
    response = client.post(
        "/events/normalize", json={**CLOUDTRAIL_FIXTURE, "_time": "not-a-timestamp"}
    )

    assert response.status_code == 422
    assert "could not parse timestamp" in response.json()["detail"]


def test_normalize_rejects_non_object_body() -> None:
    response = client.post("/events/normalize", json=[CLOUDTRAIL_FIXTURE])

    assert response.status_code == 422
