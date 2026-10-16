"""Tests for GET /health and GET /health/kafka.

Kafka readiness is mocked. A broker outage must not fail /health.
"""

from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_still_ok_when_kafka_is_down() -> None:
    with patch("app.main.check_kafka", return_value={"status": "unavailable"}):
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "agentic-soc-platform"}


def test_health_kafka_ok() -> None:
    payload = {"status": "ok", "bootstrap_servers": "localhost:9092", "broker_count": 1}
    with patch("app.main.check_kafka", return_value=payload):
        response = client.get("/health/kafka")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["bootstrap_servers"] == "localhost:9092"


def test_health_kafka_unavailable() -> None:
    payload = {
        "status": "unavailable",
        "bootstrap_servers": "localhost:9092",
        "error": "connection refused",
    }
    with patch("app.main.check_kafka", return_value=payload):
        response = client.get("/health/kafka")

    assert response.status_code == 503
    assert response.json()["status"] == "unavailable"
