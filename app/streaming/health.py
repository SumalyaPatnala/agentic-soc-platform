"""Kafka broker reachability check used by GET /health/kafka."""

from __future__ import annotations

from typing import Any

from app.streaming.config import KafkaSettings


def check_kafka(settings: KafkaSettings | None = None, timeout: float = 3.0) -> dict[str, Any]:
    """Return a small status dict. ``status`` is ``ok`` only after a metadata call succeeds."""
    settings = settings or KafkaSettings.from_env()
    payload: dict[str, Any] = {
        "status": "unavailable",
        "bootstrap_servers": settings.bootstrap_servers,
    }
    try:
        from confluent_kafka.admin import AdminClient

        admin = AdminClient({"bootstrap.servers": settings.bootstrap_servers})
        metadata = admin.list_topics(timeout=timeout)
        payload["status"] = "ok"
        payload["broker_count"] = len(metadata.brokers)
        return payload
    except Exception as exc:  # noqa: BLE001 — health must not raise
        payload["error"] = str(exc)
        return payload
