"""FastAPI application entrypoint."""

from __future__ import annotations

from typing import Any

from fastapi import Body, FastAPI, HTTPException
from fastapi.responses import JSONResponse

from app.ingestion import NormalizationError, SplunkBOTSEventNormalizer
from app.models import SecurityEvent
from app.streaming.health import check_kafka

SERVICE_NAME = "agentic-soc-platform"

app = FastAPI(
    title="Agentic SOC Platform",
    description="Agentic SOC investigation and response platform.",
    version="0.1.0",
)

normalizer = SplunkBOTSEventNormalizer()


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe used by local runs, Docker, and later orchestrators.

    Independent of Kafka. A broker outage must not fail this endpoint.
    """
    return {"status": "ok", "service": SERVICE_NAME}


@app.get("/health/kafka")
def health_kafka() -> JSONResponse:
    """Readiness for the local Kafka broker. Does not affect ``GET /health``."""
    payload = check_kafka()
    status_code = 200 if payload.get("status") == "ok" else 503
    return JSONResponse(content=payload, status_code=status_code)


@app.post("/events/normalize", response_model=SecurityEvent)
def normalize_event(raw_event: dict[str, Any] = Body(...)) -> SecurityEvent:
    """Normalize one raw Splunk event into a ``SecurityEvent``.

    The event is not persisted; this endpoint is the ingestion boundary that later
    milestones will call before handing events to the investigation graph.
    """
    try:
        return normalizer.normalize(raw_event)
    except NormalizationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
