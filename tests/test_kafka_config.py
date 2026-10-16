"""Tests for Kafka settings and client configuration. No broker required."""

from __future__ import annotations

import pytest

from app.streaming.config import (
    DEFAULT_EVIDENCE_GROUP,
    DEFAULT_NORMALIZER_GROUP,
    KafkaSettings,
    consumer_config,
    producer_config,
)


def test_defaults_match_documented_local_values() -> None:
    settings = KafkaSettings()

    assert settings.bootstrap_servers == "localhost:9092"
    assert settings.raw_topic == "soc.raw.events"
    assert settings.normalized_topic == "soc.normalized.events"
    assert settings.evidence_topic == "soc.evidence.events"
    assert settings.dlq_topic == "soc.deadletter"
    assert settings.normalizer_group == DEFAULT_NORMALIZER_GROUP
    assert settings.evidence_group == DEFAULT_EVIDENCE_GROUP


def test_from_env_reads_kafka_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", "127.0.0.1:19092")
    monkeypatch.setenv("KAFKA_RAW_TOPIC", "custom.raw")
    monkeypatch.setenv("KAFKA_NORMALIZER_GROUP", "custom-group")

    settings = KafkaSettings.from_env()

    assert settings.bootstrap_servers == "127.0.0.1:19092"
    assert settings.raw_topic == "custom.raw"
    assert settings.normalizer_group == "custom-group"
    assert settings.normalized_topic == "soc.normalized.events"


def test_from_env_treats_blank_as_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", "   ")

    assert KafkaSettings.from_env().bootstrap_servers == "localhost:9092"


def test_producer_config_uses_acks_all_and_client_id() -> None:
    settings = KafkaSettings(bootstrap_servers="broker:9092", producer_client_id="soc-x")
    config = producer_config(settings)

    assert config["bootstrap.servers"] == "broker:9092"
    assert config["client.id"] == "soc-x"
    assert config["acks"] == "all"
    assert config["enable.idempotence"] == "true"
    assert "sasl.username" not in config
    assert "ssl.ca.location" not in config


def test_consumer_config_disables_auto_commit() -> None:
    settings = KafkaSettings()
    config = consumer_config(
        settings, group_id="soc-normalizer-v1", client_id="soc-normalizer-consumer"
    )

    assert config["enable.auto.commit"] is False
    assert config["group.id"] == "soc-normalizer-v1"
    assert config["auto.offset.reset"] == "earliest"
    assert config["bootstrap.servers"] == "localhost:9092"
