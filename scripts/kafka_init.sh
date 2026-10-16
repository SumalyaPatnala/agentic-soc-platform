#!/usr/bin/env bash
#
# Idempotently create the local SOC Kafka topics.
#
# Usage:
#   scripts/kafka_init.sh
#   KAFKA_BOOTSTRAP_SERVERS=localhost:9092 scripts/kafka_init.sh
#
# Topics are created with partitions=1, replication-factor=1.
# Re-running is safe: --if-not-exists does not fail if a topic is already there.

set -euo pipefail

BOOTSTRAP="${KAFKA_BOOTSTRAP_SERVERS:-localhost:9092}"
CONTAINER="${KAFKA_CONTAINER:-soc-kafka}"

TOPICS=(
  soc.raw.events
  soc.normalized.events
  soc.evidence.events
  soc.deadletter
)

usage() {
  cat <<'EOF'
Idempotently create local SOC Kafka topics (partitions=1, replication-factor=1).

Usage:
  scripts/kafka_init.sh

Requires the Kafka container from docker-compose.yml to be running.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "error: container $CONTAINER is not running" >&2
  echo "start it with: docker compose up -d" >&2
  exit 2
fi

for topic in "${TOPICS[@]}"; do
  docker exec "$CONTAINER" /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server "$BOOTSTRAP" \
    --create --if-not-exists \
    --topic "$topic" \
    --partitions 1 \
    --replication-factor 1
done

echo "topics:"
docker exec "$CONTAINER" /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server "$BOOTSTRAP" \
  --list
