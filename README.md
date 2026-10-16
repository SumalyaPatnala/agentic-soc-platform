# agentic-soc-platform

Production-style Agentic SOC platform using Splunk security telemetry, LangGraph, XSOAR-inspired playbooks, FastAPI, Docker, Kubernetes, observability, and evaluation.

## Purpose

The platform will investigate and respond to security alerts the way a Tier 1/Tier 2
SOC analyst does: pull telemetry from a SIEM, enrich the indicators, correlate related
activity into a single incident narrative, and then drive a containment playbook. The
long-term design goal is vendor neutrality — telemetry from Splunk, CrowdStrike, Okta,
AWS GuardDuty, and network firewalls all normalize into one internal event shape so the
agents never need vendor-specific logic.

## Current milestone

**Milestone 5 — local Apache Kafka streaming.** The repository contains:

- a FastAPI application with `GET /health`, `GET /health/kafka`, and `POST /events/normalize`,
- the vendor-neutral `SecurityEvent` Pydantic model and the `EvidenceRecord` wrapper
  that gives each event a traceable identity,
- `SplunkBOTSEventNormalizer`, which maps exported Splunk events onto that model
  using per-field alias lists rather than per-sourcetype branching,
- deterministic correlation and timeline utilities in `app/investigation/`,
- a local Apache Kafka streaming layer (KRaft, Docker Compose, PLAINTEXT, $0),
- a validation report that proves a real export survived the file pipeline with its
  provenance intact,
- CLIs for file normalization, timeline, validation, Kafka produce, and Kafka consume,
- empty packages reserving the shape of future work (`agents`, `graph`, `tools`),
- pytest coverage for every one of the above.

The file-based BOTS v3 validation tooling is written and tested, but **it has not yet
been run against a real BOTS v3 export**. Kafka streaming of real BOTS records is the
same: the adapter is ready, and it must not be called validated until a real Splunk
export is published. Fixture-only Kafka tests are labeled as such.

Deliberately **not** implemented yet: LangGraph orchestration, XSOAR-style response
workflows, vector databases, LLM calls, Kubernetes manifests, databases, auth, and
background workers other than the Kafka consumers. Normalized events are published to
Kafka or written to disk; nothing is persisted to a datastore.

## Requirements

- Python 3.11+

## Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

Optionally copy the sample configuration (no value in it is read yet):

```bash
cp .env.example .env
```

## Run the API

```bash
uvicorn app.main:app --reload
```

Then verify:

```bash
curl http://127.0.0.1:8000/health
# {"status":"ok","service":"agentic-soc-platform"}
```

Interactive docs are at http://127.0.0.1:8000/docs.

## Run the tests

```bash
pytest
```

## Using real Splunk BOTS v3 data

This project is built against **real public security telemetry only**. There is no
synthetic incident dataset, and no fabricated alerts are generated anywhere in the
codebase. The test suite contains a handful of *schema-shape fixtures*
(`tests/splunk_fixtures.py`) whose only job is to exercise field-alias logic; they are
labelled as such and are not BOTS evidence.

### The dataset is not in this repository

Splunk's Boss of the SOC v3 dataset is distributed by Splunk as pre-indexed Splunk
data and is not redistributed here. `data/botsv3/` and `data/normalized/` are empty
placeholders and their contents are gitignored.

### Load BOTS v3 into Splunk

Obtain BOTS v3 from Splunk and install it into a local Splunk instance following
Splunk's own instructions. Once indexed it is searchable as:

```
index=botsv3 earliest=0
```

The dataset includes sourcetypes such as `aws:cloudtrail`, `aws:cloudwatch`,
`aws:cloudwatch:guardduty`, `aws:cloudwatchlogs`, `aws:cloudwatchlogs:vpcflow`, and
Windows `WinEventLog`/Sysmon telemetry.

### Export real events from Splunk

Run a search scoped to what you want to investigate and export the results as JSON.
From the Splunk UI use *Export → JSON*; from the CLI/REST API, for example:

```bash
curl -u admin:<password> -k https://localhost:8089/services/search/v2/jobs/export \
  -d output_mode=json \
  -d search='search index=botsv3 sourcetype=aws:cloudtrail earliest=0 | head 500' \
  > data/botsv3/cloudtrail_sample.json
```

The normalizer accepts every shape Splunk produces on export: a JSON array, a single
JSON object, a `{"results": [...]}` envelope, and JSON Lines including the
`{"preview": false, "result": {...}}` streaming wrapper.

### Normalize the export

A whole file at once, printing a summary and writing JSONL to `data/normalized/`:

```bash
python -m app.ingestion.normalize_file data/botsv3/cloudtrail_sample.json --out
```

```
total: 500
normalized: 498
failed: 2
wrote 498 events to data/normalized/cloudtrail_sample.normalized.jsonl
```

Failed records are reported individually on stderr with the reason, and a bad record
never aborts the rest of the file. The exit code is `0` for a clean run, `1` if any
record failed, and `2` if the file itself could not be read or parsed.

One event at a time, over HTTP:

```bash
curl -X POST http://127.0.0.1:8000/events/normalize \
  -H 'Content-Type: application/json' \
  -d @event.json
```

An event that cannot be normalized returns `422` with an explanation. Nothing is
persisted by either path.

### How normalization behaves

`timestamp`, `source`, `sourcetype`, and `event_name` are required. If any of them
cannot be resolved from a known alias, the record fails loudly with the list of
aliases that were tried — a timestamp is never invented. Optional fields become
`null` when absent. The untouched original payload is always kept in
`SecurityEvent.raw_event`, so a field the current alias table misses is never lost and
can be picked up later. Values are copied, not interpreted: a numeric GuardDuty
`severity` of `2.0` becomes the string `"2.0"` rather than being graded as "low".

## Real BOTS v3 validation

The full manual procedure lives in [`docs/botsv3-validation.md`](docs/botsv3-validation.md).
This is the short version of the rules it enforces.

**Fixtures are for automated schema testing only.** `tests/splunk_fixtures.py` and
`tests/evidence_factory.py` build hand-written events whose sole purpose is to exercise
field-alias and ordering logic in the test suite. Each says so in its own docstring.
They are never project evidence, and nothing in the codebase generates security events.

**Real project evidence comes from exported Splunk BOTS v3 records.** You load BOTS v3
into your own Splunk, search it with `index=botsv3 earliest=0`, and export a small real
result set as JSON to `data/botsv3/raw/real_export_001.json`.

**The raw export stays untouched.** It is never edited, reformatted, or written back to.
Every stage reads it and writes elsewhere, and the validation report takes its SHA-256
before and after processing so "untouched" is a stated result rather than an assumption.
`data/botsv3/raw/*` is gitignored with only a `.gitkeep` tracked, so real telemetry
never lands in version control.

**Deterministic processing happens before any AI reasoning.** Normalization and timeline
reconstruction are reproducible and interpretation-free, so a later reasoning layer can
be wrong about what the evidence *means* without being wrong about what it *is*.

Run all three stages:

```bash
source .venv/bin/activate
scripts/validate_botsv3.sh data/botsv3/raw/real_export_001.json
```

Or by hand:

```bash
python -m app.ingestion.normalize_file \
  data/botsv3/raw/real_export_001.json \
  -o data/normalized/real_export_001.jsonl

python -m app.investigation.timeline \
  data/normalized/real_export_001.jsonl

python -m app.services.validation \
  --raw data/botsv3/raw/real_export_001.json \
  --normalized data/normalized/real_export_001.jsonl
```

If the export mixes naive and timezone-aware timestamps, ordering stops and tells you
so. Add `--assume-timezone UTC` to state the zone yourself; no timezone is ever assigned
silently. See [naive versus timezone-aware timestamps](#naive-versus-timezone-aware-timestamps).

The report names the source file, its digest, and its classification. A file outside
`data/botsv3/raw/` is titled `UNVERIFIED SOURCE LOCATION`, so a tooling check can never
be mistaken for real-data validation.

## Deterministic evidence processing

Everything in `app/investigation/` is deterministic: the same input always produces
byte-identical output, and no step infers, scores, or classifies anything. This layer
deliberately sits *before* any AI reasoning, for three reasons.

**Facts and interpretation must be separable.** Whether two events share a source IP
is a fact. Whether that sharing is suspicious is an interpretation. If a model
produces both, a reviewer cannot tell which part to check. Computing the facts here
means a later reasoning layer can be wrong about what a grouping *means* while never
being wrong about which events shared a value.

**Reproducibility is a prerequisite for evaluation.** A future milestone will measure
agent quality. That is only meaningful if the evidence the agent was given is
identical across runs, so the correlation and ordering it depends on must not vary.

**Token budgets are finite.** Grouping and ordering a 50,000-event export down to the
handful of records that touch one host is cheap and exact. Asking a model to do it is
neither.

### The evidence record

`EvidenceRecord` wraps a normalized `SecurityEvent` and adds only provenance:

| Field | Meaning |
| --- | --- |
| `evidence_id` | Stable id such as `ev-000004`, derived from `order` |
| `normalized_event` | The event, including its untouched `raw_event` |
| `order` | Zero-based position in the source; for JSONL, the line number minus one |

`SecurityEvent` itself is unchanged. Because `order` is the source position,
`ev-000004` is line 5 of the normalized file, so every rendered timeline row can be
traced to a specific line and from there to the original Splunk payload.

### Event correlation

Correlation means grouping evidence by an identifier that is literally present in the
events. The correlatable fields are `user`, `host`, `src_ip`, and `dest_ip`.

```python
from app.investigation.correlation import group_by_user, shared_value_groups
from app.investigation.timeline import load_evidence

records, failures = load_evidence(Path("data/normalized/export.normalized.jsonl"))

by_user = group_by_user(records)                        # {"alpha": [EvidenceRecord, ...]}
pivots = shared_value_groups(records, "src_ip")         # only IPs seen more than once
```

Records with no value for the field are **omitted from the result entirely** rather
than collected under a shared `None` key. Two events that both lack a username do not
share a user, and bucketing them together would manufacture a correlation the
telemetry does not support. Group keys appear in order of first occurrence and members
keep their input order, so results are reproducible.

### Evidence timeline

```bash
python -m app.investigation.timeline data/normalized/export.normalized.jsonl
```

```
total events: 5
earliest timestamp: 2018-08-20T09:30:00
latest timestamp: 2018-08-20T15:22:10+00:00
unique users: 1 (alpha)
unique hosts: 3 (111111111111, EXAMPLE-WKS01, i-0example1234abcd)
unique source IPs: 2 (198.51.100.14, 203.0.113.25)
unique destination IPs: 1 (10.0.1.42)

timeline:
2018-08-20T13:01:46+00:00  ev-000000  aws:cloudtrail              DescribeInstances  user=alpha host=111111111111 src=203.0.113.25
2018-08-20T14:05:00+00:00  ev-000003  aws:cloudwatchlogs:vpcflow  ACCEPT             host=i-0example1234abcd src=203.0.113.25 dest=10.0.1.42
```

Every row leads with its `evidence_id`, so a row is always traceable back to the
normalized record and its `raw_event`. Any `severity` shown is the vendor's own value
copied through by normalization — nothing in this layer assigns or grades severity.

Filters are exact-match and combine with AND:

```bash
python -m app.investigation.timeline <file> --user alpha
python -m app.investigation.timeline <file> --host wks01 --src-ip 203.0.113.25
python -m app.investigation.timeline <file> --dest-ip 10.0.1.42
```

A record with no value for a filtered field never matches, consistent with how
correlation treats an unset field.

### Naive versus timezone-aware timestamps

BOTS v3 mixes both: CloudTrail carries UTC offsets, Windows telemetry frequently does
not. Python cannot compare a naive datetime with an aware one, and the tempting fix —
quietly stamping UTC onto the naive values — would silently invent an offset and
could reorder an investigation by hours.

So ordering a mixed set **fails loudly** instead:

```
error: cannot order 4 timezone-aware and 1 naive timestamps together; state the zone
the naive timestamps are recorded in to order them explicitly
hint: re-run with --assume-timezone UTC to order them explicitly
```

Naming the zone makes the assumption yours and puts it in your shell history:

```bash
python -m app.investigation.timeline <file> --assume-timezone UTC
python -m app.investigation.timeline <file> --assume-timezone America/Los_Angeles
python -m app.investigation.timeline <file> --assume-timezone -07:00
```

The assumed zone is used **for comparison only**. Stored and rendered timestamps stay
exactly as they were recorded, which is why the sample output above shows a naive
`earliest timestamp` next to an offset-bearing `latest timestamp`. A set that is
uniformly naive or uniformly aware sorts with no flag at all. Equal timestamps keep
source order, decided by `order` rather than by however the caller arranged the list.

The exit code is `0` for a clean run, `1` if any line failed to load, and `2` if the
file could not be read or the timestamps could not be ordered.

## Local Kafka Streaming

Local Apache Kafka in KRaft mode, run with Docker Compose. **Cost: $0. Cloud
services: none. Confluent Cloud: not used.** The Python package `confluent-kafka` is
only the client library talking to this local broker. ZooKeeper is not used.
Delivery is **at-least-once**: a consumer may see a duplicate if it crashes after
publishing downstream and before committing. Downstream stages must tolerate that.
This is not exactly-once.

```
Splunk/BOTS
   ↓
Kafka raw topic          soc.raw.events
   ↓
Normalizer consumer      group soc-normalizer-v1
   ↓                     (existing SplunkBOTSEventNormalizer)
Normalized topic         soc.normalized.events
   ↓
Evidence consumer        group soc-evidence-v1
   ↓                     (existing EvidenceRecord / format_evidence_id)
Evidence topic           soc.evidence.events
   ↓
Timeline / Agents        (file CLI today; agents later)
```

Failures at either consumer stage go to `soc.deadletter` with `failed_stage`,
`error_type`, `error_message`, and the original event. Stack traces stay in local
logs, not in the DLQ payload.

`GET /health` does **not** depend on Kafka. `GET /health/kafka` reports broker
reachability separately.

### 1. Start Kafka

```bash
docker compose up -d
```

Wait until `soc-kafka` is healthy. `soc-kafka-init` creates the four topics once and
exits.

### 2. Check container status

```bash
docker compose ps
curl -s http://127.0.0.1:8000/health/kafka
```

### 3. Create or list topics

Topics are created automatically by `kafka-init`. To re-run idempotently:

```bash
scripts/kafka_init.sh
docker exec soc-kafka /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server localhost:9092 --list
```

### 4. Start the normalizer consumer

```bash
python -m app.ingestion.kafka_consumer normalizer
```

### 5. Start the evidence consumer

```bash
python -m app.ingestion.kafka_consumer evidence
```

### 6. Produce a labeled test fixture (NOT BOTS data)

```bash
python -m app.ingestion.kafka_producer \
  tests/fixtures/kafka_smoke_event.json \
  --source test-fixture
```

That file is marked `TEST FIXTURE — NOT BOTS DATA`. Publishing it validates
infrastructure, not BOTS.

To publish a **real** untouched Splunk export later (when you have one):

```bash
python -m app.ingestion.kafka_producer \
  data/botsv3/raw/real_export_001.json \
  --source splunk-export
```

The producer does not query Splunk and does not modify the file.

### 7. Inspect topic messages

```bash
python -m app.ingestion.kafka_consumer inspect soc.raw.events --max 10
python -m app.ingestion.kafka_consumer inspect soc.normalized.events --max 10
python -m app.ingestion.kafka_consumer inspect soc.evidence.events --max 10
python -m app.ingestion.kafka_consumer inspect soc.deadletter --max 10
```

Or with Kafka's console consumer:

```bash
docker exec soc-kafka /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 \
  --topic soc.raw.events \
  --from-beginning \
  --timeout-ms 5000
```

### 8. Stop Kafka

```bash
docker compose down
```

Add `-v` only if you also want to delete the local Kafka volume.

### Environment

See `.env.example`. Defaults:

```
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
KAFKA_RAW_TOPIC=soc.raw.events
KAFKA_NORMALIZED_TOPIC=soc.normalized.events
KAFKA_EVIDENCE_TOPIC=soc.evidence.events
KAFKA_DLQ_TOPIC=soc.deadletter
```

### Tests

Unit tests mock Kafka and always run. Optional live-broker tests:

```bash
RUN_KAFKA_INTEGRATION=1 pytest tests/test_kafka_integration.py
```

Those still use schema fixtures, not BOTS evidence.

Streaming evidence ids are `format_evidence_id(kafka_offset)` on partition 0, so the
same offset always yields the same `ev-NNNNNN`. File-pipeline evidence ids remain
line-based. Both use the same formatter.

## Run in Docker

```bash
docker build -t agentic-soc-platform .
docker run --rm -p 8000:8000 agentic-soc-platform
```

## Layout

```
app/
  main.py                        FastAPI app, /health, /health/kafka, /events/normalize
  models/security_event.py       vendor-neutral SecurityEvent
  models/evidence.py             EvidenceRecord provenance wrapper
  models/kafka_envelope.py       transport envelope + DLQ record
  ingestion/splunk.py            SplunkBOTSEventNormalizer and field-alias tables
  ingestion/normalize_file.py    bulk normalization CLI
  ingestion/kafka_producer.py    local Kafka producer CLI
  ingestion/kafka_consumer.py    normalizer/evidence consumers and inspect CLI
  investigation/correlation.py   deterministic grouping by shared identifiers
  investigation/timeline.py      deterministic ordering, summary, and timeline CLI
  services/validation.py         pipeline validation report CLI
  streaming/config.py            KAFKA_* environment settings
  agents/                        investigation agents (later)
  graph/                         agent orchestration (later)
  tools/                         agent-callable tools (later)
data/botsv3/raw/                 untouched real Splunk exports (not committed)
data/normalized/                 CLI output (not committed)
docs/botsv3-validation.md        manual real-data validation procedure
scripts/validate_botsv3.sh       runs the file pipeline stages
scripts/kafka_init.sh            idempotent local topic create/list
docker-compose.yml               Apache Kafka (KRaft), $0, no ZooKeeper
tests/                           pytest suite
tests/fixtures/kafka_smoke_event.json   TEST FIXTURE — NOT BOTS DATA
```
