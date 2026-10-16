# BOTS v3 validation status

**Status: NOT RUN.** Do not claim BOTS v3 validation has happened.

Rechecked 2026-10-08 (Phase 5).

## What was inspected

| Path | Result |
| --- | --- |
| `data/botsv3/raw/` | Only `.gitkeep`. No `real_export_*.json`. |
| `data/normalized/` | Empty of exports. |
| `splunk` on `PATH` | Not found. |
| `/Applications/Splunk/bin/splunk` | Binary exists on this machine. That is not an indexed `botsv3` export and was **not queried** (would require credentials; this project does not log in). |
| Documented procedure | `docs/botsv3-validation.md`. Field-shape table still empty. |

No alternative public telemetry was ingested and relabeled as BOTS v3.

## Blockers (exact)

1. No real BOTS v3 JSON export at `data/botsv3/raw/real_export_001.json`.
2. No confirmed `index=botsv3 earliest=0` result set obtained through this repository's documented workflow.
3. BOTS v3 is Splunk's dataset; it is not redistributed here.
4. A local Splunk application tree is insufficient without an authorized export sitting in `data/botsv3/raw/`.

## Software verification (not BOTS)

Pytest on schema, normalizer, correlation, timeline, and validation remains the verified layer. Fixture events in `tests/splunk_fixtures.py` are schema-shape fixtures, not BOTS evidence.

Repeatability of evidence IDs is covered by unit tests: `format_evidence_id(order)` is `ev-{order:06d}` and `build_evidence` is a pure function of the event sequence.

## How to run when an export exists

Follow `docs/botsv3-validation.md` without editing the export:

```bash
source .venv/bin/activate
scripts/validate_botsv3.sh data/botsv3/raw/real_export_001.json --assume-timezone UTC
```

Until that command produces a report from a real export, public copy must say the pipeline has not been validated on BOTS v3 data.
