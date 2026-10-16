# Validating the pipeline with real Splunk BOTS v3 data

This document is the manual procedure for getting **one real BOTS v3 export** through
the pipeline built in milestones 2 and 3:

```
real BOTS event -> raw export -> normalization -> normalized JSONL -> evidence timeline
```

Everything here is run by you, on the machine where Splunk is installed. No step in
this project downloads the dataset, queries Splunk, or generates events.

> The fixtures in `tests/splunk_fixtures.py` and `tests/evidence_factory.py` exist only
> to exercise field-alias logic in the automated test suite. They are labelled as such
> in their own docstrings, they are not BOTS evidence, and they must never be used as
> project evidence. Real evidence comes from the export produced below.

## Prerequisites

BOTS v3 obtained from Splunk and installed into a local Splunk instance following
Splunk's own instructions, indexed such that this returns results:

```
index=botsv3 earliest=0
```

The dataset spans a fixed historical window, so `earliest=0` is required on every
search — the default time picker will return nothing.

## Step 1 — Splunk searches to run manually

### A. Dataset verification

Confirms the index is populated and shows what telemetry is actually present.

```
index=botsv3 earliest=0
| stats count by sourcetype
| sort - count
```

Record the output. If this returns no rows, the dataset is not indexed and nothing
below will work.

### B. Inspect a small real sample

```
index=botsv3 earliest=0
| head 50
```

Look at which fields Splunk has extracted, and in particular whether `_time`, `source`,
and `sourcetype` are present on every row. The normalizer requires those plus an event
name.

### C. Inspect one chosen sourcetype

Pick one sourcetype from step A — `aws:cloudtrail` is a good first choice because its
timestamps carry UTC offsets and its field names are well extracted.

```
index=botsv3 earliest=0 sourcetype="<chosen_sourcetype>"
| head 20
| table *
```

`table *` is deliberate: it shows every extracted field name, which is what you need in
order to spot a field shape the normalizer does not yet handle. Compare the column
names against the alias tables at the top of `app/ingestion/splunk.py`.

## Step 2 — Export the real result set, unchanged

From the Splunk UI, run search C and use **Export → JSON**. Save the file, without
editing it in any way, as:

```
data/botsv3/raw/real_export_001.json
```

Equivalently, from the REST API:

```bash
curl -u admin:<password> -k https://localhost:8089/services/search/v2/jobs/export \
  -d output_mode=json \
  -d search='search index=botsv3 earliest=0 sourcetype="aws:cloudtrail" | head 20' \
  > data/botsv3/raw/real_export_001.json
```

Rules for this file:

- **Never modify it in place.** Do not reformat it, do not strip fields, do not fix
  anything in it. Every later stage reads it and writes elsewhere.
- It is **not committed**. `data/botsv3/raw/*` is gitignored, with only a `.gitkeep`
  tracked so the directory exists in a fresh clone.
- If you need a different sample, export it under a new name
  (`real_export_002.json`) rather than overwriting the first.

The normalizer accepts every shape Splunk produces on export, so no conversion is
needed: a JSON array, a single JSON object, a `{"results": [...]}` envelope, or JSON
Lines including the `{"preview": false, "result": {...}}` streaming wrapper.

## Step 3 — Run the pipeline

Either run the helper script, which performs all three stages and stops on the first
fatal problem:

```bash
source .venv/bin/activate
scripts/validate_botsv3.sh data/botsv3/raw/real_export_001.json
```

Or run the stages by hand, which is exactly what the script does:

```bash
# 3a. normalize the raw export into vendor-neutral JSONL
python -m app.ingestion.normalize_file \
  data/botsv3/raw/real_export_001.json \
  -o data/normalized/real_export_001.jsonl

# 3b. reconstruct the deterministic evidence timeline
python -m app.investigation.timeline \
  data/normalized/real_export_001.jsonl

# 3c. print the validation report
python -m app.services.validation \
  --raw data/botsv3/raw/real_export_001.json \
  --normalized data/normalized/real_export_001.jsonl
```

### If the timeline reports mixed timestamps

Real BOTS v3 mixes both kinds: CloudTrail carries UTC offsets, Windows telemetry often
does not. When a single export contains both, ordering stops with:

```
error: cannot order 18 timezone-aware and 2 naive timestamps together; state the zone
the naive timestamps are recorded in to order them explicitly
hint: re-run with --assume-timezone UTC to order them explicitly
```

This is intentional. No timezone is ever assigned silently, because guessing wrong
reorders the investigation by hours. State the zone yourself:

```bash
python -m app.investigation.timeline \
  data/normalized/real_export_001.jsonl \
  --assume-timezone UTC
```

The same flag exists on the script and on the validation report:

```bash
scripts/validate_botsv3.sh data/botsv3/raw/real_export_001.json --assume-timezone UTC

python -m app.services.validation \
  --raw data/botsv3/raw/real_export_001.json \
  --normalized data/normalized/real_export_001.jsonl \
  --assume-timezone UTC
```

The named zone is used **for comparison only**; stored and displayed timestamps stay
exactly as Splunk recorded them. `UTC` is usually right for BOTS v3, but it is your
call to make and it stays visible in your shell history. Other accepted forms are a
fixed offset (`-07:00`) and an IANA name (`America/Los_Angeles`).

The cleanest alternative is to avoid the mix altogether by scoping the export to a
single sourcetype, which is why search C above pins one.

## Step 4 — Read the validation report

The report prints, in order:

- a **source classification** line naming the file as a real BOTS v3 export, plus its
  absolute path, SHA-256, size, and modification time, so the claim is auditable rather
  than decorative;
- total raw records, total normalized records, failed normalization count with a reason
  per failure;
- the sourcetypes present with counts;
- earliest and latest timestamp, and unique users, hosts, source IPs, and destination
  IPs;
- provenance checks: that the raw export's digest is unchanged after processing, that
  every normalized record retained its `raw_event`, that the JSONL on disk matches a
  fresh re-normalization of the raw export, and that every evidence id maps back to its
  own line in the normalized file.

If the raw file is **not** in `data/botsv3/raw/`, the report says so loudly and titles
itself `UNVERIFIED SOURCE LOCATION`, so a tooling check can never be mistaken for real
validation.

Exit codes: `0` clean, `1` if records failed or a provenance check failed, `2` if an
input could not be read or the timestamps could not be ordered.

## Step 5 — If a real field shape is not supported

Requirement: **never fabricate data to make a record pass.** A record that cannot be
normalized should fail and be counted.

When the report shows failures, work through them in this order:

1. Read the failure reason. It names the field and lists every alias that was tried,
   for example `could not resolve required field 'event_name' from any of: eventName,
   signature, action, EventCode, event_name`.
2. Go back to search C for that sourcetype and find what Splunk actually calls the
   field. `| table *` shows the real name.
3. Make the **smallest** possible change in `app/ingestion/splunk.py`: usually one
   added entry in the relevant `*_FIELDS` tuple. Add it at the end so existing
   precedence does not shift. Only write a new parser if the value is a format
   `parse_timestamp` genuinely cannot read.
4. Add a regression test in `tests/test_splunk_normalizer.py` built from the **real**
   field shape you observed — the field names and value formats, not copied event
   content.
5. Record the change in the table below, including why it was needed.

### Field-shape changes discovered in real BOTS v3 data

| Date | Sourcetype | Real field | Change made | Why |
| --- | --- | --- | --- | --- |
| _(none yet — no real export has been processed)_ | | | | |

Leave this table as-is until a real export has actually been run; an empty row is
accurate, and a filled-in row invented from documentation would not be.

## What this milestone does not do

No classification of malicious or benign, no severity grading, no risk scoring, no
MITRE ATT&CK mapping, no transitive correlation, no LLM calls, no LangGraph, no XSOAR,
no vector database, and no database persistence. The point of establishing the facts
deterministically first is that a later reasoning layer can be wrong about what the
evidence *means* without being wrong about what the evidence *is*.
