#!/usr/bin/env bash
#
# Run one real Splunk BOTS v3 export through the deterministic pipeline:
#
#   raw export -> normalization -> normalized JSONL -> evidence timeline -> report
#
# The raw export is only ever read. Nothing is written to data/botsv3/raw/.
#
# Usage:
#   scripts/validate_botsv3.sh [RAW_EXPORT] [--assume-timezone TZ]
#
# Defaults to data/botsv3/raw/real_export_001.json. Activate the virtualenv first, or
# set PYTHON to the interpreter to use.
#
# If the export mixes naive and timezone-aware timestamps, this script stops and prints
# the explicit fallback command rather than choosing a timezone for you.

set -uo pipefail

PYTHON="${PYTHON:-python}"
RAW="data/botsv3/raw/real_export_001.json"
TZ_ARGS=()

usage() {
  cat <<'EOF'
Run one real Splunk BOTS v3 export through the deterministic pipeline:

  raw export -> normalization -> normalized JSONL -> evidence timeline -> report

Usage:
  scripts/validate_botsv3.sh [RAW_EXPORT] [--assume-timezone TZ]

  RAW_EXPORT            untouched real export; defaults to
                        data/botsv3/raw/real_export_001.json
  --assume-timezone TZ  zone that naive timestamps are recorded in, needed only to
                        order a mix of naive and offset-bearing timestamps

The raw export is only ever read. Nothing is written to data/botsv3/raw/.
Activate the virtualenv first, or set PYTHON to the interpreter to use.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --assume-timezone)
      if [[ $# -lt 2 ]]; then
        echo "error: --assume-timezone needs a value" >&2
        exit 2
      fi
      TZ_ARGS=(--assume-timezone "$2")
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "error: unknown option: $1" >&2
      exit 2
      ;;
    *)
      RAW="$1"
      shift
      ;;
  esac
done

if [[ ! -f "$RAW" ]]; then
  echo "error: no such export: $RAW" >&2
  echo "export a real BOTS v3 result set from Splunk first; see docs/botsv3-validation.md" >&2
  exit 2
fi

case "$(cd "$(dirname "$RAW")" && pwd)" in
  */data/botsv3/raw) ;;
  *)
    echo "warning: $RAW is not in data/botsv3/raw/, the documented location for" >&2
    echo "warning: untouched real exports. The report will flag this run as unverified." >&2
    ;;
esac

STEM="$(basename "$RAW")"
STEM="${STEM%.*}"
NORMALIZED="data/normalized/${STEM}.jsonl"

echo "==> 1/3 normalizing $RAW"
"$PYTHON" -m app.ingestion.normalize_file "$RAW" -o "$NORMALIZED"
status=$?
if [[ $status -ge 2 ]]; then
  echo "error: normalization could not read the export (exit $status)" >&2
  exit "$status"
fi
if [[ $status -eq 1 ]]; then
  echo "note: some records failed to normalize; they are listed above and counted below"
fi

echo
echo "==> 2/3 reconstructing the evidence timeline"
"$PYTHON" -m app.investigation.timeline "$NORMALIZED" "${TZ_ARGS[@]+"${TZ_ARGS[@]}"}"
status=$?
if [[ $status -ge 2 ]]; then
  if [[ ${#TZ_ARGS[@]} -eq 0 ]]; then
    echo >&2
    echo "The export mixes naive and timezone-aware timestamps, so no ordering is" >&2
    echo "possible without stating which zone the naive values are recorded in." >&2
    echo "Re-run with the zone made explicit, for example:" >&2
    echo >&2
    echo "  scripts/validate_botsv3.sh $RAW --assume-timezone UTC" >&2
  fi
  exit "$status"
fi

echo
echo "==> 3/3 validation report"
"$PYTHON" -m app.services.validation \
  --raw "$RAW" \
  --normalized "$NORMALIZED" \
  "${TZ_ARGS[@]+"${TZ_ARGS[@]}"}"
status=$?

echo
if [[ $status -eq 0 ]]; then
  echo "pipeline validation: clean"
else
  echo "pipeline validation: completed with findings (exit $status); see the counts above"
fi
exit "$status"
