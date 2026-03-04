#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  upload_bom_and_fetch_metrics.sh --bom-file <file> --project-suffix <suffix> [options]

Required:
  --bom-file <file>          BOM JSON file (e.g. bom_syft.json)
  --project-suffix <suffix>  Project suffix (e.g. syft, berry)

Optional:
  --repo <owner/repo>        Defaults to GITHUB_REPOSITORY
  --pr-number <num>          Defaults to PR_NUMBER
  --ref-name <name>          Defaults to GITHUB_REF_NAME or main
  --dtrack-url <url>         Defaults to DTRACK_URL
  --dtrack-api-key <key>     Defaults to DTRACK_API_KEY
  --wait-seconds <n>         Defaults to 5
  --max-wait-attempts <n>    Defaults to 120

Behavior:
  1) Upload BOM and wait for processing
  2) Resolve project UUID and fetch metrics
  3) Trigger analysis and wait for completion
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

require_cmd curl
require_cmd jq

bom_file=""
project_suffix=""
repo="${GITHUB_REPOSITORY:-}"
pr_number="${PR_NUMBER:-}"
ref_name="${GITHUB_REF_NAME:-main}"
dtrack_url="${DTRACK_URL:-}"
dtrack_api_key="${DTRACK_API_KEY:-}"
wait_seconds=5
max_wait_attempts=120

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bom-file) bom_file="${2:-}"; shift 2 ;;
    --project-suffix) project_suffix="${2:-}"; shift 2 ;;
    --repo) repo="${2:-}"; shift 2 ;;
    --pr-number) pr_number="${2:-}"; shift 2 ;;
    --ref-name) ref_name="${2:-}"; shift 2 ;;
    --dtrack-url) dtrack_url="${2:-}"; shift 2 ;;
    --dtrack-api-key) dtrack_api_key="${2:-}"; shift 2 ;;
    --wait-seconds) wait_seconds="${2:-}"; shift 2 ;;
    --max-wait-attempts) max_wait_attempts="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

[[ -n "$bom_file" ]] || { echo "--bom-file is required" >&2; exit 1; }
[[ -n "$project_suffix" ]] || { echo "--project-suffix is required" >&2; exit 1; }
[[ -f "$bom_file" ]] || { echo "$bom_file not found" >&2; exit 1; }
[[ -n "$repo" ]] || { echo "Missing repo (--repo or GITHUB_REPOSITORY)" >&2; exit 1; }
[[ -n "$dtrack_url" ]] || { echo "Missing dtrack url (--dtrack-url or DTRACK_URL)" >&2; exit 1; }
[[ -n "$dtrack_api_key" ]] || { echo "Missing dtrack api key (--dtrack-api-key or DTRACK_API_KEY)" >&2; exit 1; }
[[ "$wait_seconds" =~ ^[0-9]+$ ]] || { echo "--wait-seconds must be numeric" >&2; exit 1; }
[[ "$max_wait_attempts" =~ ^[0-9]+$ ]] || { echo "--max-wait-attempts must be numeric" >&2; exit 1; }

dtrack_url="${dtrack_url%/}"
project_name="${repo}-${project_suffix}"

if [[ -n "$pr_number" ]]; then
  project_version="pr-${pr_number}"
else
  project_version="${ref_name:-main}"
fi

token="$(
  curl -sSf -X POST "$dtrack_url/api/v1/bom" \
    -H "X-Api-Key: $dtrack_api_key" \
    -F "projectName=$project_name" \
    -F "projectVersion=$project_version" \
    -F "autoCreate=true" \
    -F "bom=@$bom_file" \
  | jq -r '.token // empty'
)"

[[ -n "$token" ]] || { echo "Dependency-Track upload returned empty token" >&2; exit 1; }
echo "Dependency-Track token: $token"

echo "Waiting for Dependency-Track to finish processing..."
processing="true"
for ((i=1; i<=max_wait_attempts; i++)); do
  processing="$(
    curl -sSf "$dtrack_url/api/v1/bom/token/$token" \
      -H "X-Api-Key: $dtrack_api_key" \
    | jq -r '.processing'
  )"
  if [[ "$processing" == "false" ]]; then
    echo "Processing finished."
    break
  fi
  sleep "$wait_seconds"
done

[[ "$processing" == "false" ]] || { echo "Timed out waiting for BOM processing" >&2; exit 1; }

project_name_enc="$(printf '%s' "$project_name" | jq -sRr @uri)"
project_version_enc="$(printf '%s' "$project_version" | jq -sRr @uri)"

project="$(
  curl -sSf \
    "$dtrack_url/api/v1/project/lookup?name=${project_name_enc}&version=${project_version_enc}" \
    -H "X-Api-Key: $dtrack_api_key"
)"

project_uuid="$(echo "$project" | jq -r '.uuid // empty')"
[[ -n "$project_uuid" ]] || { echo "Could not resolve project UUID: $project" >&2; exit 1; }
echo "Project UUID: $project_uuid"

metrics="$(
  curl -sSf "$dtrack_url/api/v1/metrics/project/$project_uuid/current" \
    -H "X-Api-Key: $dtrack_api_key"
)"

critical="$(echo "$metrics" | jq -r '.critical // 0' | tr -d '\r\n ')"
high="$(echo "$metrics" | jq -r '.high // 0' | tr -d '\r\n ')"

[[ "$critical" =~ ^[0-9]+$ ]] || { echo "Invalid critical metric: $critical" >&2; exit 1; }
[[ "$high" =~ ^[0-9]+$ ]] || { echo "Invalid high metric: $high" >&2; exit 1; }

echo "=== Metrics ==="
echo "$metrics" | jq '{critical, high, medium, low, unassigned, vulnerabilities, vulnerableComponents, components}'
echo "Collected gate values: critical=[$critical] high=[$high]"

analysis_token="$(
  curl -sSf -X POST "$dtrack_url/api/v1/finding/project/$project_uuid/analyze" \
    -H "X-Api-Key: $dtrack_api_key" \
  | jq -r '.token // empty'
)"
[[ -n "$analysis_token" ]] || { echo "Dependency-Track analysis token was empty" >&2; exit 1; }

echo "Waiting for Dependency-Track analysis to finish..."
analysis_processing="true"
for ((i=1; i<=max_wait_attempts; i++)); do
  analysis_processing="$(
    curl -sSf "$dtrack_url/api/v1/event/token/$analysis_token" \
      -H "X-Api-Key: $dtrack_api_key" \
    | jq -r '.processing'
  )"
  if [[ "$analysis_processing" == "false" ]]; then
    echo "Analysis finished."
    break
  fi
  sleep "$wait_seconds"
done

[[ "$analysis_processing" == "false" ]] || { echo "Timed out waiting for Dependency-Track analysis" >&2; exit 1; }

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "project_uuid=$project_uuid"
    echo "critical=$critical"
    echo "high=$high"
  } >> "$GITHUB_OUTPUT"
fi
