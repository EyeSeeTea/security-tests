#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  report_open_code_scanning_alert_instances.sh [options]

Options:
  --repo <owner/repo>         Default: $GITHUB_REPOSITORY
  --tool-name <name>          Default: $TOOL_NAME
  --head-ref <refs/...>       Head ref to inspect (required unless --ref or $REF is set)
  --base-ref <refs/...>       Optional base ref for comparison
  --ref <refs/...>            Backward-compatible alias for --head-ref
  --token <token>             Default: $GH_TOKEN or $GITHUB_TOKEN
  --api-url <url>             Default: $GITHUB_API_URL or https://api.github.com
  --output-prefix <name>      Default: open_alerts
  -h, --help                  Show this help
EOF
}

normalize_ref() {
  local value="$1"
  if [[ "$value" == refs/* ]]; then
    echo "$value"
  else
    echo "refs/heads/${value#refs/heads/}"
  fi
}

normalize_severity_stream() {
  jq -r '
    (.rule.security_severity_level // .rule.severity // "unknown")
    | ascii_downcase
    | if . == "error" then "high"
      elif . == "warning" or . == "moderate" then "medium"
      elif . == "note" then "low"
      else .
      end
  '
}

count_severity() {
  local file="$1"
  local severity="$2"
  awk -v target="$severity" '$0 == target { c++ } END { print c + 0 }' < <(
    normalize_severity_stream <"$file"
  )
}

fetch_open_alerts_jsonl() {
  local ref="$1"
  local out_file="$2"
  local page=1
  : > "$out_file"

  while :; do
    local batch
    batch="$(
      curl -sSfL --get \
        -H "Authorization: Bearer $token" \
        -H "Accept: application/vnd.github+json" \
        --data-urlencode "state=open" \
        --data-urlencode "tool_name=$tool_name" \
        --data-urlencode "ref=$ref" \
        --data-urlencode "per_page=100" \
        --data-urlencode "page=$page" \
        "$api_url/repos/$repo/code-scanning/alerts"
    )"

    local count
    count="$(jq 'length' <<<"$batch")"
    [ "$count" -eq 0 ] && break

    jq -c '.[]' <<<"$batch" >> "$out_file"
    page=$((page + 1))
  done
}

repo="${GITHUB_REPOSITORY:-}"
tool_name="${TOOL_NAME:-}"
head_ref="${REF:-}"
base_ref="${BASE_REF:-}"
token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
api_url="${GITHUB_API_URL:-https://api.github.com}"
output_prefix="open_alerts"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo) repo="$2"; shift 2 ;;
    --tool-name) tool_name="$2"; shift 2 ;;
    --head-ref) head_ref="$2"; shift 2 ;;
    --base-ref) base_ref="$2"; shift 2 ;;
    --ref) head_ref="$2"; shift 2 ;;
    --token) token="$2"; shift 2 ;;
    --api-url) api_url="$2"; shift 2 ;;
    --output-prefix) output_prefix="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ -z "$repo" ]; then
  echo "Missing --repo (or GITHUB_REPOSITORY)." >&2
  exit 1
fi
if [ -z "$tool_name" ]; then
  echo "Missing --tool-name (or TOOL_NAME)." >&2
  exit 1
fi
if [ -z "$head_ref" ]; then
  echo "Missing --head-ref (or --ref/REF)." >&2
  exit 1
fi
if [ -z "$token" ]; then
  echo "Missing --token (or GH_TOKEN/GITHUB_TOKEN)." >&2
  exit 1
fi

head_ref="$(normalize_ref "$head_ref")"
if [ -n "$base_ref" ]; then
  base_ref="$(normalize_ref "$base_ref")"
fi

head_tmp="$(mktemp)"
base_tmp="$(mktemp)"
trap 'rm -f "$head_tmp" "$base_tmp"' EXIT

fetch_open_alerts_jsonl "$head_ref" "$head_tmp"
if [ -n "$base_ref" ]; then
  fetch_open_alerts_jsonl "$base_ref" "$base_tmp"
else
  : > "$base_tmp"
fi

head_instances="$(wc -l < "$head_tmp" | tr -d ' ')"
head_unique_rule_ids="$(jq -r '.rule.id // empty' "$head_tmp" | sed '/^$/d' | sort -u | wc -l | tr -d ' ')"
head_critical="$(count_severity "$head_tmp" "critical")"
head_high="$(count_severity "$head_tmp" "high")"
head_medium="$(count_severity "$head_tmp" "medium")"
head_low="$(count_severity "$head_tmp" "low")"
head_unknown="$(count_severity "$head_tmp" "unknown")"

base_instances=0
base_unique_rule_ids=0
base_critical=0
base_high=0
base_medium=0
base_low=0
base_unknown=0
introduced_instances=0
introduced_critical=0
introduced_high=0
introduced_medium=0
introduced_low=0
introduced_unknown=0
baseline_missing="false"

if [ -n "$base_ref" ]; then
  base_instances="$(wc -l < "$base_tmp" | tr -d ' ')"
  base_unique_rule_ids="$(jq -r '.rule.id // empty' "$base_tmp" | sed '/^$/d' | sort -u | wc -l | tr -d ' ')"
  base_critical="$(count_severity "$base_tmp" "critical")"
  base_high="$(count_severity "$base_tmp" "high")"
  base_medium="$(count_severity "$base_tmp" "medium")"
  base_low="$(count_severity "$base_tmp" "low")"
  base_unknown="$(count_severity "$base_tmp" "unknown")"

  if [ "$base_instances" -eq 0 ]; then
    baseline_missing="true"
  fi

  introduced_json="$(
    jq -s --slurpfile base "$base_tmp" '
      def norm:
        ascii_downcase
        | if . == "error" then "high"
          elif . == "warning" or . == "moderate" then "medium"
          elif . == "note" then "low"
          else .
          end;
      ($base | map(.number) | unique) as $base_numbers
      | [ .[] | select((.number as $n | $base_numbers | index($n) | not)) ] as $introduced
      | {
          total: ($introduced | length),
          critical: ($introduced | map((.rule.security_severity_level // .rule.severity // "unknown" | norm)) | map(select(. == "critical")) | length),
          high: ($introduced | map((.rule.security_severity_level // .rule.severity // "unknown" | norm)) | map(select(. == "high")) | length),
          medium: ($introduced | map((.rule.security_severity_level // .rule.severity // "unknown" | norm)) | map(select(. == "medium")) | length),
          low: ($introduced | map((.rule.security_severity_level // .rule.severity // "unknown" | norm)) | map(select(. == "low")) | length),
          unknown: ($introduced | map((.rule.security_severity_level // .rule.severity // "unknown" | norm)) | map(select(. == "unknown")) | length)
        }
    ' "$head_tmp"
  )"

  introduced_instances="$(jq -r '.total' <<<"$introduced_json")"
  introduced_critical="$(jq -r '.critical' <<<"$introduced_json")"
  introduced_high="$(jq -r '.high' <<<"$introduced_json")"
  introduced_medium="$(jq -r '.medium' <<<"$introduced_json")"
  introduced_low="$(jq -r '.low' <<<"$introduced_json")"
  introduced_unknown="$(jq -r '.unknown' <<<"$introduced_json")"
fi

echo "Repository: $repo"
echo "Tool name: $tool_name"
echo "Head ref: $head_ref"
if [ -n "$base_ref" ]; then
  echo "Base ref: $base_ref"
fi
echo "Open alert instances (UI) in head: $head_instances"
echo "Unique rule.id in head: $head_unique_rule_ids"
echo "Open instances by severity in head (critical/high/medium/low/unknown): $head_critical/$head_high/$head_medium/$head_low/$head_unknown"

if [ -n "$base_ref" ]; then
  echo "Open alert instances (UI) in base: $base_instances"
  echo "Unique rule.id in base: $base_unique_rule_ids"
  echo "Open instances by severity in base (critical/high/medium/low/unknown): $base_critical/$base_high/$base_medium/$base_low/$base_unknown"
  echo "New alert instances vs base (head - base): $introduced_instances"
  echo "New instances by severity (critical/high/medium/low/unknown): $introduced_critical/$introduced_high/$introduced_medium/$introduced_low/$introduced_unknown"
  echo "baseline_missing: $baseline_missing"
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "${output_prefix}_head_ref=$head_ref"
    echo "${output_prefix}_head_instances_count=$head_instances"
    echo "${output_prefix}_head_unique_rule_ids_count=$head_unique_rule_ids"
    echo "${output_prefix}_head_critical_count=$head_critical"
    echo "${output_prefix}_head_high_count=$head_high"
    echo "${output_prefix}_head_medium_count=$head_medium"
    echo "${output_prefix}_head_low_count=$head_low"
    echo "${output_prefix}_head_unknown_count=$head_unknown"
    if [ -n "$base_ref" ]; then
      echo "${output_prefix}_base_ref=$base_ref"
      echo "${output_prefix}_base_instances_count=$base_instances"
      echo "${output_prefix}_base_unique_rule_ids_count=$base_unique_rule_ids"
      echo "${output_prefix}_base_critical_count=$base_critical"
      echo "${output_prefix}_base_high_count=$base_high"
      echo "${output_prefix}_base_medium_count=$base_medium"
      echo "${output_prefix}_base_low_count=$base_low"
      echo "${output_prefix}_base_unknown_count=$base_unknown"
      echo "${output_prefix}_introduced_instances_count=$introduced_instances"
      echo "${output_prefix}_introduced_instances_critical_count=$introduced_critical"
      echo "${output_prefix}_introduced_instances_high_count=$introduced_high"
      echo "${output_prefix}_introduced_instances_medium_count=$introduced_medium"
      echo "${output_prefix}_introduced_instances_low_count=$introduced_low"
      echo "${output_prefix}_introduced_instances_unknown_count=$introduced_unknown"
      echo "${output_prefix}_baseline_missing=$baseline_missing"
    fi
  } >> "$GITHUB_OUTPUT"
fi

