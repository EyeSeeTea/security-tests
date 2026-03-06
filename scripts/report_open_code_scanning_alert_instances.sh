#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  report_open_code_scanning_alert_instances.sh [options]

Options:
  --repo <owner/repo>       Default: $GITHUB_REPOSITORY
  --tool-name <name>        Default: $TOOL_NAME
  --ref <refs/...>          Required if not provided by env
  --token <token>           Default: $GH_TOKEN or $GITHUB_TOKEN
  --api-url <url>           Default: $GITHUB_API_URL or https://api.github.com
  --output-prefix <name>    Default: open_alerts
  -h, --help                Show this help
EOF
}

repo="${GITHUB_REPOSITORY:-}"
tool_name="${TOOL_NAME:-}"
ref="${REF:-}"
token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
api_url="${GITHUB_API_URL:-https://api.github.com}"
output_prefix="open_alerts"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo) repo="$2"; shift 2 ;;
    --tool-name) tool_name="$2"; shift 2 ;;
    --ref) ref="$2"; shift 2 ;;
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
if [ -z "$ref" ]; then
  echo "Missing --ref (or REF)." >&2
  exit 1
fi
if [ -z "$token" ]; then
  echo "Missing --token (or GH_TOKEN/GITHUB_TOKEN)." >&2
  exit 1
fi

if [[ "$ref" != refs/* ]]; then
  ref="refs/heads/${ref#refs/heads/}"
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
: > "$tmp"

page=1
while :; do
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
  count="$(jq 'length' <<<"$batch")"
  [ "$count" -eq 0 ] && break
  jq -c '.[]' <<<"$batch" >> "$tmp"
  page=$((page + 1))
done

open_instances="$(wc -l < "$tmp" | tr -d ' ')"
unique_rule_ids="$(jq -r '.rule.id // empty' "$tmp" | sed '/^$/d' | sort -u | wc -l | tr -d ' ')"

echo "Repository: $repo"
echo "Tool name: $tool_name"
echo "Ref: $ref"
echo "Open alert instances (UI): $open_instances"
echo "Unique rule.id: $unique_rule_ids"
echo "By severity (instances):"
if [ "$open_instances" -gt 0 ]; then
  jq -r '.rule.security_severity_level // .rule.severity // "unknown"' "$tmp" | sort | uniq -c
else
  echo "  0 unknown"
fi

echo "List number + rule.id + severity:"
if [ "$open_instances" -gt 0 ]; then
  jq -r '[.number, .rule.id, (.rule.security_severity_level // .rule.severity // "unknown")] | @tsv' "$tmp" | sort -n
else
  echo "(none)"
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "${output_prefix}_ref=$ref"
    echo "${output_prefix}_instances_count=$open_instances"
    echo "${output_prefix}_unique_rule_ids_count=$unique_rule_ids"
  } >> "$GITHUB_OUTPUT"
fi

