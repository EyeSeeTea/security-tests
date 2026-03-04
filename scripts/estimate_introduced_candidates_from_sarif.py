#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple


DEFAULT_API_URL = "https://api.github.com"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Estimate introduced candidates from SARIF using rule.id:\n"
            "introduced_candidate_all = sarif_rule_ids_all - base_rule_ids_all"
        )
    )
    parser.add_argument("--sarif", required=True, help="Path to SARIF file.")
    parser.add_argument("--repo", default=os.getenv("GITHUB_REPOSITORY", ""))
    parser.add_argument("--tool-name", default=os.getenv("TOOL_NAME", ""))
    parser.add_argument(
        "--base-branch",
        default=os.getenv("GITHUB_BASE_REF", os.getenv("BASE_REF", "")),
        help="Base branch name (e.g. master).",
    )
    parser.add_argument("--base-ref", default="", help="Explicit refs/heads/... override.")
    parser.add_argument("--out-dir", default=os.getenv("RUNNER_TEMP", "/tmp"))
    parser.add_argument("--prefix", default="dtrack_intro")
    parser.add_argument("--api-url", default=os.getenv("GITHUB_API_URL", DEFAULT_API_URL))
    parser.add_argument("--token", default=os.getenv("GH_TOKEN", os.getenv("GITHUB_TOKEN", "")))
    parser.add_argument("--json", action="store_true", help="Print compact JSON summary.")
    return parser.parse_args()


def resolve_base_ref(base_ref: str, base_branch: str) -> str:
    if base_ref.strip():
        return base_ref.strip()
    branch = base_branch.strip()
    if not branch:
        raise ValueError("Missing base branch. Set --base-branch or GITHUB_BASE_REF.")
    if branch.startswith("refs/heads/"):
        return branch
    return f"refs/heads/{branch}"


def normalize_severity(result: Dict[str, Any]) -> str:
    props = result.get("properties")
    if not isinstance(props, dict):
        props = {}

    sev = (
        props.get("severity")
        or props.get("security_severity_level")
        or result.get("level")
        or "unknown"
    )
    value = str(sev).strip().lower()
    if value == "error":
        return "high"
    if value == "warning":
        return "medium"
    if value == "note":
        return "low"
    if value in {"critical", "high", "medium", "low"}:
        return value
    return "unknown"


def severity_rank(severity: str) -> int:
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "unknown": 0,
    }.get(severity, 0)


def extract_from_sarif(sarif_path: Path) -> Tuple[Set[str], Dict[str, str]]:
    with sarif_path.open("r", encoding="utf-8") as file_obj:
        data = json.load(file_obj)

    runs = data.get("runs")
    if not isinstance(runs, list):
        return set(), {}

    rule_ids: Set[str] = set()
    best_severity_by_rule: Dict[str, str] = {}

    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results")
        if not isinstance(results, list):
            continue

        for result in results:
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("ruleId") or "").strip()
            if not rule_id:
                continue

            rule_ids.add(rule_id)
            sev = normalize_severity(result)
            prev = best_severity_by_rule.get(rule_id, "unknown")
            if severity_rank(sev) > severity_rank(prev):
                best_severity_by_rule[rule_id] = sev
            elif rule_id not in best_severity_by_rule:
                best_severity_by_rule[rule_id] = prev

    return rule_ids, best_severity_by_rule


def github_get_json(
    *,
    api_url: str,
    repo: str,
    token: str,
    path: str,
    query: Dict[str, str],
) -> Any:
    endpoint = f"{api_url.rstrip('/')}/repos/{repo}{path}"
    url = f"{endpoint}?{urllib.parse.urlencode(query)}"
    req = urllib.request.Request(
        url=url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub API HTTP {exc.code}: {body}") from exc


def fetch_base_open_rule_ids(
    *,
    api_url: str,
    repo: str,
    token: str,
    tool_name: str,
    base_ref: str,
) -> Set[str]:
    rule_ids: Set[str] = set()
    page = 1
    while True:
        response = github_get_json(
            api_url=api_url,
            repo=repo,
            token=token,
            path="/code-scanning/alerts",
            query={
                "state": "open",
                "tool_name": tool_name,
                "ref": base_ref,
                "per_page": "100",
                "page": str(page),
            },
        )
        if not isinstance(response, list):
            raise RuntimeError("Unexpected API response shape: expected list.")
        if not response:
            break

        for item in response:
            if not isinstance(item, dict):
                continue
            rule = item.get("rule")
            if not isinstance(rule, dict):
                continue
            rule_id = rule.get("id")
            if isinstance(rule_id, str) and rule_id.strip():
                rule_ids.add(rule_id.strip())
        page += 1
    return rule_ids


def write_github_output(values: Dict[str, str]) -> None:
    output_path = os.getenv("GITHUB_OUTPUT", "")
    if not output_path:
        return
    with open(output_path, "a", encoding="utf-8") as file_obj:
        for key, value in values.items():
            file_obj.write(f"{key}={value}\n")


def main() -> int:
    args = parse_args()

    sarif_path = Path(args.sarif)
    if not sarif_path.exists():
        print(f"SARIF file not found: {sarif_path}", file=sys.stderr)
        return 1
    if not args.repo.strip():
        print("Missing --repo (or GITHUB_REPOSITORY).", file=sys.stderr)
        return 1
    if not args.tool_name.strip():
        print("Missing --tool-name (or TOOL_NAME).", file=sys.stderr)
        return 1
    if not args.token.strip():
        print("Missing --token (or GH_TOKEN/GITHUB_TOKEN).", file=sys.stderr)
        return 1

    try:
        base_ref = resolve_base_ref(args.base_ref, args.base_branch)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    sarif_rule_ids_all, sarif_severity_by_rule = extract_from_sarif(sarif_path)
    base_rule_ids_all = fetch_base_open_rule_ids(
        api_url=args.api_url,
        repo=args.repo.strip(),
        token=args.token.strip(),
        tool_name=args.tool_name.strip(),
        base_ref=base_ref,
    )

    introduced_candidate_all = sarif_rule_ids_all - base_rule_ids_all

    open_in_branch_by_severity: Dict[str, List[str]] = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "unknown": [],
    }
    for rule_id in sorted(sarif_rule_ids_all):
        sev = sarif_severity_by_rule.get(rule_id, "unknown")
        if sev not in open_in_branch_by_severity:
            sev = "unknown"
        open_in_branch_by_severity[sev].append(rule_id)

    introduced_by_severity: Dict[str, List[str]] = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "unknown": [],
    }
    for rule_id in sorted(introduced_candidate_all):
        sev = sarif_severity_by_rule.get(rule_id, "unknown")
        if sev not in introduced_by_severity:
            sev = "unknown"
        introduced_by_severity[sev].append(rule_id)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    summary_file = out_dir / f"{args.prefix}_introduced_candidate_summary.json"

    baseline_missing = len(base_rule_ids_all) == 0

    sarif_rule_ids_sorted = sorted(sarif_rule_ids_all)
    base_rule_ids_sorted = sorted(base_rule_ids_all)
    introduced_candidate_all_sorted = sorted(introduced_candidate_all)

    summary = {
        "repo": args.repo.strip(),
        "tool_name": args.tool_name.strip(),
        "base_ref": base_ref,
        "sarif_rule_ids_all_count": len(sarif_rule_ids_sorted),
        "base_rule_ids_all_count": len(base_rule_ids_sorted),
        "open_in_branch_all_count": len(sarif_rule_ids_sorted),
        "open_in_branch_critical_count": len(open_in_branch_by_severity["critical"]),
        "open_in_branch_high_count": len(open_in_branch_by_severity["high"]),
        "open_in_branch_medium_count": len(open_in_branch_by_severity["medium"]),
        "open_in_branch_low_count": len(open_in_branch_by_severity["low"]),
        "open_in_branch_unknown_count": len(open_in_branch_by_severity["unknown"]),
        "introduced_candidate_all_count": len(introduced_candidate_all_sorted),
        "introduced_candidate_critical_count": len(introduced_by_severity["critical"]),
        "introduced_candidate_high_count": len(introduced_by_severity["high"]),
        "introduced_candidate_medium_count": len(introduced_by_severity["medium"]),
        "introduced_candidate_low_count": len(introduced_by_severity["low"]),
        "introduced_candidate_unknown_count": len(introduced_by_severity["unknown"]),
        "baseline_missing": baseline_missing,
        "rule_ids": {
            "sarif_rule_ids_all": sarif_rule_ids_sorted,
            "base_rule_ids_all": base_rule_ids_sorted,
            "introduced_candidate_all": introduced_candidate_all_sorted,
        },
        "open_in_branch_by_severity": open_in_branch_by_severity,
        "introduced_candidate_by_severity": introduced_by_severity,
        "summary_file": str(summary_file),
    }

    with summary_file.open("w", encoding="utf-8") as file_obj:
        json.dump(summary, file_obj, ensure_ascii=True, indent=2)
        file_obj.write("\n")

    print(f"Repository: {summary['repo']}")
    print(f"Tool name: {summary['tool_name']}")
    print(f"Base ref: {summary['base_ref']}")
    print(f"SARIF file: {sarif_path}")
    print(f"sarif_rule_ids_all: {summary['sarif_rule_ids_all_count']}")
    print(f"base_rule_ids_all: {summary['base_rule_ids_all_count']}")
    print(
        "open_in_branch by severity (critical/high/medium/low/unknown): "
        f"{summary['open_in_branch_critical_count']}/"
        f"{summary['open_in_branch_high_count']}/"
        f"{summary['open_in_branch_medium_count']}/"
        f"{summary['open_in_branch_low_count']}/"
        f"{summary['open_in_branch_unknown_count']}"
    )
    print(f"introduced_candidate_all: {summary['introduced_candidate_all_count']}")
    print(
        "introduced by severity (critical/high/medium/low/unknown): "
        f"{summary['introduced_candidate_critical_count']}/"
        f"{summary['introduced_candidate_high_count']}/"
        f"{summary['introduced_candidate_medium_count']}/"
        f"{summary['introduced_candidate_low_count']}/"
        f"{summary['introduced_candidate_unknown_count']}"
    )
    print(f"baseline_missing: {'true' if baseline_missing else 'false'}")
    print(f"summary_file: {summary_file}")

    write_github_output(
        {
            "base_ref": summary["base_ref"],
            "sarif_rule_ids_all_count": str(summary["sarif_rule_ids_all_count"]),
            "base_rule_ids_all_count": str(summary["base_rule_ids_all_count"]),
            "open_in_branch_all_count": str(summary["open_in_branch_all_count"]),
            "open_in_branch_critical_count": str(summary["open_in_branch_critical_count"]),
            "open_in_branch_high_count": str(summary["open_in_branch_high_count"]),
            "open_in_branch_medium_count": str(summary["open_in_branch_medium_count"]),
            "open_in_branch_low_count": str(summary["open_in_branch_low_count"]),
            "open_in_branch_unknown_count": str(summary["open_in_branch_unknown_count"]),
            "introduced_candidate_all_count": str(summary["introduced_candidate_all_count"]),
            "introduced_candidate_critical_count": str(summary["introduced_candidate_critical_count"]),
            "introduced_candidate_high_count": str(summary["introduced_candidate_high_count"]),
            "introduced_candidate_medium_count": str(summary["introduced_candidate_medium_count"]),
            "introduced_candidate_low_count": str(summary["introduced_candidate_low_count"]),
            "introduced_candidate_unknown_count": str(summary["introduced_candidate_unknown_count"]),
            "baseline_missing": "true" if baseline_missing else "false",
            "summary_file": str(summary_file),
        }
    )

    if args.json:
        print(json.dumps(summary, ensure_ascii=True, separators=(",", ":")))

    return 0


if __name__ == "__main__":
    sys.exit(main())
