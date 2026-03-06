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
            "Estimate introduced open alerts (rule.id) for a branch using GitHub code scanning:\n"
            "introduced_candidate_all = head_open_rule_ids_all - base_open_rule_ids_all"
        )
    )
    parser.add_argument("--sarif", required=True, help="Path to SARIF file (used for fallback severity mapping).")
    parser.add_argument("--repo", default=os.getenv("GITHUB_REPOSITORY", ""))
    parser.add_argument("--tool-name", default=os.getenv("TOOL_NAME", ""))
    parser.add_argument(
        "--head-branch",
        default=os.getenv("GITHUB_HEAD_REF", os.getenv("GITHUB_REF_NAME", "")),
        help="Head branch name (e.g. feature/my-branch).",
    )
    parser.add_argument("--head-ref", default="", help="Explicit head ref override (refs/heads/...).")
    parser.add_argument(
        "--base-branch",
        default=os.getenv("GITHUB_BASE_REF", os.getenv("BASE_REF", "")),
        help="Base branch name (e.g. master).",
    )
    parser.add_argument("--base-ref", default="", help="Explicit base ref override (refs/heads/...).")
    parser.add_argument("--out-dir", default=os.getenv("RUNNER_TEMP", "/tmp"))
    parser.add_argument("--prefix", default="dtrack_intro")
    parser.add_argument("--api-url", default=os.getenv("GITHUB_API_URL", DEFAULT_API_URL))
    parser.add_argument("--token", default=os.getenv("GH_TOKEN", os.getenv("GITHUB_TOKEN", "")))
    parser.add_argument("--json", action="store_true", help="Print compact JSON summary.")
    return parser.parse_args()


def resolve_ref(name: str, explicit_ref: str, branch: str) -> str:
    if explicit_ref.strip():
        return explicit_ref.strip()
    clean_branch = branch.strip()
    if not clean_branch:
        raise ValueError(f"Missing {name} branch. Set --{name}-branch or provide --{name}-ref.")
    if clean_branch.startswith("refs/heads/") or clean_branch.startswith("refs/pull/"):
        return clean_branch
    return f"refs/heads/{clean_branch}"


def severity_rank(severity: str) -> int:
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "unknown": 0,
    }.get(severity, 0)


def normalize_severity_value(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized == "error":
        return "high"
    if normalized == "warning":
        return "medium"
    if normalized == "note":
        return "low"
    if normalized in {"critical", "high", "medium", "low"}:
        return normalized
    return "unknown"


def normalize_sarif_result_severity(result: Dict[str, Any]) -> str:
    props = result.get("properties")
    if not isinstance(props, dict):
        props = {}
    raw = props.get("severity") or props.get("security_severity_level") or result.get("level")
    return normalize_severity_value(raw)


def normalize_alert_severity(alert: Dict[str, Any]) -> str:
    rule = alert.get("rule")
    if not isinstance(rule, dict):
        rule = {}
    raw = (
        rule.get("security_severity_level")
        or rule.get("severity")
        or alert.get("security_severity_level")
        or alert.get("severity")
    )
    return normalize_severity_value(raw)


def extract_from_sarif(sarif_path: Path) -> Tuple[Set[str], Dict[str, str], Dict[str, str]]:
    with sarif_path.open("r", encoding="utf-8") as file_obj:
        data = json.load(file_obj)

    runs = data.get("runs")
    if not isinstance(runs, list):
        return set(), {}, {}

    rule_ids: Set[str] = set()
    best_severity_by_rule: Dict[str, str] = {}
    best_severity_by_rule_pkg_ver: Dict[str, str] = {}

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
            sev = normalize_sarif_result_severity(result)

            properties = result.get("properties")
            if not isinstance(properties, dict):
                properties = {}
            package_name = str(properties.get("name") or "unknown-package").strip()
            package_version = str(properties.get("version") or "").strip()
            rule_pkg_ver_key = "|".join([rule_id, package_name, package_version])

            prev = best_severity_by_rule.get(rule_id, "unknown")
            if severity_rank(sev) > severity_rank(prev):
                best_severity_by_rule[rule_id] = sev
            elif rule_id not in best_severity_by_rule:
                best_severity_by_rule[rule_id] = prev
            prev_pkg_ver = best_severity_by_rule_pkg_ver.get(rule_pkg_ver_key, "unknown")
            if severity_rank(sev) > severity_rank(prev_pkg_ver):
                best_severity_by_rule_pkg_ver[rule_pkg_ver_key] = sev
            elif rule_pkg_ver_key not in best_severity_by_rule_pkg_ver:
                best_severity_by_rule_pkg_ver[rule_pkg_ver_key] = prev_pkg_ver

    return rule_ids, best_severity_by_rule, best_severity_by_rule_pkg_ver


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


def fetch_open_rule_ids_with_severity(
    *,
    api_url: str,
    repo: str,
    token: str,
    tool_name: str,
    ref: str,
    fallback_severity_by_rule: Dict[str, str],
) -> Dict[str, str]:
    severity_by_rule: Dict[str, str] = {}
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
                "ref": ref,
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
            rule_id = str(rule.get("id") or "").strip()
            if not rule_id:
                continue

            sev = normalize_alert_severity(item)
            if sev == "unknown":
                sev = fallback_severity_by_rule.get(rule_id, "unknown")

            previous = severity_by_rule.get(rule_id, "unknown")
            if severity_rank(sev) > severity_rank(previous):
                severity_by_rule[rule_id] = sev
            elif rule_id not in severity_by_rule:
                severity_by_rule[rule_id] = previous

        page += 1

    return severity_by_rule


def group_rule_ids_by_severity(severity_by_rule: Dict[str, str]) -> Dict[str, List[str]]:
    grouped: Dict[str, List[str]] = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "unknown": [],
    }
    for rule_id in sorted(severity_by_rule.keys()):
        sev = severity_by_rule.get(rule_id, "unknown")
        if sev not in grouped:
            sev = "unknown"
        grouped[sev].append(rule_id)
    return grouped


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
        head_ref = resolve_ref("head", args.head_ref, args.head_branch)
        base_ref = resolve_ref("base", args.base_ref, args.base_branch)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    sarif_rule_ids_all, sarif_severity_by_rule, sarif_rule_pkg_ver_severity = extract_from_sarif(
        sarif_path
    )
    sarif_rule_pkg_ver_by_severity = group_rule_ids_by_severity(sarif_rule_pkg_ver_severity)

    head_open_severity_by_rule = fetch_open_rule_ids_with_severity(
        api_url=args.api_url,
        repo=args.repo.strip(),
        token=args.token.strip(),
        tool_name=args.tool_name.strip(),
        ref=head_ref,
        fallback_severity_by_rule=sarif_severity_by_rule,
    )
    base_open_severity_by_rule = fetch_open_rule_ids_with_severity(
        api_url=args.api_url,
        repo=args.repo.strip(),
        token=args.token.strip(),
        tool_name=args.tool_name.strip(),
        ref=base_ref,
        fallback_severity_by_rule=sarif_severity_by_rule,
    )

    head_open_rule_ids_all = set(head_open_severity_by_rule.keys())
    base_rule_ids_all = set(base_open_severity_by_rule.keys())
    introduced_candidate_all = head_open_rule_ids_all - base_rule_ids_all

    open_in_branch_by_severity = group_rule_ids_by_severity(head_open_severity_by_rule)

    introduced_severity_by_rule: Dict[str, str] = {}
    for rule_id in introduced_candidate_all:
        introduced_severity_by_rule[rule_id] = head_open_severity_by_rule.get(
            rule_id,
            sarif_severity_by_rule.get(rule_id, "unknown"),
        )
    introduced_by_severity = group_rule_ids_by_severity(introduced_severity_by_rule)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    summary_file = out_dir / f"{args.prefix}_introduced_candidate_summary.json"

    baseline_missing = len(base_rule_ids_all) == 0

    sarif_rule_ids_sorted = sorted(sarif_rule_ids_all)
    head_open_rule_ids_sorted = sorted(head_open_rule_ids_all)
    base_rule_ids_sorted = sorted(base_rule_ids_all)
    introduced_candidate_all_sorted = sorted(introduced_candidate_all)

    summary = {
        "repo": args.repo.strip(),
        "tool_name": args.tool_name.strip(),
        "head_ref": head_ref,
        "base_ref": base_ref,
        "sarif_rule_ids_all_count": len(sarif_rule_ids_sorted),
        "sarif_rule_pkg_ver_all_count": len(sarif_rule_pkg_ver_severity),
        "sarif_rule_pkg_ver_critical_count": len(sarif_rule_pkg_ver_by_severity["critical"]),
        "sarif_rule_pkg_ver_high_count": len(sarif_rule_pkg_ver_by_severity["high"]),
        "sarif_rule_pkg_ver_medium_count": len(sarif_rule_pkg_ver_by_severity["medium"]),
        "sarif_rule_pkg_ver_low_count": len(sarif_rule_pkg_ver_by_severity["low"]),
        "sarif_rule_pkg_ver_unknown_count": len(sarif_rule_pkg_ver_by_severity["unknown"]),
        "base_rule_ids_all_count": len(base_rule_ids_sorted),
        "open_in_branch_all_count": len(head_open_rule_ids_sorted),
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
            "head_open_rule_ids_all": head_open_rule_ids_sorted,
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
    print(f"Head ref: {summary['head_ref']}")
    print(f"Base ref: {summary['base_ref']}")
    print(f"SARIF file: {sarif_path}")
    print(f"sarif_rule_ids_all: {summary['sarif_rule_ids_all_count']}")
    print(
        "sarif_rule_pkg_ver by severity (critical/high/medium/low/unknown): "
        f"{summary['sarif_rule_pkg_ver_critical_count']}/"
        f"{summary['sarif_rule_pkg_ver_high_count']}/"
        f"{summary['sarif_rule_pkg_ver_medium_count']}/"
        f"{summary['sarif_rule_pkg_ver_low_count']}/"
        f"{summary['sarif_rule_pkg_ver_unknown_count']}"
    )
    print(f"head_open_rule_ids_all: {summary['open_in_branch_all_count']}")
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
            "head_ref": summary["head_ref"],
            "base_ref": summary["base_ref"],
            "sarif_rule_ids_all_count": str(summary["sarif_rule_ids_all_count"]),
            "sarif_rule_pkg_ver_all_count": str(summary["sarif_rule_pkg_ver_all_count"]),
            "sarif_rule_pkg_ver_critical_count": str(summary["sarif_rule_pkg_ver_critical_count"]),
            "sarif_rule_pkg_ver_high_count": str(summary["sarif_rule_pkg_ver_high_count"]),
            "sarif_rule_pkg_ver_medium_count": str(summary["sarif_rule_pkg_ver_medium_count"]),
            "sarif_rule_pkg_ver_low_count": str(summary["sarif_rule_pkg_ver_low_count"]),
            "sarif_rule_pkg_ver_unknown_count": str(summary["sarif_rule_pkg_ver_unknown_count"]),
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
