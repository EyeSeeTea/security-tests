#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_TOOL_PREFIX = "OWASP Dependency-Track"
DEFAULT_FALLBACK_URI = "package.json"
DEFAULT_FALLBACK_LINE = 2
DEFAULT_SUMMARY_MAX_LEN = 180
URI_BASE_ID = "%SRCROOT%"


def has_text(value: Any) -> bool:
    return value is not None and str(value) != ""


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as file_obj:
        data = json.load(file_obj)
    if not isinstance(data, dict):
        raise ValueError(f"Top-level JSON object expected: {path}")
    return data


def save_json(path: str, payload: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as file_obj:
        json.dump(payload, file_obj, ensure_ascii=False, indent=2)
        file_obj.write("\n")


def to_number(value: Any) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and re.match(r"^[0-9]+(\.[0-9]+)?$", value.strip()):
        return float(value.strip())
    return None


def score_from_result(result: Dict[str, Any]) -> Optional[float]:
    properties = result.get("properties")
    if not isinstance(properties, dict):
        properties = {}

    cvss_value = to_number(properties.get("cvssV3BaseScore"))
    if cvss_value is not None:
        return cvss_value

    rank = to_number(properties.get("severityRank"))
    if rank is None:
        return None

    mapped = {0.0: 9.0, 1.0: 8.0, 2.0: 5.0, 3.0: 2.0}
    return mapped.get(rank)


def map_level(score: Optional[float], current: Any) -> str:
    if score is None:
        return str(current) if has_text(current) else "warning"
    if score >= 7.0:
        return "error"
    if score >= 4.0:
        return "warning"
    return "note"


def severity_from_result(result: Dict[str, Any], score: Optional[float]) -> str:
    properties = result.get("properties")
    if not isinstance(properties, dict):
        properties = {}

    explicit = properties.get("severity")
    if has_text(explicit):
        return str(explicit).strip().lower()

    rank = to_number(properties.get("severityRank"))
    if rank is not None:
        mapped = {0.0: "critical", 1.0: "high", 2.0: "medium", 3.0: "low"}
        if rank in mapped:
            return mapped[rank]

    if score is None:
        level = str(result.get("level") or "").strip().lower()
        if level == "error":
            return "high"
        if level == "warning":
            return "medium"
        if level == "note":
            return "low"
        return "unknown"

    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "unknown"


def normalize_path(path_value: Any) -> Optional[str]:
    if not has_text(path_value):
        return None
    normalized = str(path_value).replace("\\", "/").lstrip("/")
    return normalized or None


def extract_component_paths(component: Dict[str, Any]) -> List[str]:
    paths: List[str] = []

    properties = component.get("properties")
    if isinstance(properties, list):
        for prop in properties:
            if not isinstance(prop, dict):
                continue
            name = prop.get("name")
            if not isinstance(name, str):
                continue
            if not (name.startswith("syft:location:") and name.endswith(":path")):
                continue
            normalized = normalize_path(prop.get("value"))
            if normalized and normalized not in paths:
                paths.append(normalized)

    evidence = component.get("evidence")
    if isinstance(evidence, dict):
        occurrences = evidence.get("occurrences")
        if isinstance(occurrences, list):
            for occ in occurrences:
                if not isinstance(occ, dict):
                    continue
                normalized = normalize_path(occ.get("location"))
                if normalized and normalized not in paths:
                    paths.append(normalized)

    return paths


def build_purl_to_path_map(vdr_doc: Dict[str, Any]) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    components = vdr_doc.get("components")
    if not isinstance(components, list):
        return mapping

    for component in components:
        if not isinstance(component, dict):
            continue
        paths = extract_component_paths(component)
        if not paths:
            continue
        first_path = paths[0]
        for key_name in ("purl", "bom-ref"):
            key_value = component.get(key_name)
            if has_text(key_value):
                mapping[str(key_value)] = first_path
    return mapping


def build_vulnerability_url_map(doc: Dict[str, Any]) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    vulnerabilities = doc.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return mapping

    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        vuln_id = vuln.get("id")
        if not has_text(vuln_id):
            continue

        selected_url: Optional[str] = None
        source = vuln.get("source")
        if isinstance(source, dict) and has_text(source.get("url")):
            selected_url = str(source.get("url"))

        if not selected_url:
            references = vuln.get("references")
            if isinstance(references, list):
                for ref in references:
                    if isinstance(ref, dict) and has_text(ref.get("url")):
                        selected_url = str(ref.get("url"))
                        break

        if selected_url:
            mapping[str(vuln_id)] = selected_url

    return mapping


def merge_url_maps(primary: Dict[str, str], secondary: Dict[str, str]) -> Dict[str, str]:
    merged = dict(primary)
    for key, value in secondary.items():
        if not has_text(merged.get(key)):
            merged[key] = value
    return merged


def advisory_url(rule_id: str, url_map: Dict[str, str], existing: Optional[str]) -> Optional[str]:
    if has_text(existing):
        return str(existing)
    mapped = url_map.get(rule_id)
    if has_text(mapped):
        return str(mapped)
    return None


def clean_text(text: str) -> str:
    value = str(text or "")
    value = value.replace("\r", "")
    # Convert markdown links to plain text.
    value = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", value)
    ignored_lines = {"Summary", "Details", "Impact", "PoC"}

    lines: List[str] = []
    for raw_line in value.split("\n"):
        line = re.sub(r"^#+\s*", "", raw_line)
        line = line.replace("`", "").strip()
        if line:
            if line in ignored_lines:
                continue
            lines.append(line)
    return "\n".join(lines)


def clean_summary(text: str) -> str:
    ignored_lines = {"Summary", "Details", "Impact", "PoC"}
    for line in clean_text(text).split("\n"):
        line = line.strip()
        if not line:
            continue
        if line in ignored_lines:
            continue
        return line
    return ""


def truncate_summary(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."


def get_first_logical_fqn(result: Dict[str, Any]) -> str:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        return ""
    first = locations[0]
    if not isinstance(first, dict):
        return ""
    logical_locations = first.get("logicalLocations")
    if not isinstance(logical_locations, list) or not logical_locations:
        return ""
    logical = logical_locations[0]
    if not isinstance(logical, dict):
        return ""
    value = logical.get("fullyQualifiedName")
    return str(value) if has_text(value) else ""


def ensure_locations(
    result: Dict[str, Any],
    mapped_path: Optional[str],
    logical_key: str,
    package_name: str,
    fallback_uri: str,
    fallback_line: int,
) -> None:
    uri = mapped_path if has_text(mapped_path) else fallback_uri
    start_line = 1 if has_text(mapped_path) else fallback_line

    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        result["locations"] = [
            {
                "logicalLocations": [
                    {"fullyQualifiedName": logical_key or package_name or "dependency-track"}
                ],
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": URI_BASE_ID},
                    "region": {"startLine": start_line},
                },
            }
        ]
        return

    for index, loc in enumerate(locations):
        if not isinstance(loc, dict):
            loc = {}
            locations[index] = loc

        physical = loc.get("physicalLocation")
        if not isinstance(physical, dict):
            physical = {}
            loc["physicalLocation"] = physical

        artifact = physical.get("artifactLocation")
        if not isinstance(artifact, dict):
            artifact = {}
            physical["artifactLocation"] = artifact
        artifact["uri"] = uri
        artifact["uriBaseId"] = URI_BASE_ID

        region = physical.get("region")
        if not isinstance(region, dict):
            region = {}
            physical["region"] = region

        if has_text(mapped_path):
            existing_line = region.get("startLine")
            if isinstance(existing_line, int) and existing_line > 0:
                region["startLine"] = existing_line
            else:
                region["startLine"] = 1
        else:
            region["startLine"] = fallback_line


def set_rule_text(rule: Dict[str, Any], key: str, value: str) -> None:
    node = rule.get(key)
    if not isinstance(node, dict):
        node = {}
        rule[key] = node
    node["text"] = value


def format_security_severity(value: float) -> str:
    rounded = round(value * 10) / 10
    return str(rounded)


def build_long_message(
    source: str,
    original_rule_id: str,
    package_name: str,
    package_version: str,
    severity: str,
    component_path: str,
    summary_line: str,
    detail_text: str,
    help_url: str,
) -> str:
    affected_component = (
        f"{package_name}@{package_version}" if has_text(package_version) else package_name
    )
    header = f"[{source}] {original_rule_id} in {affected_component}"
    if has_text(summary_line):
        header += f": {summary_line}"

    lines = [
        header,
        f"severity: {severity}",
        f"affected_components: {affected_component}",
        f"affected_component_paths: {component_path}",
        f"affected_names: {package_name}",
        f"affected_versions: {package_version}",
        f"id: {original_rule_id}",
        "description:",
        detail_text if has_text(detail_text) else "",
    ]
    if has_text(help_url):
        lines.append(f"reference_url: {help_url}")
    return "\n".join(lines)


def normalize_sarif(
    sarif: Dict[str, Any],
    vdr_doc: Dict[str, Any],
    vex_doc: Dict[str, Any],
    source: str,
    tool_name: str,
    rule_id_namespace: str,
    location_mode: str,
    fallback_uri: str,
    fallback_line: int,
    summary_max_len: int,
) -> Tuple[int, int]:
    runs = sarif.get("runs")
    if not isinstance(runs, list):
        raise ValueError("Invalid SARIF: 'runs' must be a list")

    purl_path = build_purl_to_path_map(vdr_doc)
    vdr_urls = build_vulnerability_url_map(vdr_doc)
    vex_urls = build_vulnerability_url_map(vex_doc)
    url_by_rule = merge_url_maps(vdr_urls, vex_urls)

    updated_rules = 0
    updated_results = 0

    for run in runs:
        if not isinstance(run, dict):
            continue

        tool = run.setdefault("tool", {})
        if not isinstance(tool, dict):
            tool = {}
            run["tool"] = tool
        driver = tool.setdefault("driver", {})
        if not isinstance(driver, dict):
            driver = {}
            tool["driver"] = driver

        driver["name"] = tool_name
        rules = driver.get("rules")
        if not isinstance(rules, list):
            rules = []
            driver["rules"] = rules

        for rule in rules:
            if not isinstance(rule, dict):
                continue
            original_rule_id = str(rule.get("id") or "Dependency-Track finding")
            namespaced_rule_id = f"{rule_id_namespace}{original_rule_id}"
            help_url = advisory_url(original_rule_id, url_by_rule, rule.get("helpUri"))

            full_desc = rule.get("fullDescription")
            full_desc_text = (
                full_desc.get("text")
                if isinstance(full_desc, dict) and has_text(full_desc.get("text"))
                else None
            )
            base_short = None
            short_desc = rule.get("shortDescription")
            if isinstance(short_desc, dict):
                base_short = short_desc.get("text")
            if not has_text(base_short):
                base_short = rule.get("id") or "Dependency-Track finding"
            rule_detail = clean_text(
                str(full_desc_text or base_short or "Dependency-Track finding")
            )

            rule["id"] = namespaced_rule_id
            set_rule_text(rule, "shortDescription", f"[{source}] {str(base_short)}")
            full_text = f"[{source}] {original_rule_id}"
            if has_text(rule_detail):
                full_text += f"\n{rule_detail}"
            if help_url:
                full_text += f"\nReference: {help_url}"
            set_rule_text(rule, "fullDescription", full_text)
            if help_url:
                rule["helpUri"] = help_url
            updated_rules += 1

        results = run.get("results")
        if not isinstance(results, list):
            continue

        for result in results:
            if not isinstance(result, dict):
                continue

            properties = result.get("properties")
            if not isinstance(properties, dict):
                properties = {}

            original_rule_id = str(result.get("ruleId") or "Dependency-Track finding")
            namespaced_rule_id = f"{rule_id_namespace}{original_rule_id}"
            help_url = advisory_url(original_rule_id, url_by_rule, None)
            package_name = str(properties.get("name") or "unknown-package")
            package_version = str(properties.get("version") or "")

            message = result.get("message")
            if not isinstance(message, dict):
                message = {}
                result["message"] = message
            raw_detail = str(message.get("text") or "")
            detail_text = clean_text(raw_detail)
            summary_line = truncate_summary(clean_summary(raw_detail), summary_max_len)

            score = score_from_result(result)
            severity = severity_from_result(result, score)
            logical_key = get_first_logical_fqn(result)
            component_path = purl_path.get(logical_key) if logical_key else None
            mapped_path = component_path
            if location_mode == "fallback":
                mapped_path = None

            properties = dict(properties)
            properties["scan_source"] = source
            properties["original_rule_id"] = original_rule_id
            if help_url:
                properties["advisory_url"] = help_url
            if raw_detail:
                properties["advisory_detail"] = raw_detail
            result["properties"] = properties
            result["ruleId"] = namespaced_rule_id

            message["text"] = build_long_message(
                source=source,
                original_rule_id=original_rule_id,
                package_name=package_name,
                package_version=package_version,
                severity=severity,
                component_path=str(component_path or ""),
                summary_line=summary_line,
                detail_text=detail_text,
                help_url=str(help_url or ""),
            )

            partial = result.get("partialFingerprints")
            if not isinstance(partial, dict):
                partial = {}

            finding_key = "|".join(
                [
                    source,
                    str(result.get("ruleId") or ""),
                    str(properties.get("name") or ""),
                    str(properties.get("group") or ""),
                    str(properties.get("version") or ""),
                    logical_key,
                ]
            )
            partial["dtrack_finding_key"] = finding_key
            result["partialFingerprints"] = partial

            result["level"] = map_level(score, result.get("level"))

            ensure_locations(
                result=result,
                mapped_path=mapped_path,
                logical_key=logical_key,
                package_name=package_name,
                fallback_uri=fallback_uri,
                fallback_line=fallback_line,
            )
            updated_results += 1

        score_by_rule: Dict[str, float] = {}
        for result in results:
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("ruleId") or "")
            if not rule_id:
                continue
            score = score_from_result(result)
            if score is None:
                continue
            if rule_id not in score_by_rule or score > score_by_rule[rule_id]:
                score_by_rule[rule_id] = score

        for rule in rules:
            if not isinstance(rule, dict):
                continue
            rule_id = str(rule.get("id") or "")
            if not rule_id or rule_id not in score_by_rule:
                continue
            rule_properties = rule.get("properties")
            if not isinstance(rule_properties, dict):
                rule_properties = {}
            rule_properties["security-severity"] = format_security_severity(
                score_by_rule[rule_id]
            )
            if not has_text(rule_properties.get("precision")):
                rule_properties["precision"] = "high"
            tags = rule_properties.get("tags")
            if not isinstance(tags, list):
                tags = []
            if "security" not in tags:
                tags.append("security")
            rule_properties["tags"] = tags
            rule["properties"] = rule_properties

    return updated_rules, updated_results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Normalize Dependency-Track SARIF for GitHub Code Scanning."
    )
    parser.add_argument("--input-sarif", required=True, help="Input SARIF file path.")
    parser.add_argument(
        "--output-sarif", required=True, help="Output SARIF file path."
    )
    parser.add_argument(
        "--vdr",
        default="",
        help="CycloneDX VDR/BOM JSON file path. Optional but recommended for path mapping.",
    )
    parser.add_argument(
        "--vex",
        default="",
        help="CycloneDX VEX JSON file path. Optional but recommended for references.",
    )
    parser.add_argument(
        "--source",
        required=True,
        help="Source label added to output, for example syft or yarn4.",
    )
    parser.add_argument(
        "--tool-name",
        default="",
        help="Override tool.driver.name. Default: OWASP Dependency-Track (<source>).",
    )
    parser.add_argument(
        "--rule-id-namespace",
        default="",
        help="Prefix added to rule IDs in both rules and results, for example syft-test::",
    )
    parser.add_argument(
        "--location-mode",
        choices=["auto", "fallback"],
        default="auto",
        help=(
            "Location strategy: 'auto' uses mapped component paths when available; "
            "'fallback' always uses fallback-uri/line."
        ),
    )
    parser.add_argument(
        "--fallback-uri",
        default=DEFAULT_FALLBACK_URI,
        help=f"Fallback artifact path when no component path is found. Default: {DEFAULT_FALLBACK_URI}.",
    )
    parser.add_argument(
        "--fallback-line",
        type=int,
        default=DEFAULT_FALLBACK_LINE,
        help=f"Fallback start line for fallback-uri. Default: {DEFAULT_FALLBACK_LINE}.",
    )
    parser.add_argument(
        "--summary-max-len",
        type=int,
        default=DEFAULT_SUMMARY_MAX_LEN,
        help=f"Maximum summary length in result.message.text. Default: {DEFAULT_SUMMARY_MAX_LEN}.",
    )
    parser.add_argument(
        "--pretty-indent",
        type=int,
        default=2,
        help="JSON indentation for output SARIF. Default: 2.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    tool_name = (
        args.tool_name.strip()
        if has_text(args.tool_name)
        else f"{DEFAULT_TOOL_PREFIX} ({args.source})"
    )

    try:
        sarif = load_json(args.input_sarif)
        if not has_text(args.vdr) and not has_text(args.vex):
            raise ValueError("At least one input is required: --vdr and/or --vex")

        vdr_doc = load_json(args.vdr) if has_text(args.vdr) else {}
        vex_doc = load_json(args.vex) if has_text(args.vex) else {}

        updated_rules, updated_results = normalize_sarif(
            sarif=sarif,
            vdr_doc=vdr_doc,
            vex_doc=vex_doc,
            source=args.source,
            tool_name=tool_name,
            rule_id_namespace=args.rule_id_namespace,
            location_mode=args.location_mode,
            fallback_uri=args.fallback_uri,
            fallback_line=args.fallback_line,
            summary_max_len=args.summary_max_len,
        )

        with open(args.output_sarif, "w", encoding="utf-8") as file_obj:
            json.dump(sarif, file_obj, ensure_ascii=False, indent=args.pretty_indent)
            file_obj.write("\n")

        runs = sarif.get("runs")
        run_count = len(runs) if isinstance(runs, list) else 0
        print(f"SARIF normalized successfully: {args.output_sarif}")
        print(f"Input SARIF: {args.input_sarif}")
        print(f"VDR: {args.vdr if has_text(args.vdr) else '<not provided>'}")
        print(f"VEX: {args.vex if has_text(args.vex) else '<not provided>'}")
        print(f"Source label: {args.source}")
        print(f"Tool name: {tool_name}")
        print(
            f"Rule ID namespace: {args.rule_id_namespace if has_text(args.rule_id_namespace) else '<none>'}"
        )
        print(f"Location mode: {args.location_mode}")
        print(f"Runs processed: {run_count}")
        print(f"Rules updated: {updated_rules}")
        print(f"Results updated: {updated_results}")
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
