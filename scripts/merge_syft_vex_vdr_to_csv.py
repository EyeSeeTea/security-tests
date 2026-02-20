#!/usr/bin/env python3
import argparse
import csv
import json
import sys
from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_VEX = "vex_syft.json"
DEFAULT_VDR = "vdr_syft.json"
DEFAULT_OUTPUT = "syft_vex_vdr.csv"

FIXED_COLUMNS = [
    "False positive",
    "Explanation of false positive",
    "Reviewed by",
    "score",
    "severity",
    "affected_components",
    "affected_component_paths",
    "affected_names",
    "affected_versions",
]

OMIT_COLUMNS = {
    "severity_rank",
    "affected_bom_refs",
    "bom-ref",
    "affected_purls",
    "source.name",
    "source.url",
    "ratings",
    "cwes",
    "published",
    "affects",
}


def flatten(value: Any, prefix: str, out: Dict[str, Any]) -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            new_prefix = f"{prefix}.{k}" if prefix else k
            flatten(v, new_prefix, out)
    elif isinstance(value, list):
        if all(not isinstance(x, (dict, list)) for x in value):
            out[prefix] = ";".join("" if x is None else str(x) for x in value)
        else:
            out[prefix] = json.dumps(value, ensure_ascii=False)
    else:
        out[prefix] = "" if value is None else value


def load_vulnerabilities(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Top-level JSON value is not an object: {path}")

    vulns = data.get("vulnerabilities", [])
    if not isinstance(vulns, list):
        raise ValueError(f"'vulnerabilities' is not a list in: {path}")

    return [v for v in vulns if isinstance(v, dict)]


def ensure_ids(vulns: List[Dict[str, Any]], path: str) -> None:
    missing: List[str] = []
    for idx, v in enumerate(vulns):
        if not v.get("id"):
            ref = v.get("bom-ref") or "missing bom-ref"
            missing.append(f"index={idx} bom-ref={ref}")
        if len(missing) >= 5:
            break
    if missing:
        details = "; ".join(missing)
        raise ValueError(
            f"Vulnerabilities without 'id' were found in {path}. "
            f"They cannot be uniquely identified. Examples: {details}"
        )


def load_components_map(path: str) -> Dict[str, Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Top-level JSON value is not an object: {path}")

    components = data.get("components", [])
    if not isinstance(components, list):
        return {}

    result: Dict[str, Dict[str, Any]] = {}
    for comp in components:
        if not isinstance(comp, dict):
            continue
        ref = comp.get("bom-ref")
        if ref:
            result[ref] = comp
    return result


def _json_key(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    except TypeError:
        return str(value)


def merge_lists(base: List[Any], other: List[Any]) -> List[Any]:
    if not base:
        return other
    if not other:
        return base

    result = list(base)
    seen = set(_json_key(item) for item in base)
    for item in other:
        key = _json_key(item)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def merge_dicts(base: Dict[str, Any], other: Dict[str, Any]) -> Dict[str, Any]:
    for k, v in other.items():
        if k not in base or base[k] in (None, "", [], {}):
            base[k] = v
            continue

        b = base[k]
        if isinstance(b, dict) and isinstance(v, dict):
            base[k] = merge_dicts(b, v)
        elif isinstance(b, list) and isinstance(v, list):
            base[k] = merge_lists(b, v)
        # else: keep the base value
    return base


def merge_vulnerabilities(vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    for idx, v in enumerate(vulns):
        key = v.get("id") or v.get("bom-ref") or f"__idx_{idx}"
        if key not in merged:
            merged[key] = deepcopy(v)
        else:
            merged[key] = merge_dicts(merged[key], v)
    return list(merged.values())


def rating_summary(ratings: Any) -> Tuple[Optional[float], Optional[str]]:
    if not isinstance(ratings, list):
        return None, None

    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
    best_score: Optional[float] = None
    best_sev: Optional[str] = None
    best_rank = -1
    fallback_sev: Optional[str] = None

    for r in ratings:
        if not isinstance(r, dict):
            continue
        score = r.get("score")
        sev = r.get("severity")

        if sev:
            if fallback_sev is None:
                fallback_sev = sev
            rank = severity_rank.get(str(sev).lower(), -1)
            if best_score is None and rank > best_rank:
                best_rank = rank
                best_sev = sev

        try:
            score_val = float(score) if score is not None else None
        except (TypeError, ValueError):
            score_val = None

        if score_val is None:
            continue

        if best_score is None or score_val > best_score:
            best_score = score_val
            best_sev = sev

    if best_score is None and best_sev is None:
        best_sev = fallback_sev

    return best_score, best_sev


def _append_unique(target: List[str], value: Optional[str]) -> None:
    if not value:
        return
    if value not in target:
        target.append(value)


def _normalize_component_path(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    normalized = str(path).replace("\\", "/").lstrip("/")
    return normalized or None


def _extract_component_paths(component: Dict[str, Any]) -> List[str]:
    paths: List[str] = []
    for prop in component.get("properties", []) or []:
        if not isinstance(prop, dict):
            continue
        name = prop.get("name")
        if not isinstance(name, str):
            continue
        if not (name.startswith("syft:location:") and name.endswith(":path")):
            continue
        _append_unique(paths, _normalize_component_path(prop.get("value")))
    return paths


def affected_fields(item: Dict[str, Any], components_map: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    names: List[str] = []
    versions: List[str] = []
    components: List[str] = []
    component_paths: List[str] = []

    affects = item.get("affects")
    if isinstance(affects, list):
        for entry in affects:
            if not isinstance(entry, dict):
                continue
            ref = entry.get("ref")
            comp = components_map.get(ref)
            if not comp:
                continue
            name = comp.get("name")
            version = comp.get("version")
            _append_unique(names, name)
            _append_unique(versions, version)
            for path in _extract_component_paths(comp):
                _append_unique(component_paths, path)
            if name and version:
                _append_unique(components, f"{name}@{version}")
            elif name:
                _append_unique(components, str(name))
            elif version:
                _append_unique(components, str(version))

    return {
        "affected_components": ";".join(components),
        "affected_component_paths": ";".join(component_paths),
        "affected_names": ";".join(names),
        "affected_versions": ";".join(versions),
    }


def build_rows(
    vulns: List[Dict[str, Any]], components_map: Dict[str, Dict[str, Any]]
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in vulns:
        flat: Dict[str, Any] = {}
        flatten(item, "", flat)
        score, sev = rating_summary(item.get("ratings"))
        flat["score"] = "" if score is None else score
        flat["severity"] = "" if sev is None else sev
        flat.update(affected_fields(item, components_map))
        flat["False positive"] = ""
        flat["Explanation of false positive"] = ""
        flat["Reviewed by"] = ""
        rows.append(flat)
    return rows


def rows_to_csv(rows: List[Dict[str, Any]], output_path: str) -> None:
    columns: List[str] = [c for c in FIXED_COLUMNS if c not in OMIT_COLUMNS]

    for row in rows:
        for key in row.keys():
            if key in OMIT_COLUMNS:
                continue
            if key not in columns:
                columns.append(key)

    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in columns})


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Merge VEX and VDR vulnerabilities (Syft) and export to CSV."
    )
    parser.add_argument("--vex", default=DEFAULT_VEX, help="Path to vex_syft.json")
    parser.add_argument("--vdr", default=DEFAULT_VDR, help="Path to vdr_syft.json")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output CSV path")
    args = parser.parse_args()

    try:
        vex_vulns = load_vulnerabilities(args.vex)
        vdr_vulns = load_vulnerabilities(args.vdr)
        ensure_ids(vex_vulns, args.vex)
        ensure_ids(vdr_vulns, args.vdr)
        merged = merge_vulnerabilities(vex_vulns + vdr_vulns)
        components_map = load_components_map(args.vdr)
        rows = build_rows(merged, components_map)
        rows_to_csv(rows, args.output)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"CSV created: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
