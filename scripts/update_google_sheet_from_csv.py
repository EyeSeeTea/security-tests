#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

import requests
from google.auth.transport.requests import Request
from google.oauth2 import service_account

SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]
SHEETS_BASE = "https://sheets.googleapis.com/v4"
SERVICE_ACCOUNT_ENV = "GOOGLE_SS_SERVICE_ACCOUNT_JSON"
DEFAULT_RANGE = "A:ZZ"


def get_access_token_from_env() -> str:
    raw_json = os.getenv(SERVICE_ACCOUNT_ENV)
    if not raw_json:
        raise SystemExit(f"Missing required environment variable: {SERVICE_ACCOUNT_ENV}")

    try:
        service_account_info = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {SERVICE_ACCOUNT_ENV}: {exc}") from exc

    creds = service_account.Credentials.from_service_account_info(
        service_account_info, scopes=SCOPES
    )
    creds.refresh(Request())
    return creds.token


def _read_google_error(response: requests.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return response.text.strip() or f"HTTP {response.status_code}"

    err = payload.get("error")
    if not isinstance(err, dict):
        return json.dumps(payload, ensure_ascii=False)

    message = err.get("message") or ""
    details = err.get("status") or err.get("code") or ""
    if message and details:
        return f"{details}: {message}"
    if message:
        return str(message)
    return json.dumps(err, ensure_ascii=False)


def _values_url(spreadsheet_id: str, a1_range: str) -> str:
    encoded_range = quote(a1_range, safe="")
    return f"{SHEETS_BASE}/spreadsheets/{spreadsheet_id}/values/{encoded_range}"


def list_sheet_tabs(token: str, spreadsheet_id: str) -> List[str]:
    url = f"{SHEETS_BASE}/spreadsheets/{spreadsheet_id}"
    params = {"fields": "sheets.properties.title"}
    response = requests.get(
        url,
        headers={"Authorization": f"Bearer {token}"},
        params=params,
        timeout=30,
    )
    if not response.ok:
        return []

    payload = response.json()
    tabs: List[str] = []
    for sheet in payload.get("sheets", []):
        if not isinstance(sheet, dict):
            continue
        properties = sheet.get("properties")
        if not isinstance(properties, dict):
            continue
        title = properties.get("title")
        if isinstance(title, str) and title:
            tabs.append(title)
    return tabs


def sheets_get_values(token: str, spreadsheet_id: str, a1_range: str) -> List[List[str]]:
    url = _values_url(spreadsheet_id, a1_range)
    response = requests.get(
        url, headers={"Authorization": f"Bearer {token}"}, timeout=30
    )
    if not response.ok:
        error_detail = _read_google_error(response)
        raise SystemExit(
            f"Failed to read sheet range '{a1_range}' from spreadsheet '{spreadsheet_id}': {error_detail}"
        )
    return response.json().get("values", [])


def sheets_append_values(
    token: str, spreadsheet_id: str, a1_range: str, rows: List[List[str]]
) -> None:
    if not rows:
        return
    url = f"{_values_url(spreadsheet_id, a1_range)}:append"
    params = {
        "valueInputOption": "RAW",
        "insertDataOption": "INSERT_ROWS",
    }
    body = {"values": rows}
    response = requests.post(
        url,
        headers={"Authorization": f"Bearer {token}"},
        params=params,
        json=body,
        timeout=30,
    )
    if not response.ok:
        error_detail = _read_google_error(response)
        raise SystemExit(
            f"Failed to append rows to range '{a1_range}' in spreadsheet '{spreadsheet_id}': {error_detail}"
        )


def read_csv_dicts(path: str) -> Tuple[List[str], List[Dict[str, str]]]:
    with open(path, "r", encoding="utf-8-sig", newline="") as file_obj:
        reader = csv.DictReader(file_obj)
        fieldnames = reader.fieldnames or []
        rows: List[Dict[str, str]] = []
        for row in reader:
            rows.append({k: (v if v is not None else "") for k, v in row.items()})
    return fieldnames, rows


def append_only_new_rows(
    sheet_values: List[List[str]],
    csv_rows: List[Dict[str, str]],
    id_field: str,
    added_column: str,
    added_timestamp: str,
) -> Tuple[List[List[str]], int, int]:
    sheet_header = sheet_values[0]
    if id_field not in sheet_header:
        raise SystemExit(
            f"ID field '{id_field}' does not exist in sheet header: {sheet_header}"
        )

    id_index = sheet_header.index(id_field)
    existing_ids = set()
    for row in sheet_values[1:]:
        if len(row) <= id_index:
            continue
        row_id = str(row[id_index]).strip()
        if row_id:
            existing_ids.add(row_id)

    rows_to_append: List[List[str]] = []
    skipped_existing = 0
    skipped_missing_id = 0
    for row in csv_rows:
        row_id = str(row.get(id_field, "")).strip()
        if not row_id:
            skipped_missing_id += 1
            continue
        if row_id in existing_ids:
            skipped_existing += 1
            continue

        row_to_append = dict(row)
        if added_column in sheet_header:
            row_to_append[added_column] = added_timestamp

        aligned_row = [row_to_append.get(col, "") for col in sheet_header]
        rows_to_append.append(aligned_row)
        existing_ids.add(row_id)

    return rows_to_append, skipped_existing, skipped_missing_id


def find_column_index(header: List[str], column_name: str) -> Optional[int]:
    target = column_name.strip().lower()
    for idx, value in enumerate(header):
        if str(value).strip().lower() == target:
            return idx
    return None


def count_unresolved_by_severity(
    sheet_values: List[List[str]],
    applicable_column: str,
    severity_column: str,
    selected_severities: List[str],
) -> Dict[str, int]:
    if not sheet_values:
        return {severity: 0 for severity in selected_severities}

    header = sheet_values[0]
    applicable_idx = find_column_index(header, applicable_column)
    severity_idx = find_column_index(header, severity_column)

    if applicable_idx is None:
        raise SystemExit(
            f"Column '{applicable_column}' does not exist in sheet header: {header}"
        )
    if severity_idx is None:
        raise SystemExit(
            f"Column '{severity_column}' does not exist in sheet header: {header}"
        )

    counts: Dict[str, int] = {severity: 0 for severity in selected_severities}
    for row in sheet_values[1:]:
        applicable_value = ""
        if len(row) > applicable_idx:
            applicable_value = str(row[applicable_idx]).strip()
        if applicable_value:
            continue

        severity_value = "unknown"
        if len(row) > severity_idx:
            severity_value = str(row[severity_idx]).strip().lower() or "unknown"

        if severity_value in counts:
            counts[severity_value] += 1

    return counts


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Append only new CSV rows into a Google Sheets tab."
    )
    parser.add_argument(
        "--spreadsheet-id",
        required=True,
        help="Google Spreadsheet ID.",
    )
    parser.add_argument(
        "--sheet-name",
        required=True,
        choices=["syft", "yarn4"],
        help="Target tab name.",
    )
    parser.add_argument(
        "--csv-path",
        required=True,
        help="CSV file path with candidate rows to append.",
    )
    parser.add_argument(
        "--id-field",
        default="id",
        help="Unique ID column used to detect existing rows.",
    )
    parser.add_argument(
        "--range-columns",
        default=DEFAULT_RANGE,
        help="Columns range used for read/append, for example A:ZZ.",
    )
    parser.add_argument(
        "--report-severities",
        default="critical,high",
        help="Comma-separated severities to report from unresolved rows.",
    )
    parser.add_argument(
        "--applicable-column",
        default="False positive",
        help="Column that marks whether a finding was identified as false positive.",
    )
    parser.add_argument(
        "--severity-column",
        default="severity",
        help="Column used to group unresolved findings.",
    )
    parser.add_argument(
        "--added-column",
        default="added",
        help="Column that stores when a row was first appended.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    added_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    token = get_access_token_from_env()
    a1_range = f"{args.sheet_name}!{args.range_columns}"

    tabs = list_sheet_tabs(token, args.spreadsheet_id)
    if args.sheet_name not in tabs:
        available_tabs = ", ".join(tabs) if tabs else "(none or inaccessible)"
        raise SystemExit(
            f"Target tab '{args.sheet_name}' was not found in spreadsheet '{args.spreadsheet_id}'. "
            f"Available tabs: {available_tabs}"
        )

    sheet_values = sheets_get_values(token, args.spreadsheet_id, a1_range)
    if not sheet_values:
        raise SystemExit(
            "The sheet tab is empty. It must contain at least one header row."
        )

    csv_fields, csv_rows = read_csv_dicts(args.csv_path)
    if args.id_field not in csv_fields:
        raise SystemExit(
            f"ID field '{args.id_field}' does not exist in CSV header: {csv_fields}"
        )

    rows_to_append, skipped_existing, skipped_missing_id = append_only_new_rows(
        sheet_values,
        csv_rows,
        args.id_field,
        args.added_column,
        added_timestamp,
    )
    sheets_append_values(token, args.spreadsheet_id, a1_range, rows_to_append)

    refreshed_values = sheets_get_values(token, args.spreadsheet_id, a1_range)
    selected_severities = [
        value.strip().lower()
        for value in args.report_severities.split(",")
        if value.strip()
    ]
    unresolved_counts = count_unresolved_by_severity(
        refreshed_values,
        args.applicable_column,
        args.severity_column,
        selected_severities,
    )
    unresolved_selected_total = sum(unresolved_counts.values())
    sheet_url = f"https://docs.google.com/spreadsheets/d/{args.spreadsheet_id}/edit"

    existing_rows = max(len(sheet_values) - 1, 0)
    print(f"Target tab: {args.sheet_name}")
    print(f"Rows already in sheet: {existing_rows}")
    print(f"Rows in CSV input: {len(csv_rows)}")
    print(f"Rows appended: {len(rows_to_append)}")
    print(f"Rows skipped (ID already exists): {skipped_existing}")
    print(f"Rows skipped (missing ID): {skipped_missing_id}")
    print("Unresolved findings (False positive empty) by selected severity:")
    for severity in selected_severities:
        print(f"- {severity}: {unresolved_counts.get(severity, 0)}")
    print(f"Selected unresolved total: {unresolved_selected_total}")
    print(f"Spreadsheet URL: {sheet_url}")

    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as output:
            output.write(f"appended={len(rows_to_append)}\n")
            output.write(f"skipped_existing={skipped_existing}\n")
            output.write(f"skipped_missing_id={skipped_missing_id}\n")
            output.write(f"unresolved_selected_total={unresolved_selected_total}\n")
            output.write(
                "unresolved_counts_json="
                + json.dumps(unresolved_counts, separators=(",", ":"))
                + "\n"
            )
            output.write(f"sheet_url={sheet_url}\n")
            for severity in selected_severities:
                safe_name = "".join(
                    c if c.isalnum() or c == "_" else "_" for c in severity
                )
                output.write(
                    f"unresolved_{safe_name}={unresolved_counts.get(severity, 0)}\n"
                )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
