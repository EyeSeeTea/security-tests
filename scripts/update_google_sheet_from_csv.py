#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
from typing import Dict, List, Tuple

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


def sheets_get_values(token: str, spreadsheet_id: str, a1_range: str) -> List[List[str]]:
    url = f"{SHEETS_BASE}/spreadsheets/{spreadsheet_id}/values/{a1_range}"
    response = requests.get(
        url, headers={"Authorization": f"Bearer {token}"}, timeout=30
    )
    response.raise_for_status()
    return response.json().get("values", [])


def sheets_append_values(
    token: str, spreadsheet_id: str, a1_range: str, rows: List[List[str]]
) -> None:
    if not rows:
        return
    url = f"{SHEETS_BASE}/spreadsheets/{spreadsheet_id}/values/{a1_range}:append"
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
    response.raise_for_status()


def read_csv_dicts(path: str) -> Tuple[List[str], List[Dict[str, str]]]:
    with open(path, "r", encoding="utf-8-sig", newline="") as file_obj:
        reader = csv.DictReader(file_obj)
        fieldnames = reader.fieldnames or []
        rows = []
        for row in reader:
            rows.append({k: (v if v is not None else "") for k, v in row.items()})
    return fieldnames, rows


def append_only_new_rows(
    sheet_values: List[List[str]], csv_rows: List[Dict[str, str]], id_field: str
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

        aligned_row = [row.get(col, "") for col in sheet_header]
        rows_to_append.append(aligned_row)
        existing_ids.add(row_id)

    return rows_to_append, skipped_existing, skipped_missing_id


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
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    token = get_access_token_from_env()
    a1_range = f"{args.sheet_name}!{args.range_columns}"

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
        sheet_values, csv_rows, args.id_field
    )
    sheets_append_values(token, args.spreadsheet_id, a1_range, rows_to_append)

    existing_rows = max(len(sheet_values) - 1, 0)
    print(f"Target tab: {args.sheet_name}")
    print(f"Rows already in sheet: {existing_rows}")
    print(f"Rows in CSV input: {len(csv_rows)}")
    print(f"Rows appended: {len(rows_to_append)}")
    print(f"Rows skipped (ID already exists): {skipped_existing}")
    print(f"Rows skipped (missing ID): {skipped_missing_id}")

    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as output:
            output.write(f"appended={len(rows_to_append)}\n")
            output.write(f"skipped_existing={skipped_existing}\n")
            output.write(f"skipped_missing_id={skipped_missing_id}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
