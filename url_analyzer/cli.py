# Purpose: Yeh file command-line interface provide karti hai.
# User jo terminal commands `init-db` aur `analyze` run karta hai, unka parsing aur execution flow yahin handle hota hai.
# Presentation layer ke hisaab se final JSON output bhi isi module se print hota hai.

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from url_analyzer.config import DB_PATH
from url_analyzer.service import analyze_email, sync_attack_database


def main() -> None:
    """Yeh CLI arguments parse karke correct command branch choose karta hai.
    User ne DB initialize karna hai ya email analyze karna hai, yeh decision isi function me hota hai.
    Top-level command handling ke liye yeh module ka primary controller hai."""
    parser = argparse.ArgumentParser(
        description="MITRE ATT&CK based URL analyzer for `.eml` email files."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser(
        "init-db", help="Fetch MITRE Enterprise data and populate SQLite mappings."
    )
    init_parser.add_argument(
        "--db-path",
        default=str(DB_PATH),
        help="Optional SQLite database path.",
    )

    analyze_parser = subparsers.add_parser(
        "analyze", help="Analyze a `.eml` file and print ATT&CK output rows."
    )
    analyze_parser.add_argument("eml_path", help="Path to the `.eml` file to inspect.")
    analyze_parser.add_argument(
        "--db-path",
        default=str(DB_PATH),
        help="Optional SQLite database path.",
    )

    args = parser.parse_args()
    if args.command == "init-db":
        _run_init(Path(args.db_path))
    elif args.command == "analyze":
        _run_analysis(Path(args.eml_path), Path(args.db_path))


def _run_init(db_path: Path) -> None:
    """Yeh helper database initialization command execute karta hai.
    MITRE data ko fetch karke SQLite me save karta hai aur user ko inserted row count dikhata hai.
    Project ko first time use karte waqt generally yahi command pehle chalti hai."""
    count = sync_attack_database(db_path)
    print(f"Database initialized: {db_path}")
    print(f"Inserted rows: {count}")


def _run_analysis(eml_path: Path, db_path: Path) -> None:
    """Yeh helper ek email file analyze karke final grouped JSON output print karta hai.
    Raw DB rows ko yeh readable technique-wise structure me convert karta hai jahan mitigations grouped hoti hain.
    Demo output ko clean aur understandable banane ke liye yeh formatting step important hai."""
    results = analyze_email(eml_path, db_path)
    if not results:
        print(json.dumps([], indent=2))
        return

    dataframe = pd.DataFrame(
        results,
        columns=[
            "tactics",
            "technique_id",
            "technique_name",
            "mitigation_id",
            "mitigation_description",
            "data_source",
        ],
    ).drop_duplicates()

    grouped_results: list[dict[str, object]] = []
    grouping_columns = ["tactics", "technique_id", "technique_name", "data_source"]

    for group_keys, group_frame in dataframe.groupby(grouping_columns, dropna=False, sort=True):
        tactics, technique_id, technique_name, data_source = group_keys
        mitigations = (
            group_frame[["mitigation_id", "mitigation_description"]]
            .drop_duplicates()
            .sort_values(by=["mitigation_id"])
            .to_dict(orient="records")
        )

        grouped_results.append(
            {
                "tactics": tactics,
                "technique_id": technique_id,
                "technique_name": technique_name,
                "data_source": data_source,
                "mitigations": mitigations,
            }
        )

    print(json.dumps(grouped_results, indent=2, ensure_ascii=True))
