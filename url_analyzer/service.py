# Purpose: Yeh file project ki orchestration layer hai.
# Parser, heuristics, MITRE loader aur DB module ko jodkar actual application flow yahin control hota hai.

from __future__ import annotations

from pathlib import Path

from url_analyzer.config import DB_PATH
from url_analyzer.db import (
    ensure_database,
    fetch_results_for_techniques,
    has_mapping_rows,
    replace_mappings,
)
from url_analyzer.eml_parser import extract_urls_from_eml
from url_analyzer.heuristics import analyze_urls
from url_analyzer.mitre_loader import build_attack_mapping_rows


def sync_attack_database(db_path: Path = DB_PATH) -> int:
    """Yeh function ATT&CK data load karke local SQLite database refresh karta hai.
    `init-db` command ke time yahi function run hota hai aur latest mapping rows store karta hai.
    Return value inserted row count hota hai, jo CLI user ko dikhata hai."""
    rows = build_attack_mapping_rows()
    replace_mappings(db_path, rows)
    return len(rows)


def analyze_email(eml_path: Path, db_path: Path = DB_PATH) -> list[tuple[str, str, str, str, str, str]]:
    """Yeh project ka main analysis workflow hai jo ek `.eml` file process karta hai.
    Pehle URLs extract hote hain, phir heuristics se technique pairs bante hain, aur finally DB se mitigations fetch hoti hain.
    Final returned rows ko CLI JSON format me present karta hai."""
    ensure_database(db_path)
    if not has_mapping_rows(db_path):
        sync_attack_database(db_path)

    urls = extract_urls_from_eml(eml_path)
    findings = analyze_urls(urls)
    technique_pairs = [(finding.technique_id, finding.data_source) for finding in findings]
    return fetch_results_for_techniques(db_path, technique_pairs)
