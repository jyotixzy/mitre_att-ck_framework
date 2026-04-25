# Purpose: Yeh file SQLite database ke saare low-level operations handle karti hai.
# Isme table creation, fresh data insert, aur technique/data-source ke basis par lookup logic diya gaya hai.
# Service layer ko direct SQL likhne ki zarurat na pade, isliye DB logic yahan isolate kiya gaya hai.

import sqlite3
from pathlib import Path
from typing import Iterable


TABLE_NAME = "url_attack_mapping"


def ensure_database(db_path: Path) -> None:
    """Yeh function DB file aur required table ko ensure karta hai.
    Agar DB ya table missing ho to create kar deta hai, taaki baaki code safely query kar sake.
    Initialization flow aur analysis flow dono is helper par depend karte hain."""
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
                tactics TEXT NOT NULL,
                technique_id TEXT NOT NULL,
                technique_name TEXT NOT NULL,
                mitigation_id TEXT NOT NULL,
                mitigation_description TEXT NOT NULL,
                data_source TEXT NOT NULL,
                UNIQUE(technique_id, mitigation_id, data_source)
            )
            """
        )
        connection.commit()


def replace_mappings(db_path: Path, rows: Iterable[tuple[str, str, str, str, str, str]]) -> None:
    """Yeh function purani ATT&CK mapping rows ko hata kar naya dataset store karta hai.
    `init-db` ke time isi function se SQLite refresh hoti hai.
    Isse local DB latest generated mapping ke saath sync me rehti hai."""
    ensure_database(db_path)

    with sqlite3.connect(db_path) as connection:
        connection.execute(f"DELETE FROM {TABLE_NAME}")
        connection.executemany(
            f"""
            INSERT OR IGNORE INTO {TABLE_NAME} (
                tactics,
                technique_id,
                technique_name,
                mitigation_id,
                mitigation_description,
                data_source
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            list(rows),
        )
        connection.commit()


def has_mapping_rows(db_path: Path) -> bool:
    """Yeh check karta hai ki mapping table me actual ATT&CK rows present hain ya nahi.
    Analyze flow isse decide karta hai ki DB ready hai ya pehle sync karna padega.
    Empty DB hone par yeh `False` return karega."""
    ensure_database(db_path)

    with sqlite3.connect(db_path) as connection:
        cursor = connection.execute(f"SELECT COUNT(*) FROM {TABLE_NAME}")
        count = cursor.fetchone()[0]
    return count > 0


def fetch_results_for_techniques(
    db_path: Path, technique_data_source_pairs: Iterable[tuple[str, str]]
) -> list[tuple[str, str, str, str, str, str]]:
    """Yeh detected technique aur data source pairs ke liye matching DB rows nikalta hai.
    Input usually heuristics module se aata hai aur output CLI ke final JSON me jata hai.
    Isi step me mitigations, tactic aur technique details local SQLite se resolve hoti hain."""
    ensure_database(db_path)
    pairs = list({pair for pair in technique_data_source_pairs})
    if not pairs:
        return []

    query = f"""
        SELECT
            tactics,
            technique_id,
            technique_name,
            mitigation_id,
            mitigation_description,
            data_source
        FROM {TABLE_NAME}
        WHERE technique_id = ? AND data_source = ?
        ORDER BY technique_id, mitigation_id
    """

    results: list[tuple[str, str, str, str, str, str]] = []
    with sqlite3.connect(db_path) as connection:
        cursor = connection.cursor()
        for pair in pairs:
            cursor.execute(query, pair)
            results.extend(cursor.fetchall())
    return results
