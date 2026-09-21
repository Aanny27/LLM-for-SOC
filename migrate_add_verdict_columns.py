"""
migrate_add_verdict_columns.py

One-time migration: adds verdict + escalation columns to the existing
soc_results table. Safe to re-run (skips columns that already exist).

Usage:
    python migrate_add_verdict_columns.py --db soc_results.db
"""

import argparse
import sqlite3

NEW_COLUMNS = {
    "verdict": "TEXT",
    "verdict_reasoning": "TEXT",
    "escalation_level": "TEXT",
    "escalation_reason": "TEXT",
    "should_escalate": "INTEGER",  # 0/1
}


def migrate(db_path: str, table: str = "soc_results"):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute(f"PRAGMA table_info({table})")
    existing_cols = {row[1] for row in cur.fetchall()}

    if not existing_cols:
        raise RuntimeError(
            f"Table '{table}' not found in {db_path} — check --db path or table name."
        )

    added = []
    for col, col_type in NEW_COLUMNS.items():
        if col not in existing_cols:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")
            added.append(col)

    conn.commit()
    conn.close()

    if added:
        print(f"Added columns to {table}: {', '.join(added)}")
    else:
        print(f"No changes — {table} already has all verdict/escalation columns.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="soc_results.db", help="Path to SQLite DB file")
    parser.add_argument("--table", default="soc_results", help="Table name to alter")
    args = parser.parse_args()
    migrate(args.db, args.table)
