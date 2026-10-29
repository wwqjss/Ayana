"""导出旧自治/权限历史数据（导出后才允许删表）。

用法：
  python scripts/export_retired_tables.py [db_path] [outdir]

默认从当前生产 t.db 导出 JSONL 到 outputs/retired-export/。
绝不打印或导出明文密钥：ai_provider_keys 只导出元数据列。
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

# 只导出元数据，排除密文/明文秘密列
TABLES = {
    "permissions": None,
    "agent_ceiling": None,
    "permission_changes": None,
    "ai_calls": None,
    "ai_provider_keys": ["id", "role", "provider", "label", "base_url", "model",
                         "created_at", "updated_at", "verified_at", "status"],
    "incident_session": None,
}


def export(db_path: Path, outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    for table, cols in TABLES.items():
        exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()
        if not exists:
            print(f"skip {table}: no table")
            continue
        col_names = [r["name"] for r in conn.execute(f"PRAGMA table_info({table})")]
        selected = cols if cols else col_names
        selected = [c for c in selected if c in col_names]
        rows = conn.execute(f"SELECT {', '.join(selected)} FROM {table}").fetchall()
        out = outdir / f"{table}.jsonl"
        with out.open("w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(dict(row), ensure_ascii=False) + "\n")
        print(f"exported {table}: {len(rows)} rows -> {out}")
    conn.close()


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    db = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "t.db"
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else root / "outputs" / "retired-export"
    if not db.exists():
        print(f"db not found: {db}", file=sys.stderr)
        sys.exit(1)
    export(db, out)
