"""SQLite 在线备份 / 隔离恢复校验（P1-06）。

- 使用 sqlite3 backup API 做一致性备份，不复制 WAL 文件冒充
- 恢复到隔离临时库，不覆盖生产
- integrity_check + schema version + 关键表可读

CLI: python -m ayana.backup {create,restore-rehearsal,validate} ...
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from .db import SCHEMA_VERSION

# 恢复校验必须可读的表
REQUIRED_TABLES = (
    "incidents",
    "investigations",
    "actions",
    "verifications",
    "audit_log",
    "events",
    "alert_episodes",
    "schema_migrations",
)


class BackupError(RuntimeError):
    def __init__(self, code: str, message: str = ""):
        self.code = code
        self.detail = message
        super().__init__(f"{code}: {message}" if message else code)


def create_backup(
    source_path: str | Path,
    dest_path: str | Path,
    *,
    source_label: str = "",
) -> dict[str, Any]:
    """在线一致性备份。

    源库可以是 WAL 运行中数据库；backup API 会取得一致快照。
    失败必须显式抛 BackupError。
    """
    src = Path(source_path)
    dst = Path(dest_path)
    if not src.is_file():
        raise BackupError("source_missing", str(src))
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        dst.unlink()
    meta: dict[str, Any] = {
        "created_at": time.time(),
        "source_label": source_label or src.name,
        "dest": str(dst),
        "schema_version": None,
        "ok": False,
        "size": 0,
    }
    try:
        s = sqlite3.connect(str(src), timeout=10.0)
        s.row_factory = sqlite3.Row
        try:
            s.execute("PRAGMA busy_timeout=10000")
            d = sqlite3.connect(str(dst), timeout=10.0)
            try:
                s.backup(d)
                d.commit()
                row = d.execute(
                    "SELECT value FROM meta WHERE key='schema_version'"
                ).fetchone()
                meta["schema_version"] = int(row[0]) if row else None
                # 备份后源端不得被破坏
                integrity = d.execute("PRAGMA integrity_check").fetchone()
                if not integrity or integrity[0] != "ok":
                    raise BackupError("integrity_failed", str(integrity))
            finally:
                d.close()
        finally:
            s.close()
        meta["size"] = dst.stat().st_size
        meta["ok"] = True
        # metadata sidecar（不含敏感路径以外的秘密）
        side = dst.with_suffix(dst.suffix + ".meta.json")
        side.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        return meta
    except BackupError:
        raise
    except Exception as e:
        raise BackupError("backup_failed", str(e)) from e


def restore_rehearsal(
    backup_path: str | Path,
    *,
    work_dir: str | Path | None = None,
    expected_schema: int | None = None,
) -> dict[str, Any]:
    """恢复到隔离临时库并校验。不触碰生产库。

    返回校验报告；不通过则 ok=False 并给出 reasons。
    """
    import tempfile

    src = Path(backup_path)
    if not src.is_file():
        raise BackupError("backup_missing", str(src))
    expected = SCHEMA_VERSION if expected_schema is None else int(expected_schema)

    td = None
    if work_dir is None:
        td = tempfile.TemporaryDirectory(prefix="ayana-restore-")
        work = Path(td.name)
    else:
        work = Path(work_dir)
        work.mkdir(parents=True, exist_ok=True)

    restored = work / "restored.db"
    report: dict[str, Any] = {
        "ok": False,
        "backup": str(src),
        "restored": str(restored),
        "integrity": "",
        "schema_version": None,
        "expected_schema": expected,
        "tables": {},
        "reasons": [],
    }
    try:
        # 用 backup API 从备份复制到隔离库（等价于恢复）
        s = sqlite3.connect(str(src), timeout=10.0)
        d = sqlite3.connect(str(restored), timeout=10.0)
        try:
            s.backup(d)
            d.commit()
            integ = d.execute("PRAGMA integrity_check").fetchone()
            report["integrity"] = (integ[0] if integ else "")
            if report["integrity"] != "ok":
                report["reasons"].append(f"integrity:{report['integrity']}")
            row = d.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            report["schema_version"] = int(row[0]) if row else None
            if report["schema_version"] != expected:
                report["reasons"].append(
                    f"schema_version:{report['schema_version']}!={expected}"
                )
            for t in REQUIRED_TABLES:
                try:
                    n = d.execute(f"SELECT COUNT(*) AS n FROM {t}").fetchone()
                    report["tables"][t] = int(n[0]) if n else 0
                except Exception as e:
                    report["tables"][t] = None
                    report["reasons"].append(f"table_unreadable:{t}:{e}")
            # 关键逻辑校验：schema_migrations 应覆盖到 current
            try:
                applied = d.execute(
                    "SELECT MAX(version) AS v FROM schema_migrations"
                ).fetchone()
                max_v = int(applied[0] or 0) if applied else 0
                if max_v < expected:
                    report["reasons"].append(f"migrations_incomplete:{max_v}<{expected}")
            except Exception as e:
                report["reasons"].append(f"migrations_check:{e}")
        finally:
            d.close()
            s.close()
        report["ok"] = not report["reasons"]
        return report
    finally:
        if td is not None:
            # 允许调用方先检查 report；此处清理
            try:
                td.cleanup()
            except Exception:
                pass


def validate_backup_file(backup_path: str | Path) -> dict[str, Any]:
    """快速校验备份文件是否可读且完整（不恢复）。"""
    src = Path(backup_path)
    if not src.is_file():
        return {"ok": False, "reasons": ["missing"]}
    try:
        c = sqlite3.connect(f"file:{src}?mode=ro", uri=True, timeout=5.0)
        try:
            integ = c.execute("PRAGMA integrity_check").fetchone()
            row = c.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            tables = [
                r[0]
                for r in c.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            ]
        finally:
            c.close()
        reasons = []
        if not integ or integ[0] != "ok":
            reasons.append(f"integrity:{integ}")
        missing = [t for t in REQUIRED_TABLES if t not in tables]
        if missing:
            reasons.append(f"missing_tables:{missing}")
        return {
            "ok": not reasons,
            "integrity": integ[0] if integ else "",
            "schema_version": int(row[0]) if row else None,
            "tables": tables,
            "reasons": reasons,
        }
    except Exception as e:
        return {"ok": False, "reasons": [str(e)]}


def main(argv: list[str] | None = None) -> int:
    """CLI: python -m ayana.backup {create,restore-rehearsal,validate} ..."""
    import argparse
    import sys as _sys

    parser = argparse.ArgumentParser(prog="ayana.backup", description="Ayana SQLite 备份/恢复校验")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_create = sub.add_parser("create", help="在线一致性备份")
    p_create.add_argument("source", help="源数据库路径")
    p_create.add_argument("dest", help="备份输出路径")
    p_create.add_argument("--label", default="", help="备份来源标签")

    p_restore = sub.add_parser("restore-rehearsal", help="恢复到隔离临时库并校验")
    p_restore.add_argument("backup", help="备份文件路径")
    p_restore.add_argument("--work-dir", default=None, help="隔离工作目录（默认临时目录）")
    p_restore.add_argument("--expected-schema", type=int, default=None, help="期望 schema 版本")

    p_validate = sub.add_parser("validate", help="快速校验备份文件")
    p_validate.add_argument("backup", help="备份文件路径")

    args = parser.parse_args(argv)
    try:
        if args.cmd == "create":
            meta = create_backup(args.source, args.dest, source_label=args.label)
            print(json.dumps(meta, ensure_ascii=False, indent=2))
            return 0 if meta.get("ok") else 1
        if args.cmd == "restore-rehearsal":
            report = restore_rehearsal(
                args.backup, work_dir=args.work_dir, expected_schema=args.expected_schema,
            )
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return 0 if report.get("ok") else 1
        if args.cmd == "validate":
            report = validate_backup_file(args.backup)
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return 0 if report.get("ok") else 1
    except BackupError as e:
        print(json.dumps({"ok": False, "code": e.code, "detail": e.detail}, ensure_ascii=False), file=_sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
