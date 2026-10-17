#!/usr/bin/env python3
"""把旧版硬编码的 required_checks / runbook 迁到 config.json。

用法（在仍带有旧代码的部署旁执行，例如升级前的 KANATA）：
  python3 scripts/migrate_monitor_config.py \\
    --legacy-health /opt/ayana/ayana/health.py \\
    --legacy-runbook /opt/ayana/ayana/runbook.py \\
    --config /etc/ayana/config.json

行为：
- 只新增/合并 config 中的 required_checks、runbook_rules 键
- 不覆盖 secrets.json、不改数据库、不动其它配置项
- 已有同名 runbook id 以文件解析结果为准写入（写前打印 diff 摘要）
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path


def _load_dict_assign(src: str, name: str):
    """从源码里抠出 NAME = {...} / NAME = [...] 的字面量。"""
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    return ast.literal_eval(node.value)
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--legacy-health", required=True)
    ap.add_argument("--legacy-runbook", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    health_src = Path(args.legacy_health).read_text(encoding="utf-8", errors="replace")
    runbook_src = Path(args.legacy_runbook).read_text(encoding="utf-8", errors="replace")
    try:
        required = _load_dict_assign(health_src, "REQUIRED_CHECKS") or {}
    except Exception as e:
        print(f"WARN: parse REQUIRED_CHECKS failed: {e}", file=sys.stderr)
        required = {}
    raw_rules = []  # RUNBOOK 含 RunbookRule() 调用，不能 literal_eval

    # RunbookRule(...) 调用不是纯字面量，用宽松正则抽字段
    rules = []
    for m in re.finditer(r"RunbookRule\((.*?)\)", runbook_src, re.S):
        body = m.group(1)
        item = {"id": "", "name": ""}
        for key in (
            "id",
            "name",
            "asset_id",
            "object_name",
            "alertname",
            "category",
            "capability",
            "reason",
            "require_service_state",
        ):
            km = re.search(rf"{key}\s*=\s*[\"']([^\"']*)[\"']", body)
            if km:
                item[key] = km.group(1)
        for key in ("require_probe_fail", "manual_only"):
            km = re.search(rf"{key}\s*=\s*(True|False)", body)
            if km:
                item[key] = km.group(1) == "True"
        for key in ("max_per_day", "cooldown_sec"):
            km = re.search(rf"{key}\s*=\s*(\d+)", body)
            if km:
                item[key] = int(km.group(1))
        if item.get("id"):
            rules.append(item)

    cfg_path = Path(args.config)
    cfg = json.loads(cfg_path.read_text(encoding="utf-8")) if cfg_path.exists() else {}
    print(f"legacy REQUIRED_CHECKS assets: {list(required.keys())}")
    print(f"legacy RUNBOOK rules: {[r.get('id') for r in rules]}")
    print(f"config keys before: {sorted(cfg.keys())}")

    cfg["required_checks"] = required
    if rules:
        cfg["runbook_rules"] = rules

    print(f"config keys after: {sorted(cfg.keys())}")
    if args.dry_run:
        print(json.dumps({"required_checks": required, "runbook_rules": rules}, ensure_ascii=False, indent=2)[:2000])
        return 0
    cfg_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {cfg_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
