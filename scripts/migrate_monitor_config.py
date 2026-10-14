#!/usr/bin/env python3
"""把旧版硬编码的 REQUIRED_CHECKS / RUNBOOK 迁到 config.json。

安全约束：
- 解析失败或规则数异常 → 退出码非 0，禁止静默丢规则
- --dry-run / --check 只读，不写文件
- 默认合并：按 asset_id / rule id 取并集，不删除用户已写的其它规则
- --replace 才整段替换 required_checks / runbook_rules
- 只碰这两个键；不覆盖 secrets、不改数据库、不动其它配置

用法（升级前、旧代码仍在时）：
  python3 scripts/migrate_monitor_config.py \\
    --legacy-health /opt/ayana/ayana/health.py \\
    --legacy-runbook /opt/ayana/ayana/runbook.py \\
    --config /etc/ayana/config.json --dry-run
  # 核对输出后去掉 --dry-run 写入；再升级代码
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path


def _load_assign_literal(src: str, name: str):
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    return ast.literal_eval(node.value)
        # 兼容 NAME: Type = {...} 注解赋值
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == name and node.value is not None:
                return ast.literal_eval(node.value)
    return None


def _count_required_literal_hits(src: str) -> int:
    """源码 REQUIRED_CHECKS 字面量里大约有多少条 object 项（粗检，防静默丢失）。"""
    m = re.search(r"REQUIRED_CHECKS[^=]*=\s*\{", src)
    if not m:
        return 0
    # 从赋值处截到下一个顶层 FRESHNESS/def/class
    tail = src[m.end() :]
    end = re.search(r"\n(?:FRESHNESS_|def |class |@)", tail)
    block = tail[: end.start()] if end else tail[:2000]
    return len(re.findall(r"\"object\"\s*:", block))


def _count_runbook_calls(src: str) -> int:
    return len(re.findall(r"\bRunbookRule\s*\(", src))


def _parse_runbook_rules(src: str) -> list[dict]:
    """AST 解析 RunbookRule(...)，字段完整、可校验。"""
    tree = ast.parse(src)
    rules: list[dict] = []

    def _const(node):
        if isinstance(node, ast.Constant):
            return node.value
        return None

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = getattr(fn, "id", "") or getattr(fn, "attr", "")
        if name != "RunbookRule":
            continue
        item: dict = {}
        for kw in node.keywords:
            key = kw.arg
            if not key:
                continue
            val = _const(kw.value)
            if val is None and isinstance(kw.value, ast.UnaryOp) and isinstance(kw.value.op, ast.USub):
                val = -_const(kw.value.operand)
            if val is None:
                continue
            item[key] = val
        if item.get("id"):
            rules.append(item)
    return rules


def _norm_required(required: dict) -> dict:
    out = {}
    for asset_id, items in (required or {}).items():
        if not isinstance(asset_id, str) or not isinstance(items, list):
            continue
        cleaned = []
        for it in items:
            if not isinstance(it, dict):
                continue
            cleaned.append(
                {
                    "object": str(it.get("object") or ""),
                    "metric": str(it.get("metric") or "probe_success"),
                    "selector": dict(it.get("selector") or {}),
                    "freshness_sec": float(it.get("freshness_sec") or 120),
                }
            )
        if cleaned:
            out[asset_id] = cleaned
    return out


REQUIRED_FIELDS = ("object", "metric", "selector")
RULE_REQUIRED_FIELDS = ("id", "capability")


def _validate(required: dict, rules: list[dict]) -> list[str]:
    problems = []
    for aid, items in required.items():
        for i, it in enumerate(items):
            for f in REQUIRED_FIELDS:
                if f not in it:
                    problems.append(f"required_checks[{aid}][{i}] missing {f}")
    seen = set()
    for r in rules:
        rid = r.get("id") or ""
        if rid in seen:
            problems.append(f"duplicate runbook id: {rid}")
        seen.add(rid)
        for f in RULE_REQUIRED_FIELDS:
            if not r.get(f):
                problems.append(f"runbook {rid or '?'} missing {f}")
    return problems


def _merge_required(base: dict, incoming: dict) -> dict:
    """按 asset_id 合并：object 名相同的以 incoming 为准，保留 base 中其余 object。"""
    out = {k: list(v) for k, v in (base or {}).items()}
    for aid, items in (incoming or {}).items():
        existing = out.get(aid, [])
        by_obj = {str(it.get("object") or ""): it for it in existing}
        for it in items:
            by_obj[str(it.get("object") or "")] = it
        out[aid] = list(by_obj.values())
    return out


def _merge_rules(base: list, incoming: list) -> list:
    out = []
    by_id = {}
    for r in list(base or []) + list(incoming or []):
        rid = r.get("id")
        if not rid:
            continue
        by_id[rid] = r  # incoming 同 id 覆盖
    return list(by_id.values())


def _count_required(required: dict) -> int:
    return sum(len(v) for v in (required or {}).values())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--legacy-health", required=True)
    ap.add_argument("--legacy-runbook", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--dry-run", action="store_true", help="只预览，不写文件")
    ap.add_argument("--check", action="store_true", help="校验 legacy 与 config 是否已对齐，不写")
    ap.add_argument("--replace", action="store_true", help="整段替换（默认合并）")
    args = ap.parse_args()

    health_path = Path(args.legacy_health)
    runbook_path = Path(args.legacy_runbook)
    if not health_path.is_file() or not runbook_path.is_file():
        print("ERROR: legacy source files not found", file=sys.stderr)
        return 2

    health_src = health_path.read_text(encoding="utf-8", errors="replace")
    runbook_src = runbook_path.read_text(encoding="utf-8", errors="replace")

    try:
        required = _norm_required(_load_assign_literal(health_src, "REQUIRED_CHECKS") or {})
    except Exception as e:
        print(f"ERROR: parse REQUIRED_CHECKS failed: {e}", file=sys.stderr)
        return 2

    call_n = _count_runbook_calls(runbook_src)
    try:
        rules = _parse_runbook_rules(runbook_src)
    except Exception as e:
        print(f"ERROR: parse RUNBOOK failed: {e}", file=sys.stderr)
        return 2

    # 源码里有 RunbookRule( 却解析不出 → 视为静默丢失，必须失败
    if call_n > 0 and len(rules) == 0:
        print(f"ERROR: found {call_n} RunbookRule() but parsed 0 rules", file=sys.stderr)
        return 2
    if call_n != len(rules):
        print(
            f"ERROR: RunbookRule() count {call_n} != parsed {len(rules)}; refusing to migrate",
            file=sys.stderr,
        )
        return 2

    # REQUIRED_CHECKS 同理：源码有 object 字面量却解析为空 → 拒绝
    hits = _count_required_literal_hits(health_src)
    parsed_n = _count_required(required)
    if hits > 0 and parsed_n == 0:
        print(
            f"ERROR: health.py has ~{hits} required check literals but parsed 0; refusing to migrate",
            file=sys.stderr,
        )
        return 2

    problems = _validate(required, rules)
    if problems:
        print("ERROR: validation failed:", file=sys.stderr)
        for p in problems:
            print("  -", p, file=sys.stderr)
        return 2

    cfg_path = Path(args.config)
    cfg = {}
    if cfg_path.exists():
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"ERROR: config.json invalid: {e}", file=sys.stderr)
            return 2
        if not isinstance(cfg, dict):
            print("ERROR: config.json must be object", file=sys.stderr)
            return 2

    existing_req = _norm_required(cfg.get("required_checks") or {})
    existing_rules = [
        r for r in (cfg.get("runbook_rules") or []) if isinstance(r, dict) and r.get("id")
    ]

    if args.replace:
        new_req, new_rules = required, rules
    else:
        new_req = _merge_required(existing_req, required)
        new_rules = _merge_rules(existing_rules, rules)

    print("=== migration preview ===")
    print(f"legacy REQUIRED_CHECKS: assets={list(required.keys())} checks={_count_required(required)}")
    print(f"legacy RUNBOOK: rules={len(rules)} ids={[r.get('id') for r in rules]}")
    print(f"config before: assets={list(existing_req.keys())} checks={_count_required(existing_req)} rules={len(existing_rules)}")
    print(f"config after : assets={list(new_req.keys())} checks={_count_required(new_req)} rules={len(new_rules)}")
    print(f"mode: {'replace' if args.replace else 'merge'}")
    if args.dry_run:
        print("--- payload ---")
        print(json.dumps({"required_checks": new_req, "runbook_rules": new_rules}, ensure_ascii=False, indent=2))
        return 0

    if args.check:
        missing_req = [
            a
            for a, items in required.items()
            if _count_required({a: items}) != _count_required({a: new_req.get(a, [])})
        ]
        missing_rules = [r["id"] for r in rules if r["id"] not in {x.get("id") for x in new_rules}]
        if missing_req or missing_rules:
            print(f"CHECK FAIL missing assets={missing_req} rules={missing_rules}", file=sys.stderr)
            return 3
        print("CHECK OK: legacy rules fully represented in config")
        return 0

    # 写入前最终数量断言
    if _count_required(new_req) < _count_required(required):
        print("ERROR: would lose required checks; abort", file=sys.stderr)
        return 2
    if len(new_rules) < len(rules):
        print("ERROR: would lose runbook rules; abort", file=sys.stderr)
        return 2

    cfg["required_checks"] = new_req
    cfg["runbook_rules"] = new_rules
    tmp = cfg_path.with_suffix(cfg_path.suffix + ".tmp")
    tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(cfg_path)
    print(f"wrote {cfg_path}")
    print(f"required_checks={_count_required(new_req)} runbook_rules={len(new_rules)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
