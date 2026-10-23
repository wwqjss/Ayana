#!/usr/bin/env python3
"""飞牛备份只读采集器 → Ayana 外部事务上报。

只读打开 basic_backup.db3，不修改飞牛任务/数据库/凭据。
每个任务映射一个 event_key；每次执行 run_id = fnbk:{task_id}:{operation_id}。
DB 不可读/字段异常 → report_kind=collector，绝不默认成功。
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

DB_PATH = "/usr/trim/var/backup_service/basic_backup.db3"
LOG_PATH = "/usr/trim/logs/backup_service.log"
STATE_PATH = "/var/lib/ayana/ext-collector-state.json"
CONFIG_PATH = "/etc/ayana/ext-collector.json"
AYANA_URL = "http://127.0.0.1:6200"

ERROR_CODE_HINTS = {
    84934737: "RefreshTokenExpired / 云盘令牌失效",
    0: "",
}


def slugify(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", (name or "task").strip()).strip("-").lower()
    return s or "task"


def log(msg: str) -> None:
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)


def load_json(path: str, default):
    try:
        p = Path(path)
        if not p.exists():
            return default
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        log(f"load_json {path} failed: {e}")
        return default


def save_json(path: str, data) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(p)


def open_db_ro(path: str) -> sqlite3.Connection:
    uri = f"file:{path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=5.0)
    conn.row_factory = sqlite3.Row
    return conn


def map_status(op: dict) -> tuple[str, str, str]:
    """返回 (status, message, detail)。无法识别 → unknown，不默认成功。"""
    st = op.get("status")
    err = int(op.get("error_code") or 0)
    fin = int(op.get("finished_time") or 0)
    start = int(op.get("start_time") or 0)
    msg = (op.get("error_message") or "").strip()
    hint = ERROR_CODE_HINTS.get(err, "")
    detail_parts = []
    if err:
        detail_parts.append(f"error_code={err}({err:#x})")
    if hint:
        detail_parts.append(hint)
    if msg:
        detail_parts.append(msg[:200])
    detail = "; ".join(detail_parts)

    if st == 3 and err == 0 and fin:
        return "success", "备份成功", detail or f"files={op.get('files_count')}"
    if st == 4 or (err != 0 and fin):
        return "failure", msg or hint or f"备份失败 error_code={err}", detail
    if start and not fin:
        return "running", "执行中", f"start_time={start}"
    if st == 3 and not fin:
        return "running", "执行中", f"status=3 unfinished start={start}"
    return "unknown", f"无法识别的执行状态 status={st}", detail or f"status={st} err={err}"


def extract_log_reason(task_name: str, op_id: int, error_code: int, log_path: str = "") -> str:
    """从 backup_service.log 尾部提取错误原因（尽力而为）。"""
    try:
        path = log_path or LOG_PATH
        if not os.path.exists(path):
            return ""
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            f.seek(max(0, size - 400000))
            data = f.read().decode("utf-8", "replace")
        keys = []
        if error_code:
            keys.append(str(error_code))
        keys.extend(["RefreshToken", "expired", "Failed", "error"])
        if task_name:
            keys.append(task_name)
        hits = []
        for ln in data.splitlines():
            low = ln.lower()
            if any(k.lower() in low for k in keys):
                hits.append(ln.strip())
        return " | ".join(hits[-3:])[:400]
    except Exception:
        return ""


def report(cfg: dict, event_key: str, body: dict) -> tuple[bool, str]:
    token = (cfg.get("tokens") or {}).get(event_key) or ""
    if not token:
        return False, f"no token for {event_key}"
    url = (cfg.get("ayana_url") or AYANA_URL).rstrip("/") + "/api/ext/report"
    payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode() or "{}")
            return bool(data.get("ok")), json.dumps(data, ensure_ascii=False)[:200]
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode("utf-8", "replace")[:200]
        except Exception:
            detail = ""
        return False, f"HTTP {e.code} {detail}"
    except Exception as e:
        return False, str(e)[:200]


def report_collector_error(cfg: dict, message: str, detail: str) -> None:
    """采集异常：对配置了 collector 通道的任一事务上报（取第一个）。"""
    tokens = cfg.get("tokens") or {}
    if not tokens:
        log(f"collector error but no tokens configured: {message}")
        return
    event_key = next(iter(tokens))
    body = {
        "event_key": event_key,
        "status": "unknown",
        "report_kind": "collector",
        "severity": "warning",
        "message": message[:500],
        "detail": detail[:2000],
        "run_id": f"fnbk-collector-{int(time.time())}",
    }
    ok, resp = report(cfg, event_key, body)
    log(f"collector error reported ok={ok} {resp}")


def main() -> int:
    cfg = load_json(CONFIG_PATH, {
        "ayana_url": AYANA_URL,
        "db_path": DB_PATH,
        "log_path": LOG_PATH,
        "state_path": STATE_PATH,
        "tokens": {},
    })
    db_path = cfg.get("db_path") or DB_PATH
    state_path = cfg.get("state_path") or STATE_PATH
    log_path = cfg.get("log_path") or LOG_PATH

    state = load_json(state_path, {})
    if not isinstance(state, dict):
        state = {}
    ckpt = state.setdefault("checkpoints", {})

    try:
        conn = open_db_ro(db_path)
    except Exception as e:
        log(f"DB open failed: {e}")
        report_collector_error(cfg, "飞牛备份库不可读", f"{type(e).__name__}: {e}"[:200])
        return 2

    try:
        tasks = [dict(r) for r in conn.execute("SELECT * FROM user_tasks")]
    except Exception as e:
        log(f"read user_tasks failed: {e}")
        report_collector_error(cfg, "飞牛备份库读取异常", f"user_tasks: {e}"[:200])
        conn.close()
        return 2

    reported = 0
    errors = 0
    try:
        for task in tasks:
            tid = int(task.get("id") or 0)
            name = str(task.get("name") or f"task{tid}")
            event_key = f"fnbk.task_{slugify(name)}"
            tokens = cfg.get("tokens") or {}
            if event_key not in tokens:
                log(f"skip task {name} ({tid}): no token for {event_key}")
                continue

            # 只读查询该任务执行记录：按开始时间排序（id 不保证时间单调）
            slot = ckpt.get(str(tid)) or {}
            seen = slot.get("seen_op_ids") or []
            seen_set = set(int(x) for x in seen)
            try:
                ops = [
                    dict(r)
                    for r in conn.execute(
                        "SELECT * FROM operations WHERE task_id=?"
                        " ORDER BY COALESCE(start_time, finished_time, 0) ASC, id ASC",
                        (tid,),
                    )
                ]
            except Exception as e:
                log(f"read operations failed task={tid}: {e}")
                report_collector_error(cfg, "飞牛备份执行记录读取异常", f"task={tid} {e}"[:200])
                errors += 1
                continue

            # 首次运行：只报最近一次，并把当前历史记入 seen，避免回放刷告警
            first_run = not seen_set
            if first_run and ops:
                for o in ops[:-1]:
                    seen_set.add(int(o.get("id") or 0))
                ops = ops[-1:]

            for op in ops:
                op_id = int(op.get("id") or 0)
                st, message, detail = map_status(op)
                content_sig = f"{st}:{op.get('error_code')}:{op.get('finished_time')}"
                if op_id in seen_set:
                    prev_sig = (slot.get("last_sig") or {}).get(str(op_id))
                    # 已见且状态未变（或首跑基线无签名）→ 跳过；状态变了才重报
                    if prev_sig is None or prev_sig == content_sig:
                        continue
                if not detail and int(op.get("error_code") or 0):
                    detail = extract_log_reason(name, op_id, int(op.get("error_code") or 0), log_path)
                elif st == "failure" and not detail:
                    detail = extract_log_reason(name, op_id, int(op.get("error_code") or 0), log_path)

                ts = op.get("start_time") or op.get("finished_time") or int(time.time())
                body = {
                    "event_key": event_key,
                    "status": st,
                    "severity": "critical" if st == "failure" else "warning",
                    "message": f"{name}: {message}"[:500],
                    "detail": detail[:2000],
                    "run_id": f"fnbk:{tid}:{op_id}",
                    "timestamp": time.strftime(
                        "%Y-%m-%dT%H:%M:%S+08:00", time.localtime(int(ts))
                    ),
                }
                ok, resp = report(cfg, event_key, body)
                log(f"report {event_key} {body['run_id']} -> {st} ok={ok} {resp}")
                if ok:
                    reported += 1
                    seen_set.add(op_id)
                    sigs = slot.get("last_sig") or {}
                    sigs[str(op_id)] = content_sig
                    # 只保留最近 80 个签名，防止状态文件膨胀
                    if len(sigs) > 80:
                        keys = sorted(sigs.keys(), key=lambda k: int(k))
                        for k in keys[:-80]:
                            sigs.pop(k, None)
                    ckpt[str(tid)] = {
                        "last_op_id": op_id,
                        "last_status": st,
                        "seen_op_ids": sorted(seen_set)[-80:],
                        "last_sig": sigs,
                    }
                    slot = ckpt[str(tid)]
                else:
                    errors += 1

    finally:
        try:
            conn.close()
        except Exception:
            pass

    state["last_run_at"] = time.time()
    state["last_reported"] = reported
    state["last_errors"] = errors
    try:
        save_json(state_path, state)
    except Exception as e:
        log(f"save state failed: {e}")

    log(f"done reported={reported} errors={errors}")
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
