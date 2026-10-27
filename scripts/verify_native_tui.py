"""Explicit, real read-only native TUI smoke on an already running runtime.

Run as the service user with --execute-readonly. Creates an isolated manual
session; uses real PTY/WebSocket input, not a browser or a fake model. Saves
private evidence and retains native history. Never changes production switches.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
from pathlib import Path
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


async def verify(config_path: str, proxy_port: int) -> dict:
    from aiohttp import ClientSession, WSMsgType, web
    from ayana.agent_tui import AgentTuiManager
    from ayana.config import load_config
    from ayana.db import Database
    from ayana.duty_session import DutySessionManager
    from ayana.mimo_admin import MimoAdmin
    from ayana.mimo_runtime_config import runtime_paths, verified_runtime
    from ayana.mimo_serve import MimoServeClient, normalize_receipt_status

    cfg = load_config(config_path)
    paths = runtime_paths(cfg)
    db = Database(cfg["db_path"])
    duty = DutySessionManager(db)
    binary = str(cfg.get("mimo_bin") or "/var/lib/ayana/.mimocode/bin/mimo")
    admin = MimoAdmin(mimo_bin=binary, workdir=paths["workdir"], config_dir=str(cfg.get("mimo_config_dir") or ""))
    native = MimoServeClient(password=str(cfg.get("mimo_serve_password") or cfg.get("webhook_token") or ""),
        directory=paths["workdir"], base_url="http://127.0.0.1:" + str(cfg.get("mimo_serve_port") or 6290))
    manager = AgentTuiManager(db, lambda: native, mimo_bin=binary, workdir=paths["workdir"], home=paths["home"],
        state_dir=paths["state_dir"] + "/tui", proxy_port=proxy_port,
        runtime_resolver=lambda: verified_runtime(cfg, db, admin), redactor_factory=admin.redactor)
    await manager.start()
    sid = duty.create(origin="manual", title="原生 TUI 实时连接验收", created_by="native-smoke")["session_id"]
    rid = (await native.create_session(title="原生 TUI 实时连接验收"))["session_id"]
    db.execute("UPDATE duty_sessions SET remote_session_id=? WHERE id=?", (rid, sid))
    binding = await manager.ensure(sid, rid)
    route = "/" + uuid.uuid4().hex
    app = web.Application()

    async def attach(request):
        return await manager.websocket(request, sid, username="native-smoke", authorize=lambda: True)

    app.router.add_get(route, attach)
    runner = web.AppRunner(app, access_log=None, shutdown_timeout=2)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    url = "http://127.0.0.1:" + str(site._server.sockets[0].getsockname()[1]) + route
    readers = []
    completed = False
    evidence = {"sid": sid, "rid": rid, "binding": binding, "at": time.time()}

    async def screen():
        return (await asyncio.to_thread(manager._tmux, "capture-pane", "-p", "-t", binding["tmux_name"])).stdout

    async def connect(http):
        ws = await http.ws_connect(url)
        ready = asyncio.get_running_loop().create_future()

        async def consume():
            async for frame in ws:
                if frame.type == WSMsgType.TEXT:
                    data = json.loads(frame.data)
                    if data.get("type") == "ready" and not ready.done():
                        ready.set_result(data)

        readers.append(asyncio.create_task(consume()))
        return ws, await asyncio.wait_for(ready, 10)

    try:
        async with ClientSession() as http:
            ws, initial = await connect(http)
            # OpenTUI startup may take several seconds. A PTY ready frame or an
            # ANSI clear alone is never treated as proof of a rendered screen.
            for _ in range(60):
                first = await screen()
                if "输入消息" in first or "Type a message" in first:
                    break
                await asyncio.sleep(.5)
            else:
                raise RuntimeError("native_welcome_not_rendered")
            evidence["native_welcome_rendered"] = True
            manager.acquire_control(sid, "native-smoke", initial["connection_id"])
            marker = "NATIVE_FINAL_" + uuid.uuid4().hex[:10]
            text = "受控只读验收：调用 ayana_asset_list 和 ayana_incident_list，最后用一句中文汇总数量，并原样带上 " + marker + "。不创建或修改任何资源，不执行修复。"
            await ws.send_json({"type": "input", "data": "\x1b[200~" + text + "\x1b[201~"})
            await asyncio.sleep(2)
            await ws.send_json({"type": "input", "data": "\r"})
            for _ in range(150):
                row = db.query_one("SELECT * FROM agent_runtime_receipts WHERE session_id=?", (sid,))
                if row:
                    break
                await asyncio.sleep(.1)
            else:
                raise RuntimeError("native_input_not_admitted")
            receipt = dict(row)
            evidence["status_at_disconnect"] = await native.session_status(rid)
            await ws.close()
            await asyncio.sleep(.4)
            ws, again = await connect(http)
            actual = (await manager.status(sid))["binding"]
            evidence["same_engine"] = actual["engine_pid"] == binding["engine_pid"] and actual["engine_started_at"] == binding["engine_started_at"]
            evidence["same_pane"] = actual["pane_pid"] == binding["pane_pid"] and actual["pane_started_at"] == binding["pane_started_at"]
            evidence["reconnect_observer"] = not again["control"]
            final = ""
            for _ in range(120):
                status = await native.receipt(rid, receipt["receipt_id"])
                messages = await native.messages(rid, limit=100)
                answers = [part.get("text", "") for message in messages if message.get("info", {}).get("role") == "assistant"
                    for part in message.get("parts", []) if part.get("type") == "text" and marker in part.get("text", "")]
                if normalize_receipt_status(status) == "completed" and answers:
                    final = answers[-1]
                    break
                await asyncio.sleep(1)
            if not final:
                raise RuntimeError("native_assistant_not_completed")
            await asyncio.sleep(1)
            rendered = await screen()
            tools = [part for message in messages for part in message.get("parts", []) if part.get("type") == "tool"]
            evidence.update(receipt=status, final=admin._redact(final),
                tools=[{"tool": part.get("tool"), "status": part.get("state", {}).get("status")} for part in tools],
                user_turns=sum(message.get("info", {}).get("role") == "user" for message in messages),
                native_result_rendered=marker in rendered and "ayana_asset_list" in rendered and "ayana_incident_list" in rendered)
            if not all(evidence[k] for k in ("same_engine", "same_pane", "native_result_rendered")) or evidence["user_turns"] != 1:
                raise RuntimeError("native_identity_or_render_assertion_failed")
            duty.finish_receipt(receipt["receipt_id"], "completed")
            duty.set_runtime_state(sid, "idle", receipt_id=receipt["receipt_id"], receipt_status="completed")
            await ws.close()
            duty.archive_session(sid, reason="native_acceptance")
            completed = True
    finally:
        evidence["passed"] = completed
        output = Path(paths["state_dir"]) / "native-scoped-probe.json"
        output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2))
        output.chmod(0o600)
        await runner.cleanup()
        await manager.stop()
        for task in readers:
            task.cancel()
        await asyncio.gather(*readers, return_exceptions=True)
        # Only remove this completed test's viewport. Never kill a model task.
        if completed:
            await asyncio.to_thread(manager._tmux, "kill-session", "-t", binding["tmux_name"])
        db.close()
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/ayana/config.json")
    parser.add_argument("--proxy-port", type=int, default=6292)
    parser.add_argument("--execute-readonly", action="store_true", required=True)
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() == 0:
        parser.error("Run on POSIX as the unprivileged Ayana service user")
    print(json.dumps(asyncio.run(verify(args.config, args.proxy_port)), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
