"""Opt-in native VT acceptance through real workbench JS and Web handlers.

Uses a private loopback test adapter for authentication, two independent gateway
instances, real MiMo serve, a fresh session, and a real xterm parser. It never
operates the user's browser. Requires Node, ws and an external @xterm/headless.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import secrets
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


async def run(config_path: str, headless_module: str, *, use_runtime_proxy: bool = False) -> dict:
    from aiohttp import web
    from ayana.agent_tui import AgentTuiManager
    from ayana.config import load_config
    from ayana.db import Database
    from ayana.duty_session import DutySessionManager
    from ayana.mimo_admin import MimoAdmin
    from ayana.mimo_runtime_config import runtime_paths, verified_runtime
    from ayana.mimo_serve import MimoServeClient
    from ayana.mimo_session import MimoServeSessionClient
    from ayana.session_bridge import SessionBridge
    from ayana.web import WebApp

    cfg = load_config(config_path)
    paths = runtime_paths(cfg)
    db = Database(cfg["db_path"])
    duty = DutySessionManager(db)
    admin = MimoAdmin(mimo_bin=str(cfg.get("mimo_bin") or (cfg.get("auto_investigate") or {}).get("mimo_bin") or "mimo"), workdir=paths["workdir"])
    runtime = lambda: verified_runtime(cfg, db, admin)
    client = MimoServeClient(base_url="http://127.0.0.1:" + str(cfg.get("mimo_serve_port") or 6290),
        password=str(cfg.get("mimo_serve_password") or cfg.get("webhook_token") or ""), directory=paths["workdir"],
        runtime_resolver=lambda: admin.runtime_configuration(db))
    arguments = dict(mimo_bin=admin._bin(), workdir=paths["workdir"], home=paths["home"],
        state_dir=paths["state_dir"] + "/tui", proxy_port=int(cfg.get("agent_tui_proxy_port") or 6291) if use_runtime_proxy else 6292, runtime_resolver=runtime,
        redactor_factory=admin.redactor)
    proxy = AgentTuiManager(db, lambda: client, **arguments)
    browser_gateway = AgentTuiManager(db, lambda: client, **arguments)
    if not use_runtime_proxy:
        await proxy.start()

    class ExistingServe:
        async def ensure_running(self):
            admin.runtime_configuration(db)
            if not (await client.health()).get("ok"):
                raise RuntimeError("native_runtime_unavailable")
        def client(self):
            return client

    adapter = MimoServeSessionClient(mimo_bin=admin._bin(), cwd=paths["workdir"], runtime_resolver=runtime,
        serve_url=client.base_url, serve_password=client.password, readonly_env=True)
    bridge = SessionBridge(db, mimo=adapter, duty=duty)
    actor = "vt-probe-" + secrets.token_hex(5)
    user = {"username": actor, "is_admin": True}
    handler = WebApp.__new__(WebApp)
    handler.db, handler.cfg, handler.duty = db, cfg, duty
    handler.session_bridge, handler.mimo_serve, handler.agent_tui = bridge, ExistingServe(), browser_gateway
    # Authentication is replaced only in this private test adapter. Every
    # business handler, native prompt, lease and PTY path remains production code.
    handler._require_admin = handler._require_auth = handler._session = lambda request: user
    handler._check_csrf = lambda *args: None
    handler._visible_asset_ids = lambda who: set()
    key = secrets.token_urlsafe(32)
    owned = set()

    @web.middleware
    async def private(request, handler):
        if request.headers.get("X-Probe-Key") != key:
            raise web.HTTPForbidden()
        sid = request.match_info.get("sid") or request.query.get("session_id") or request.query.get("sid")
        if sid and sid not in owned:
            raise web.HTTPNotFound()
        return await handler(request)

    async def create(request):
        response = await handler.api_agent_session_create(request)
        data = json.loads(response.text)
        if data.get("session_id"):
            owned.add(data["session_id"])
        return response

    async def sessions(request):
        response = await handler.api_agent_sessions(request)
        data = json.loads(response.text)
        data["sessions"] = [row for row in data.get("sessions", []) if row["id"] in owned]
        return web.json_response(data)

    async def state(request):
        sid = request.query["sid"]
        current = duty.get(sid)
        rid = str((current or {}).get("remote_session_id") or "")
        messages = await client.messages(rid, limit=100) if rid else []
        receipts = [dict(row) for row in db.query("SELECT receipt_id,status FROM agent_runtime_receipts WHERE session_id=?", (sid,))]
        return web.json_response({"binding": (await browser_gateway.status(sid)).get("binding"),
            "receipts": receipts, "user_messages": sum(row.get("info", {}).get("role") == "user" for row in messages),
            "assistant_texts": [part.get("text", "") for row in messages if row.get("info", {}).get("role") == "assistant"
                for part in row.get("parts", []) if part.get("type") == "text"]})

    app = web.Application(middlewares=[private])
    app.router.add_get("/api/agent/sessions", sessions)
    app.router.add_post("/api/agent/sessions", create)
    app.router.add_get("/api/agent/sessions/{sid}", handler.api_agent_session_detail)
    app.router.add_post("/api/agent/sessions/{sid}/terminal", handler.api_agent_terminal_prepare)
    app.router.add_get("/api/agent/sessions/{sid}/terminal", handler.api_agent_terminal_status)
    app.router.add_post("/api/agent/sessions/{sid}/terminal/control", handler.api_agent_terminal_control)
    app.router.add_get("/ws/agent-terminal", handler.ws_agent_terminal)
    app.router.add_get("/probe/state", state)
    runner = web.AppRunner(app, access_log=None, shutdown_timeout=2)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    output = Path(paths["state_dir"]) / "native-vt-cold-proof.json"
    try:
        env = {**os.environ, "AYANA_VT_BASE": f"http://127.0.0.1:{port}", "AYANA_VT_KEY": key,
            "AYANA_HEADLESS_MODULE": headless_module}
        process = await asyncio.create_subprocess_exec("node", str(Path(__file__).with_name("native_vt_client.cjs")),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env)
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=150)
        except asyncio.TimeoutError:
            process.terminate()
            await process.wait()
            raise RuntimeError("native_vt_probe_timeout") from None
        if process.returncode:
            print(admin._redact(stdout.decode(errors="replace")[-6000:]), file=sys.stderr)
            print(admin._redact(stderr.decode(errors="replace")[-5000:]), file=sys.stderr)
            raise RuntimeError("native_vt_probe_failed")
        evidence = json.loads(stdout)
        evidence.update(at=time.time(), actor=actor, private_auth_adapter=True, production_runtime_proxy=use_runtime_proxy)
        output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2))
        output.chmod(0o600)
        return evidence
    finally:
        await runner.cleanup()
        await proxy.stop()
        for sid in owned:
            # Keep all history. Only completed isolated viewports are removed;
            # uncertain or running model work is never stopped by cleanup.
            result = duty.archive_session(sid, reason="native_vt_probe")
            if result.get("ok"):
                binding = browser_gateway._binding(sid)
                if binding and binding.get("tmux_name"):
                    await asyncio.to_thread(browser_gateway._tmux, "kill-session", "-t", binding["tmux_name"])
        db.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/ayana/config.json")
    parser.add_argument("--headless-module", required=True)
    parser.add_argument("--execute-readonly", action="store_true", required=True)
    parser.add_argument("--use-runtime-proxy", action="store_true", help="Use the deployed runtime proxy rather than an isolated candidate proxy")
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() == 0:
        parser.error("Run as the unprivileged Ayana service account")
    print(json.dumps(asyncio.run(run(args.config, args.headless_module, use_runtime_proxy=args.use_runtime_proxy)), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
