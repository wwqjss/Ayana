"""Independent lifetime owner for the native MiMo server and tmux process tree."""
from __future__ import annotations
import asyncio
import logging
import os
from pathlib import Path
import signal
import sys

log = logging.getLogger("ayana.agent_runtime")


def runtime_is_quiescent(statuses: object, *, pending_receipts: bool, running_jobs: bool) -> bool:
    """Only explicit idle native lanes and settled Ayana owners allow rotation."""
    return (isinstance(statuses, dict) and not pending_receipts and not running_jobs
            and all(isinstance(value, dict) and value.get("type") == "idle"
                    for value in statuses.values()))


async def _check_tmux_owner(tui) -> None:
    """Never adopt panes from a Web/administrator process cgroup."""
    result = await asyncio.to_thread(tui._tmux, "display-message", "-p", "#{pid}")
    if result.returncode:
        return
    try:
        pid = int(result.stdout.strip())
        owner = Path(f"/proc/{pid}/cgroup").read_text()
        current = Path("/proc/self/cgroup").read_text()
        if pid <= 0 or owner != current:
            raise ValueError()
    except (OSError, ValueError):
        raise RuntimeError("tmux_runtime_owner_mismatch") from None

async def run(config_path: str) -> None:
    from .config import load_config
    from .db import Database
    from .mimo_admin import MimoAdmin
    from .mimo_runtime_config import runtime_paths, verified_runtime
    from .mimo_serve import MimoServeManager, MimoServeClient
    from .agent_tui import AgentTuiManager
    cfg = load_config(config_path)
    paths = runtime_paths(cfg)
    if os.name != "posix":
        raise RuntimeError("native_runtime_requires_posix")
    for name in ("home", "workdir", "state_dir"):
        path = Path(paths[name])
        if path.is_symlink(): raise RuntimeError("unsafe_runtime_path")
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.umask(0o077)
    os.environ.pop("MIMOCODE_HOME", None)
    os.environ.update(HOME=paths["home"], XDG_CONFIG_HOME=str(Path(paths["home"])/".config"),
                      XDG_DATA_HOME=str(Path(paths["home"])/".local/share"), XDG_CACHE_HOME=str(Path(paths["home"])/".cache"))
    dbpath = Path(cfg["db_path"])
    if not dbpath.is_absolute(): dbpath = Path(cfg["base_dir"]) / dbpath
    db = Database(dbpath)
    binary = str(cfg.get("mimo_bin") or (cfg.get("auto_investigate") or {}).get("mimo_bin") or Path(paths["home"])/".mimocode/bin/mimo")
    admin = MimoAdmin(mimo_bin=binary, workdir=paths["workdir"])
    resolver = lambda: verified_runtime(cfg, db, admin)
    password = str(cfg.get("mimo_serve_password") or cfg.get("webhook_token") or "")
    manager = MimoServeManager(mimo_bin=binary, workdir=paths["workdir"], home=paths["home"],
                              port=int(cfg.get("mimo_serve_port") or 6290), username="mimocode", password=password,
                              runtime_resolver=resolver, runtime_attestation_path=paths["attestation"])
    tui = AgentTuiManager(db, manager.client, mimo_bin=binary, workdir=paths["workdir"], home=paths["home"],
                          state_dir=str(Path(paths["state_dir"])/"tui"), runtime_resolver=manager.validate_runtime,
                          proxy_port=int(cfg.get("agent_tui_proxy_port") or 6291), redactor_factory=admin.redactor)
    # A persistent server must originate in this independent unit. A socket
    # left by the Web process requires an explicit drained deployment cutover.
    await _check_tmux_owner(tui)
    await tui.bootstrap_tmux()
    await _check_tmux_owner(tui)
    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT): asyncio.get_running_loop().add_signal_handler(sig, stop.set)
    last_error = ""
    try:
        if bool(cfg.get("agent_tui_enabled", False)):
            await tui.start()
        while not stop.is_set():
            try:
                await manager.ensure_running()
                last_error = ""
            except Exception as error:
                code = getattr(error, "code", type(error).__name__)
                if code == "runtime_changed" and manager._proc is not None:
                    # Rotate credentials/config only between turns. A Web disconnect
                    # never reaches this process owner or requests cancellation.
                    probe = MimoServeClient(base_url=manager.base_url, username=manager.username, password=password, directory=paths["workdir"])
                    try:
                        statuses = await probe.session_status()
                        queued = db.query_one("SELECT 1 FROM agent_runtime_receipts WHERE status IN ('accepted','pending','queued','running','unknown')")
                        running = db.query_one("SELECT 1 FROM investigation_jobs WHERE status='running'")
                        if runtime_is_quiescent(statuses, pending_receipts=bool(queued), running_jobs=bool(running)):
                            await manager.stop()
                            await manager.start()
                            last_error = ""
                    except Exception:
                        pass
                if code != last_error:
                    log.warning("native runtime awaiting reconciliation: %s", code)
                    last_error = code
            try: await asyncio.wait_for(stop.wait(), timeout=2)
            except asyncio.TimeoutError: pass
    finally:
        await tui.stop()
        await manager.stop()
        db.close()

def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    asyncio.run(run(sys.argv[1] if len(sys.argv)>1 else "/etc/ayana/config.json"))

if __name__ == "__main__": main()
