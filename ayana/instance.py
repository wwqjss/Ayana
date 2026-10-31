"""单实例锁（P0-01）：flock，第二实例启动失败。"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any


def acquire_single_instance_lock(lock_path: str | Path, *, nofollow: bool = False) -> Any:
    path = Path(lock_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if nofollow:
        if path.is_symlink():
            raise RuntimeError("unsafe_instance_lock")
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise RuntimeError("unsafe_instance_lock")
        fh = os.fdopen(fd, "r+")
    else:
        fh = open(path, "a+")
    try:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        raise SystemExit(f"another Ayana instance holds lock: {path}")
    fh.seek(0)
    fh.truncate()
    fh.write(str(os.getpid()))
    fh.flush()
    return fh
