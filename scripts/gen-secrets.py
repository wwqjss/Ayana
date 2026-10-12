#!/usr/bin/env python3
"""生成 Ayana secrets.json（不覆盖已有文件）。"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path

KEYS = (
    "onewbot_token",
    "webhook_token",
    "web_auth_pepper",
    "totp_encrypt_key",
    "ssh_credential_key",
    "notify_channel_key",
)


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate Ayana secrets.json")
    ap.add_argument(
        "-o",
        "--output",
        default="secrets.json",
        help="output path (default: secrets.json)",
    )
    args = ap.parse_args()
    out = Path(args.output).expanduser().resolve()
    if out.exists():
        print(f"refusing to overwrite {out}", file=sys.stderr)
        return 1
    out.parent.mkdir(parents=True, exist_ok=True)
    data = {k: secrets.token_urlsafe(32) for k in KEYS}
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(str(out), flags, 0o600)
    try:
        os.write(fd, (json.dumps(data, indent=2) + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    try:
        os.chmod(out, 0o600)
    except OSError:
        pass
    print(f"wrote {out} (mode 600, {len(KEYS)} keys)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
