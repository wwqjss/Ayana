"""Wipe Ayana on YOMI and reinstall via KANATA Next Terminal (LF-safe)."""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(r"C:\Users\karory\Git\Ayana")
PKG = ROOT / "ayana-v073-test-install.tar.gz"
REMOTE_DIR = "/root/ayana-deploy"
SSH = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20", "-l", "KANATA-NEXTTERMINAL:yomi", "kanata-nt"]


def run(cmd: list[str], timeout: int = 300) -> tuple[int, str, str]:
    print("\n$", " ".join(cmd))
    p = subprocess.run(cmd, capture_output=True, timeout=timeout)
    out = (p.stdout or b"").decode("utf-8", "replace")
    err = (p.stderr or b"").decode("utf-8", "replace")
    if out.strip():
        print(out.rstrip()[:8000])
    if err.strip():
        print("STDERR:", err.rstrip()[:3000])
    print(f"[exit {p.returncode}]")
    return p.returncode, out, err


def remote(script: str, timeout: int = 900) -> tuple[int, str, str]:
    # 强制 LF，避免 Windows CRLF 让 bash 报 $'\r'
    script_lf = script.replace("\r\n", "\n").replace("\r", "\n")
    if not script_lf.endswith("\n"):
        script_lf += "\n"
    print("\n$ ssh kanata-nt:yomi bash -s  #", script_lf.splitlines()[0][:80])
    p = subprocess.run(
        SSH + ["bash", "-s"],
        input=script_lf.encode("utf-8"),
        capture_output=True,
        timeout=timeout,
    )
    out = (p.stdout or b"").decode("utf-8", "replace")
    err = (p.stderr or b"").decode("utf-8", "replace")
    if out.strip():
        print(out.rstrip()[:10000])
    if err.strip():
        print("STDERR:", err.rstrip()[:3000])
    print(f"[exit {p.returncode}]")
    return p.returncode, out, err


def upload() -> bool:
    """scp 经 NT；失败则用 ssh + base64 管道。"""
    remote_name = f"{REMOTE_DIR}/{PKG.name}"
    code, _, err = run(
        [
            "scp",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=20",
            "-o",
            "User=KANATA-NEXTTERMINAL:yomi",
            str(PKG),
            f"kanata-nt:{remote_name}",
        ],
        timeout=300,
    )
    if code == 0:
        return True
    print("scp failed, fallback base64 over ssh")
    b64 = subprocess.run(
        ["certutil", "-encode", "-f", str(PKG), str(PKG) + ".b64"],
        capture_output=True,
        timeout=120,
    )
    if b64.returncode != 0:
        # certutil wraps with BEGIN/END lines
        print("certutil encode failed")
        return False
    raw = Path(str(PKG) + ".b64").read_text(encoding="ascii", errors="ignore")
    # strip certutil headers/blank lines
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip() and "BEGIN" not in ln and "END" not in ln]
    payload = "".join(lines)
    Path(str(PKG) + ".b64").unlink(missing_ok=True)
    code2, _, _ = remote(
        f"mkdir -p {REMOTE_DIR} && python3 -c \"import base64,sys; open('{remote_name}','wb').write(base64.b64decode(sys.stdin.read()))\"",
        timeout=600,
    )
    # feed via separate stdin: reopen approach — use ssh directly
    p = subprocess.run(
        SSH
        + [
            "python3",
            "-c",
            f"import base64,sys; open('{remote_name}','wb').write(base64.b64decode(sys.stdin.buffer.read()))",
        ],
        input=payload.encode("ascii"),
        capture_output=True,
        timeout=600,
    )
    print("b64 upload exit", p.returncode, (p.stderr or b"")[:200])
    return p.returncode == 0


def main() -> int:
    if not PKG.exists():
        print("package missing", PKG)
        return 1
    print(f"package: {PKG} ({PKG.stat().st_size} bytes)")

    remote("hostname; whoami; systemctl is-active ayana 2>&1 || true; ls /opt/ayana 2>&1 | head -5")

    ts = time.strftime("%Y%m%d-%H%M%S")
    remote(
        f"mkdir -p /root/ayana-wipe-backup; "
        f"tar -C / -czf /root/ayana-wipe-backup/ayana-{ts}.tar.gz opt/ayana etc/ayana var/lib/ayana 2>/dev/null || true; "
        f"ls -lh /root/ayana-wipe-backup/ | tail -3",
        timeout=300,
    )

    remote(
        """
set -e
systemctl stop ayana.service 2>/dev/null || true
systemctl disable ayana.service 2>/dev/null || true
rm -rf /opt/ayana /var/lib/ayana /etc/ayana
rm -f /etc/systemd/system/ayana.service
systemctl daemon-reload
id ayana >/dev/null 2>&1 && userdel -r ayana 2>/dev/null || true
echo WIPE_OK
ls -ld /opt/ayana /var/lib/ayana /etc/ayana 2>&1 || true
"""
    )

    remote(f"mkdir -p {REMOTE_DIR}")
    if not upload():
        print("UPLOAD_FAILED")
        return 2
    remote(f"ls -lh {REMOTE_DIR}/{PKG.name}")

    remote(
        f"""
set -e
rm -rf {REMOTE_DIR}/src
mkdir -p {REMOTE_DIR}/src
tar -xzf {REMOTE_DIR}/{PKG.name} -C {REMOTE_DIR}/src
ls {REMOTE_DIR}/src | head -25
test -f {REMOTE_DIR}/src/deploy/install.sh
test -f {REMOTE_DIR}/src/ayana/main.py
bash {REMOTE_DIR}/src/deploy/install.sh --system --prefix /opt/ayana --data /var/lib/ayana --conf-dir /etc/ayana
""",
        timeout=900,
    )

    remote(
        """
echo '--- service ---'
systemctl is-active ayana || true
systemctl status ayana --no-pager 2>&1 | head -20 || true
echo '--- data ---'
ls -la /var/lib/ayana/ 2>&1 | head -25
echo '--- setup token ---'
if [ -f /var/lib/ayana/setup-admin.token ]; then
  echo SETUP_TOKEN_FILE=present
  echo TOKEN_PATH=/var/lib/ayana/setup-admin.token
else
  echo SETUP_TOKEN_FILE=missing
fi
echo '--- journal ---'
journalctl -u ayana -n 40 --no-pager 2>&1 | tail -40
echo '--- http ---'
curl -sS -m 3 http://127.0.0.1:6200/health || echo health_fail
echo
curl -sS -m 3 http://127.0.0.1:6200/api/setup/status || echo setup_status_fail
""",
        timeout=180,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
