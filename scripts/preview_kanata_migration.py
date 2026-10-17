import subprocess
from pathlib import Path

root = Path(r"C:\Users\karory\Git\Ayana")
ssh = ["ssh", "-o", "BatchMode=yes", "-l", "KANATA-NEXTTERMINAL:kanata", "kanata-nt"]
for remote, local in [
    ("/opt/ayana/ayana/health.py", root / ".kanata-health.py"),
    ("/opt/ayana/ayana/runbook.py", root / ".kanata-runbook.py"),
    ("/etc/ayana/config.json", root / ".kanata-config.json"),
]:
    p = subprocess.run(ssh + ["cat " + remote], capture_output=True)
    local.write_bytes(p.stdout)
    print(local.name, "bytes", len(p.stdout), "nulls", p.stdout.count(b"\x00"))

import sys
sys.path.insert(0, str(root / "scripts"))
r = subprocess.run(
    [
        sys.executable,
        str(root / "scripts" / "migrate_monitor_config.py"),
        "--legacy-health",
        str(root / ".kanata-health.py"),
        "--legacy-runbook",
        str(root / ".kanata-runbook.py"),
        "--config",
        str(root / ".kanata-config.json"),
        "--dry-run",
    ],
    capture_output=True,
    text=True,
)
print(r.stdout)
print(r.stderr, file=sys.stderr)
print("dry-run exit", r.returncode)
r2 = subprocess.run(
    [
        sys.executable,
        str(root / "scripts" / "migrate_monitor_config.py"),
        "--legacy-health",
        str(root / ".kanata-health.py"),
        "--legacy-runbook",
        str(root / ".kanata-runbook.py"),
        "--config",
        str(root / ".kanata-config.json"),
        "--check",
    ],
    capture_output=True,
    text=True,
)
print(r2.stdout)
print(r2.stderr, file=sys.stderr)
print("check exit", r2.returncode)
