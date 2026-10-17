import subprocess
import sys
from pathlib import Path

root = Path(r"C:\Users\karory\Git\Ayana")
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
)
out = r.stdout.decode("utf-8", "replace")
if "--- payload ---" in out:
    payload = out.split("--- payload ---", 1)[1]
    (root / "docs" / "kanata-migration-preview.json").write_text(payload, encoding="utf-8")
    print("saved preview payload bytes", len(payload))
print(out)
for name in (".kanata-health.py", ".kanata-runbook.py", ".kanata-config.json"):
    p = root / name
    if p.exists():
        p.unlink()
        print("removed", name)
