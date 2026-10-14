from pathlib import Path
import re

root = Path(r"C:\Users\karory\Git\Ayana")
skip_parts = {".git", ".venv", "__pycache__", "node_modules", ".pw-verify", "backups"}
patterns = {
    "public_ip": re.compile(r"\b(?:8\.137\.153\.233|8\.210\.54\.207|47\.91\.11\.4|172\.16\.0\.\d+)\b"),
    "personal_asset_binding": re.compile(r"\b(nerv|sora|kanata|yomi):[a-z0-9_-]+", re.I),
    "hysteria_frps": re.compile(r"hysteria|frps|harbor-core", re.I),
    "passwordish": re.compile(r"913119|password\s*[:=]\s*[\"'][^\"']{6,}", re.I),
}
exts = {".py", ".md", ".json", ".yml", ".yaml", ".sh", ".js", ".html", ".css", ".txt"}
hits = {k: [] for k in patterns}
for p in root.rglob("*"):
    if not p.is_file():
        continue
    if p.suffix.lower() not in exts and p.name != "config.example.json":
        continue
    if any(x in p.parts for x in skip_parts):
        continue
    if "tests" in p.parts:
        continue
    if p.name.startswith(("_rt_", "patch_", "fix_")):
        continue
    if p.name.startswith("deploy_yomi"):
        continue
    try:
        t = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        continue
    for k, rx in patterns.items():
        m = rx.search(t)
        if m:
            hits[k].append((str(p.relative_to(root)), m.group(0)[:50]))

for k, v in hits.items():
    print(f"== {k} ({len(v)}) ==")
    for item in v[:20]:
        print(" ", item[0], "->", item[1])
