"""Current public documentation and release inputs; no installation or network."""
from __future__ import annotations

import re
import subprocess
import tomllib
import unittest
from pathlib import Path
from urllib.parse import unquote, urlsplit

from ayana import VERSION


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_DOCS = {
    "docs/README.md", "docs/INSTALL.md", "docs/CONFIGURATION.md",
    "docs/OPERATIONS.md", "docs/mcp-operations.md", "docs/TESTING.md",
}
RETIRED_PUBLIC_TOOLS = {
    "deploy/INSTALL.md", "deploy/MIGRATION-0.3.0.md",
    "scripts/build_release_073.py", "scripts/verify_agent_authority.py",
    "scripts/verify_native_tui.py", "scripts/verify_native_vt.py",
    "scripts/native_vt_client.cjs", ".mimocode/agent/ops.md",
}


def public_paths() -> set[str]:
    """Use Git visibility in a checkout, keeping ignored user evidence outside QA.

    A release archive has no Git metadata, so check its actual packaged files.
    Deleted working files are excluded; newly written public guides are included.
    """
    try:
        top = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "--show-toplevel"],
            capture_output=True, check=True, timeout=5,
        )
        if Path(top.stdout.decode("utf-8").strip()).resolve() != ROOT.resolve():
            raise FileNotFoundError("release directory is not the Git checkout root")
        result = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            capture_output=True, check=True, timeout=5,
        )
        paths = set(result.stdout.decode("utf-8").split("\0")) - {""}
        return {name for name in paths if (ROOT / name).is_file()}
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return {path.relative_to(ROOT).as_posix() for path in ROOT.rglob("*")
                if path.is_file() and not set(path.relative_to(ROOT).parts) & {".git", ".venv", "__pycache__"}}


class PublicDocumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.paths = public_paths()

    def public_markdown(self):
        return sorted(PUBLIC_DOCS | {"README.md", "CHANGELOG.md"} | {
            name for name in self.paths if name.startswith("knowledge/") and name.endswith(".md")
        })

    def test_docs_tree_contains_only_current_public_guides(self):
        actual = {name for name in self.paths if name.startswith("docs/")}
        self.assertEqual(actual, PUBLIC_DOCS)

    def test_local_markdown_links_resolve_inside_the_public_tree(self):
        for name in self.public_markdown():
            path = ROOT / name
            with self.subTest(document=name):
                self.assertTrue(path.is_file(), name)
                text = path.read_text(encoding="utf-8-sig")
                # Code examples may contain Markdown syntax that is not a link.
                text = re.sub(r"^\s*(`{3,}|~{3,}).*?^\s*\1\s*$", "", text,
                              flags=re.MULTILINE | re.DOTALL)
                for raw in re.findall(r"\[[^\]]*\]\(([^)]+)\)", text):
                    raw = raw.strip()
                    target = raw[1:raw.index(">")] if raw.startswith("<") and ">" in raw else raw.split()[0]
                    link = urlsplit(target)
                    if link.scheme or link.netloc or not link.path:
                        continue
                    destination = (path.parent / unquote(link.path)).resolve()
                    self.assertTrue(destination.is_relative_to(ROOT), f"{name}: {target}")
                    self.assertTrue(destination.exists(), f"{name}: missing {target}")
                    if destination.is_file():
                        self.assertIn(destination.relative_to(ROOT).as_posix(), self.paths,
                                      f"{name}: link points to an ignored/local-only file: {target}")

    def test_public_text_does_not_advertise_deleted_runtime_architecture(self):
        removed_module = re.compile(
            r"(?<![\w.-])(?:ayana[/.])?(?:agent|ai_providers|approval|assist|autonomy|controlled|council|legacy_history|policy)\.py\b"
        )
        old_claims = (
            "三省制自治 Agent", "中书省 Planner", "门下省双委员", "执行零自由度",
            "自动处置须走 Policy 与审批", "动手只能命中能力目录 / runbook 固定动作",
        )
        for name in self.public_markdown():
            with self.subTest(document=name):
                text = (ROOT / name).read_text(encoding="utf-8-sig")
                self.assertIsNone(removed_module.search(text), name)
                for claim in old_claims:
                    self.assertFalse(claim in text, f"{name}: obsolete claim: {claim}")
                self.assertIsNone(re.search(r"[A-Za-z]:[\\/]Users[\\/]", text), name)

    def test_install_guides_and_scripts_do_not_require_a_missing_dependency_file(self):
        names = PUBLIC_DOCS | {"README.md"} | {
            name for name in self.paths if name.startswith("deploy/") and name.endswith(".sh")
        }
        for name in sorted(names):
            with self.subTest(file=name):
                text = (ROOT / name).read_text(encoding="utf-8-sig")
                self.assertFalse("requirements.txt" in text, f"{name}: missing dependency-file reference")
                self.assertIsNone(re.search(r"(?:--branch\s+|origin/)speed-supreme\b", text), name)
        self.assertTrue((ROOT / "pyproject.toml").is_file())

    def test_public_release_inputs_exclude_retired_tools_and_private_artifacts(self):
        self.assertFalse(self.paths & RETIRED_PUBLIC_TOOLS, sorted(self.paths & RETIRED_PUBLIC_TOOLS))
        for name in self.paths:
            with self.subTest(file=name):
                self.assertFalse(name.startswith((".test-tmp/", "outputs/retired-export/", "docs/reviews/")))
                self.assertNotRegex(name, r"\.(?:db(?:-wal|-shm)?|sqlite3?|log|pem|p12|pfx|tar(?:\.gz)?)$", name)

    def test_release_manifest_includes_the_current_guides_without_old_public_material(self):
        from scripts.release_manifest import release_files

        selected = {path.relative_to(ROOT).as_posix() for path in release_files(ROOT)}
        self.assertEqual({name for name in selected if name.startswith("docs/")}, PUBLIC_DOCS)
        self.assertFalse(selected & RETIRED_PUBLIC_TOOLS, sorted(selected & RETIRED_PUBLIC_TOOLS))
        for name in selected:
            self.assertIn(name, self.paths, f"release selects an ignored/local-only file: {name}")

    def test_current_version_matches_package_and_public_intro(self):
        package = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8-sig"))
        self.assertEqual(package["project"]["version"], VERSION)
        self.assertIn("v" + VERSION, (ROOT / "README.md").read_text(encoding="utf-8-sig"))


if __name__ == "__main__":
    unittest.main()
