"""Runtime entry points locate one installation without inventing a second DB."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ayana.config import default_config_path
from ayana.mimo_runtime_config import runtime_paths
from scripts.fnbk_collector import collector_paths


class InstalledPathTests(unittest.TestCase):
    def test_source_run_keeps_its_explicit_local_configuration(self):
        with tempfile.TemporaryDirectory() as temporary:
            cwd = Path(temporary)
            (cwd / "config.json").write_text("{}")
            with patch("ayana.config.Path.cwd", return_value=cwd):
                self.assertEqual(default_config_path(), str(cwd / "config.json"))

    def test_custom_unified_install_is_found_when_launched_elsewhere(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "custom-ayana"
            config = root / "config/config.json"
            config.parent.mkdir(parents=True)
            config.write_text("{}")
            elsewhere = Path(temporary) / "elsewhere"
            elsewhere.mkdir()
            with patch("ayana.config.__file__", str(root / "app/ayana/config.py")), \
                 patch("ayana.config.Path.cwd", return_value=elsewhere):
                self.assertEqual(default_config_path(), str(config))

    def test_absolute_database_directory_is_the_runtime_home_without_an_override(self):
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary) / "data"
            paths = runtime_paths({"db_path": str(data / "ayana.db")})
            self.assertEqual(paths["home"], str(data))
            self.assertEqual(paths["state_dir"], str(data / "agent-runtime"))

    def test_legacy_explicit_runtime_paths_are_preserved(self):
        paths = runtime_paths({"agent_runtime_home": "/var/lib/ayana", "mimo_workdir": "/var/lib/ayana/project"})
        self.assertEqual(paths["home"], "/var/lib/ayana")
        self.assertEqual(paths["workdir"], "/var/lib/ayana/project")

    def test_legacy_configuration_without_home_uses_its_existing_data_layout(self):
        paths = runtime_paths({"base_dir": "/etc/ayana"})
        self.assertEqual(paths["home"], str(Path("/var/lib/ayana")))

    def test_collector_config_and_state_follow_the_same_new_installation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, state = collector_paths(root, root / "old-config.json", root / "old-state.json")
            self.assertEqual(Path(config), root / "config/ext-collector.json")
            self.assertEqual(Path(state), root / "data/ext-collector-state.json")

    def test_existing_collector_uses_legacy_state_until_configuration_is_migrated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            legacy = root / "legacy.json"
            legacy.write_text("{}")
            old_state = root / "legacy-state.json"
            self.assertEqual(collector_paths(root, legacy, old_state), (str(legacy), str(old_state)))
            (root / "config").mkdir()
            (root / "config/ext-collector.json").write_text("{}")
            config, state = collector_paths(root, legacy, old_state)
            self.assertEqual(Path(config), root / "config/ext-collector.json")
            self.assertEqual(Path(state), root / "data/ext-collector-state.json")
