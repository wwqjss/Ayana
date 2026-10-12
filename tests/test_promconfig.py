"""Prometheus 可视化配置管理单测（不触网、不碰生产）。"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.db import Database
from ayana.ntsafe import NTResult
from ayana.promconfig import (
    ALERT_TEMPLATES,
    LocalConfigFS,
    PromConfigError,
    PromConfigService,
    SSHConfigFS,
    assert_safe_listen_address,
    build_rule_yaml_from_template,
    dump_simple_yaml,
    ensure_file_sd_job,
    ensure_rule_files_entry,
    parse_simple_yaml,
    safe_rel_path,
    build_prom_config_service,
)


SAMPLE_PROM_YML = """\
# 手写配置，必须保留
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - rules/host.yml

scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ['localhost:9090']

  - job_name: node
    scrape_interval: 30s
    static_configs:
      - targets: ['10.0.0.1:9100']
        labels:
          env: prod
"""


class FakeTransport:
    def __init__(self):
        self.probe_calls = []
        self.exec_calls = []
        self.probe_result = NTResult(ok=True, output="active", returncode=0)
        self.exec_result = NTResult(ok=True, output="ok", returncode=0)

    async def probe(self, asset_id, tokens, timeout=None):
        self.probe_calls.append((asset_id, list(tokens)))
        return self.probe_result

    async def exec(self, asset_id, tokens, timeout=None):
        self.exec_calls.append((asset_id, list(tokens)))
        return self.exec_result


class BinaryExporterTransport(FakeTransport):
    """No Docker or systemd unit; a fixed-path exporter binary is available."""

    def __init__(self, *, listening=False, user_exists=True, useradd_ok=True, ss_result=None):
        super().__init__()
        self.listening = listening
        self.user_exists = user_exists
        self.useradd_ok = useradd_ok
        self.ss_result = ss_result

    async def probe(self, asset_id, tokens, timeout=None):
        self.probe_calls.append((asset_id, list(tokens)))
        if tokens[0] == "docker":
            return NTResult(ok=False, output="docker unavailable", returncode=1)
        if tokens[:2] == ["test", "-x"]:
            return NTResult(ok=True, output="", returncode=0)
        if tokens[0].endswith("/node_exporter") and tokens[1:] == ["--version"]:
            return NTResult(ok=True, output="node_exporter, version 1.8.2", returncode=0)
        if tokens[:2] == ["id", "-u"]:
            return NTResult(ok=self.user_exists, output="1001" if self.user_exists else "no such user", returncode=0 if self.user_exists else 1)
        if tokens[:2] == ["systemctl", "is-active"]:
            return NTResult(ok=False, output="inactive", returncode=3)
        if tokens[:2] == ["systemctl", "show"]:
            return NTResult(ok=True, output="not-found\n", returncode=0)
        if tokens[0] == "ss":
            if self.ss_result is not None:
                return self.ss_result
            # Legacy ss output contains a header even when there is no listener.
            output = "LISTEN 0 4096 127.0.0.1:9100 0.0.0.0:*\n" if self.listening else ""
            if not self.listening and "-H" not in tokens:
                output = "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
            return NTResult(ok=True, output=output, returncode=0)
        return NTResult(ok=True, output="systemd 252", returncode=0)

    async def exec(self, asset_id, tokens, timeout=None):
        self.exec_calls.append((asset_id, list(tokens)))
        if tokens[0] == "docker":
            return NTResult(ok=False, output="docker unavailable", returncode=1)
        if tokens[0] == "useradd":
            return NTResult(ok=self.useradd_ok, output="" if self.useradd_ok else "useradd failed", returncode=0 if self.useradd_ok else 1)
        return self.exec_result


class DockerExporterTransport(BinaryExporterTransport):
    def __init__(self, *, container_running=None):
        super().__init__()
        self.container_running = container_running

    async def probe(self, asset_id, tokens, timeout=None):
        if tokens[0] == "docker":
            self.probe_calls.append((asset_id, list(tokens)))
            if tokens[1] == "version":
                return NTResult(ok=True, output="27.0.0", returncode=0)
            if self.container_running is not None:
                return NTResult(ok=True, output="true" if self.container_running else "false", returncode=0)
            return NTResult(ok=False, output="no such container", returncode=1)
        if tokens[:2] == ["test", "-x"]:
            self.probe_calls.append((asset_id, list(tokens)))
            return NTResult(ok=False, output="", returncode=1)
        return await super().probe(asset_id, tokens, timeout)

    async def exec(self, asset_id, tokens, timeout=None):
        if tokens[:2] == ["docker", "start"]:
            self.exec_calls.append((asset_id, list(tokens)))
            self.container_running = True
            self.listening = True
            return self.exec_result
        return await super().exec(asset_id, tokens, timeout)


class CorruptExporterTransport(BinaryExporterTransport):
    async def probe(self, asset_id, tokens, timeout=None):
        if tokens[:2] == ["test", "-x"]:
            self.probe_calls.append((asset_id, list(tokens)))
            exists = tokens[2] == "/usr/local/bin/node_exporter"
            return NTResult(ok=exists, output="", returncode=0 if exists else 1)
        if tokens == ["/usr/local/bin/node_exporter", "--version"]:
            self.probe_calls.append((asset_id, list(tokens)))
            return NTResult(ok=False, output="Segmentation fault", returncode=139)
        if tokens == ["sha256sum", "/tmp/node_exporter"]:
            self.probe_calls.append((asset_id, list(tokens)))
            return NTResult(ok=True, output="0" * 64 + "  /tmp/node_exporter\n", returncode=0)
        return await super().probe(asset_id, tokens, timeout)


class TestPathsAndYaml(unittest.TestCase):
    def test_safe_rel_path(self):
        self.assertEqual(safe_rel_path("prometheus.yml"), "prometheus.yml")
        self.assertEqual(safe_rel_path("rules/a.yml"), "rules/a.yml")
        with self.assertRaises(PromConfigError):
            safe_rel_path("../etc/passwd")
        with self.assertRaises(PromConfigError):
            safe_rel_path("/etc/prometheus.yml")
        with self.assertRaises(PromConfigError):
            safe_rel_path("a;rm -rf /")

    def test_listen_address(self):
        self.assertEqual(assert_safe_listen_address("127.0.0.1:9100"), "127.0.0.1:9100")
        self.assertEqual(assert_safe_listen_address("192.168.1.5:9100"), "192.168.1.5:9100")
        with self.assertRaises(PromConfigError):
            assert_safe_listen_address("0.0.0.0:9100")
        with self.assertRaises(PromConfigError):
            assert_safe_listen_address("8.8.8.8:9100")
        self.assertEqual(
            assert_safe_listen_address("0.0.0.0:9100", allow_non_private=True),
            "0.0.0.0:9100",
        )

    def test_parse_sample_config(self):
        data = parse_simple_yaml(SAMPLE_PROM_YML)
        self.assertIn("global", data)
        self.assertIn("scrape_configs", data)
        jobs = data["scrape_configs"]
        self.assertEqual(len(jobs), 2)
        self.assertEqual(jobs[0]["job_name"], "prometheus")
        self.assertEqual(jobs[1]["job_name"], "node")
        self.assertEqual(data["rule_files"], ["rules/host.yml"])

    def test_surgical_insert_preserves_comments(self):
        raw = SAMPLE_PROM_YML
        new_raw, changed = ensure_rule_files_entry(raw, "rules/ayana-node-alerts.yml")
        self.assertTrue(changed)
        self.assertIn("# 手写配置，必须保留", new_raw)
        self.assertIn("rules/ayana-node-alerts.yml", new_raw)
        # 幂等
        again, changed2 = ensure_rule_files_entry(new_raw, "rules/ayana-node-alerts.yml")
        self.assertFalse(changed2)
        self.assertEqual(again, new_raw)

    def test_surgical_insert_job(self):
        new_raw, changed = ensure_file_sd_job(SAMPLE_PROM_YML)
        self.assertTrue(changed)
        self.assertIn("job_name: ayana-nodes", new_raw)
        self.assertIn("file_sd/ayana-nodes.json", new_raw)
        self.assertIn("# 手写配置，必须保留", new_raw)
        # 不破坏原 job
        self.assertIn("job_name: node", new_raw)
        again, ch2 = ensure_file_sd_job(new_raw)
        self.assertFalse(ch2)

    def test_dump_and_parse_roundtrip_rule(self):
        tpl = ALERT_TEMPLATES[0]
        text, meta = build_rule_yaml_from_template(tpl, threshold=90, duration="10m", severity="critical")
        data = parse_simple_yaml(text)
        rules = data["groups"][0]["rules"]
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["alert"], "NodeCpuHigh")
        self.assertEqual(rules[0]["for"], "10m")
        self.assertEqual(rules[0]["labels"]["severity"], "critical")
        self.assertIn("90", rules[0]["expr"])


class FakeReloadProm:
    """伪 Prometheus：reload 总是 200。"""

    base_url = "http://127.0.0.1:9090"


class FailReloadProm:
    base_url = "http://127.0.0.1:9090"


class TestPromConfigService(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name) / "prom"
        self.fs = LocalConfigFS(self.base)
        self.db = Database(Path(self.tmp.name) / "t.db")
        self.svc = PromConfigService(
            self.db, self.fs, prom=None, transport=None, require_promtool=False
        )
        self.svc._try_reload = self._reload_ok
        # 写入样本配置
        asyncio.run(self.fs.write_text("prometheus.yml", SAMPLE_PROM_YML))

    async def _reload_ok(self):
        return {"ok": True, "status": 200}

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_read_config(self):
        data = asyncio.run(self.svc.read_config())
        self.assertTrue(data["ok"])
        self.assertIn("# 手写配置，必须保留", data["raw"])
        self.assertEqual(len(data["jobs"]), 2)
        self.assertIn("rules/host.yml", data["rule_files"])

    def test_add_target_creates_file_sd_and_links(self):
        r = asyncio.run(
            self.svc.add_target(address="10.0.0.5:9100", labels={"asset": "nerv"}, actor="tester")
        )
        self.assertTrue(r["ok"])
        # file_sd 存在
        raw = asyncio.run(self.fs.read_text("file_sd/ayana-nodes.json"))
        items = json.loads(raw)
        self.assertEqual(items[0]["targets"], ["10.0.0.5:9100"])
        self.assertEqual(items[0]["labels"]["asset"], "nerv")
        # prometheus.yml 被外科更新，原文注释仍在
        cfg = asyncio.run(self.fs.read_text("prometheus.yml"))
        self.assertIn("# 手写配置，必须保留", cfg)
        self.assertIn("job_name: ayana-nodes", cfg)
        self.assertIn("rules/ayana-node-alerts.yml", cfg)
        # 重复添加拒绝
        with self.assertRaises(PromConfigError):
            asyncio.run(self.svc.add_target(address="10.0.0.5:9100", actor="tester"))

    def test_update_and_delete_target(self):
        asyncio.run(self.svc.add_target(address="10.0.0.5:9100", labels={"asset": "nerv"}, actor="t"))
        asyncio.run(
            self.svc.update_target(address="10.0.0.5:9100", new_address="10.0.0.6:9100", labels={"asset": "sora"}, actor="t")
        )
        raw = asyncio.run(self.fs.read_text("file_sd/ayana-nodes.json"))
        items = json.loads(raw)
        self.assertEqual(items[0]["targets"], ["10.0.0.6:9100"])
        self.assertEqual(items[0]["labels"]["asset"], "sora")
        asyncio.run(self.svc.delete_target(address="10.0.0.6:9100", actor="t"))
        raw2 = asyncio.run(self.fs.read_text("file_sd/ayana-nodes.json"))
        self.assertEqual(json.loads(raw2), [])

    def test_bad_target_rejected(self):
        with self.assertRaises(PromConfigError):
            asyncio.run(self.svc.add_target(address="10.0.0.5; rm -rf /", actor="t"))
        with self.assertRaises(PromConfigError):
            asyncio.run(self.svc.add_target(address="10.0.0.5", actor="t"))

    def test_apply_template_and_update(self):
        r = asyncio.run(
            self.svc.apply_template(
                template_id="cpu_high", threshold=90, duration="10m", severity="critical", actor="t"
            )
        )
        self.assertTrue(r["ok"])
        rules = asyncio.run(self.svc.read_rules())
        managed = next(f for f in rules["files"] if f["path"] == "rules/ayana-node-alerts.yml")
        self.assertTrue(managed["editable"])
        alerts = [x["alert"] for g in managed["groups"] for x in g["rules"]]
        self.assertIn("NodeCpuHigh", alerts)
        # 更新阈值/停用
        asyncio.run(
            self.svc.update_rule(
                file_path="rules/ayana-node-alerts.yml",
                alert="NodeCpuHigh",
                enabled=False,
                actor="t",
            )
        )
        rules2 = asyncio.run(self.svc.read_rules())
        managed2 = next(f for f in rules2["files"] if f["path"] == "rules/ayana-node-alerts.yml")
        alerts2 = [x["alert"] for g in managed2["groups"] for x in g["rules"]]
        self.assertNotIn("NodeCpuHigh", alerts2)

    def test_refuse_write_unmanaged_rules(self):
        with self.assertRaises(PromConfigError):
            asyncio.run(
                self.svc.update_rule(
                    file_path="rules/host.yml", alert="Whatever", enabled=False, actor="t"
                )
            )

    def test_list_targets_mixed(self):
        asyncio.run(self.svc.add_target(address="10.0.0.5:9100", labels={"asset": "nerv"}, actor="t"))
        data = asyncio.run(self.svc.list_targets())
        self.assertTrue(data["ok"])
        self.assertEqual(len(data["file_sd_targets"]), 1)
        # 静态目标仍在
        static_addrs = [t["address"] for t in data["config_targets"] if t.get("address")]
        self.assertTrue(any("10.0.0.1:9100" in a for a in static_addrs))

    def test_backup_rollback(self):
        before = asyncio.run(self.fs.read_text("prometheus.yml"))
        asyncio.run(self.svc.add_target(address="10.0.0.5:9100", actor="t"))
        after = asyncio.run(self.fs.read_text("prometheus.yml"))
        self.assertNotEqual(before, after)
        r = asyncio.run(self.svc.rollback_last(path="prometheus.yml", actor="t"))
        self.assertTrue(r["ok"])
        restored = asyncio.run(self.fs.read_text("prometheus.yml"))
        self.assertEqual(restored, before)

    def test_audit_written(self):
        asyncio.run(self.svc.add_target(address="10.0.0.5:9100", actor="tester"))
        rows = self.db.query("SELECT entry, actor_id FROM audit_log WHERE entry LIKE 'promconfig_%'")
        self.assertTrue(any(r["entry"] == "promconfig_target_add" for r in rows))

    def test_overview(self):
        data = asyncio.run(self.svc.overview())
        self.assertIn("fs", data)
        self.assertTrue(data["files"]["prometheus.yml"]["exists"])


class TestNodeExporter(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name) / "prom"
        self.fs = LocalConfigFS(self.base)
        self.db = Database(Path(self.tmp.name) / "t.db")
        self.svc = PromConfigService(
            self.db, self.fs, prom=None, transport=None, require_promtool=False
        )
        self.svc._try_reload = self._reload_ok
        self.transport = FakeTransport()
        asyncio.run(self.fs.write_text("prometheus.yml", SAMPLE_PROM_YML))

    async def _reload_ok(self):
        return {"ok": True, "status": 200}

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_status(self):
        self.transport.probe_result = NTResult(ok=True, output="active", returncode=0)
        st = asyncio.run(self.svc.node_exporter_status("nerv", self.transport))
        self.assertEqual(st["asset_id"], "nerv")
        self.assertIn("active", st)

    def test_start_stop_fixed_tokens(self):
        r = asyncio.run(
            self.svc.node_exporter_control(
                asset_id="nerv", action="start", transport=self.transport, actor="t"
            )
        )
        self.assertTrue(r["ok"])
        self.assertEqual(self.transport.exec_calls[-1][1], ["systemctl", "start", "node_exporter"])
        asyncio.run(
            self.svc.node_exporter_control(
                asset_id="nerv", action="stop", transport=self.transport, actor="t"
            )
        )
        self.assertEqual(self.transport.exec_calls[-1][1], ["systemctl", "stop", "node_exporter"])

    def test_install_rejects_public_listen(self):
        with self.assertRaises(PromConfigError):
            asyncio.run(
                self.svc.node_exporter_control(
                    asset_id="nerv",
                    action="install",
                    transport=self.transport,
                    actor="t",
                    listen_address="0.0.0.0:9100",
                )
            )

    def _assert_unit_command_writes_atomically(self, transport, listen_address):
        commands = [tokens for _, tokens in transport.exec_calls if tokens[0] == "python3"]
        self.assertEqual(len(commands), 1)
        tokens = commands[0]
        self.assertEqual(tokens[:2], ["python3", "-c"])
        self.assertEqual(len(tokens), 3)
        self.assertFalse(any(c in tokens[2] for c in " \t\r\n;|&$`"))

        unit_path = "/etc/systemd/system/node_exporter.service"
        sandbox_path = Path(self.tmp.name) / "node_exporter.service"
        original_open = open
        original_replace = os.replace

        def sandbox_open(path, mode):
            self.assertEqual(path, unit_path + ".tmp")
            self.assertEqual(mode, "wb")
            return original_open(str(sandbox_path) + ".tmp", mode)

        def sandbox_replace(source, destination):
            self.assertEqual(source, unit_path + ".tmp")
            self.assertEqual(destination, unit_path)
            original_replace(str(sandbox_path) + ".tmp", sandbox_path)

        with patch("builtins.open", side_effect=sandbox_open), patch("os.replace", side_effect=sandbox_replace) as replace:
            exec(tokens[2], {})
            replace.assert_called_once()
        unit = sandbox_path.read_text(encoding="utf-8")
        self.assertIn("[Service]", unit)
        self.assertIn("ExecStart=/usr/local/bin/node_exporter", unit)
        self.assertIn("--web.listen-address=" + listen_address, unit)
        self.assertFalse(Path(str(sandbox_path) + ".tmp").exists())

    def test_control_binary_fallback_writes_valid_unit_command(self):
        transport = BinaryExporterTransport()
        result = asyncio.run(
            self.svc.node_exporter_control(
                asset_id="nerv", action="install", transport=transport,
                listen_address="127.0.0.1:9100", actor="t",
            )
        )
        self.assertTrue(result["ok"])
        self._assert_unit_command_writes_atomically(transport, "127.0.0.1:9100")
        self.assertEqual(transport.exec_calls[-3:][0][1], ["systemctl", "daemon-reload"])
        self.assertEqual(transport.exec_calls[-1][1], ["systemctl", "start", "node_exporter"])

    def test_binary_install_writes_valid_unit_command(self):
        transport = BinaryExporterTransport()
        result = asyncio.run(
            self.svc.install_exporter(
                asset_id="nerv", method="binary", transport=transport,
                listen_address="10.0.0.5:9100", allow_non_private=False, actor="t",
            )
        )
        self.assertTrue(result["ok"])
        self._assert_unit_command_writes_atomically(transport, "10.0.0.5:9100")

    def test_install_branches_keep_rejecting_unsafe_listen(self):
        for branch in ("control", "binary"):
            for listen in ("127.0.0.1:9100\n", "10.0.0.5:9100;id", "0.0.0.0:9100"):
                with self.subTest(branch=branch, listen=listen):
                    transport = BinaryExporterTransport()
                    with self.assertRaises(PromConfigError):
                        if branch == "control":
                            asyncio.run(self.svc.node_exporter_control(
                                asset_id="nerv", action="install", transport=transport,
                                listen_address=listen, allow_non_private=False, actor="t",
                            ))
                        else:
                            asyncio.run(self.svc.install_exporter(
                                asset_id="nerv", method="binary", transport=transport,
                                listen_address=listen, allow_non_private=False, actor="t",
                            ))
                    self.assertFalse(any(tokens[0] == "python3" for _, tokens in transport.exec_calls))

    def test_status_and_detection_ignore_ss_header_without_listener(self):
        transport = BinaryExporterTransport()
        status = asyncio.run(self.svc.node_exporter_status("nerv", transport))
        detect = asyncio.run(self.svc.detect_exporter("nerv", transport))
        self.assertFalse(status["port_9100"])
        self.assertFalse(detect["port_9100"])
        self.assertEqual(detect["recommend"], "binary")
        calls = [tokens for _, tokens in transport.probe_calls if tokens[0] == "ss"]
        self.assertTrue(calls)
        self.assertTrue(all(tokens == ["ss", "-H", "-lnt", "sport", "=", "9100"] for tokens in calls))

    def test_failed_status_probes_do_not_report_running(self):
        transport = FakeTransport()
        transport.probe_result = NTResult(ok=False, output="active", returncode=1)
        status = asyncio.run(self.svc.node_exporter_status("nerv", transport))
        detect = asyncio.run(self.svc.detect_exporter("nerv", transport))
        self.assertFalse(status["active"])
        self.assertFalse(status["installed"])
        self.assertFalse(status["port_9100"])
        self.assertFalse(status["running"])
        self.assertFalse(detect["port_9100"])
        self.assertFalse(detect["running"])

    def test_header_or_failed_ss_output_does_not_report_listener(self):
        results = (
            NTResult(ok=True, output="State Recv-Q Send-Q Local Address:Port Peer Address:Port\n", returncode=0),
            NTResult(ok=False, output="LISTEN 0 4096 127.0.0.1:9100 0.0.0.0:*\n", returncode=1),
        )
        for result in results:
            with self.subTest(output=result.output, ok=result.ok):
                transport = BinaryExporterTransport(ss_result=result)
                status = asyncio.run(self.svc.node_exporter_status("nerv", transport))
                detect = asyncio.run(self.svc.detect_exporter("nerv", transport))
                self.assertFalse(status["port_9100"])
                self.assertFalse(detect["port_9100"])
                self.assertEqual(detect["recommend"], "binary")

    def test_binary_install_creates_missing_service_user_before_unit(self):
        for branch in ("control", "binary"):
            with self.subTest(branch=branch):
                transport = BinaryExporterTransport(user_exists=False)
                if branch == "control":
                    result = asyncio.run(self.svc.node_exporter_control(
                        asset_id="nerv", action="install", transport=transport, actor="t",
                    ))
                else:
                    result = asyncio.run(self.svc.install_exporter(
                        asset_id="nerv", method="binary", transport=transport, actor="t",
                    ))
                self.assertTrue(result["ok"])
                commands = [tokens for _, tokens in transport.exec_calls]
                user_command = ["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "node_exporter"]
                self.assertIn(user_command, commands)
                self.assertLess(commands.index(user_command), next(i for i, tokens in enumerate(commands) if tokens[0] == "python3"))

    def test_service_user_creation_failure_stops_binary_install(self):
        for branch in ("control", "binary"):
            with self.subTest(branch=branch):
                transport = BinaryExporterTransport(user_exists=False, useradd_ok=False)
                with self.assertRaises(PromConfigError) as error:
                    if branch == "control":
                        asyncio.run(self.svc.node_exporter_control(
                            asset_id="nerv", action="install", transport=transport, actor="t",
                        ))
                    else:
                        asyncio.run(self.svc.install_exporter(
                            asset_id="nerv", method="binary", transport=transport, actor="t",
                        ))
                self.assertEqual(error.exception.code, "node_exporter_user_failed")
                self.assertFalse(any(tokens[0] in ("python3", "systemctl") for _, tokens in transport.exec_calls))

    def test_adopt_reuses_active_exporter_without_reinstall(self):
        status = {"active": True, "installed": True, "port_9100": True, "running": True, "mode": "systemd"}
        with patch.object(self.svc, "node_exporter_status", new=AsyncMock(return_value=status)), \
                patch.object(self.svc, "install_exporter", new=AsyncMock(side_effect=AssertionError("must not reinstall"))), \
                patch.object(self.svc, "_verify_scrape", new=AsyncMock(return_value={"has_metrics": True})):
            result = asyncio.run(self.svc.adopt_node(
                asset_id="nerv", address="10.0.0.5:9100", transport=self.transport, actor="t",
            ))
        self.assertTrue(result["ok"])
        self.assertFalse(self.transport.exec_calls)
        self.assertIn("register", [step["step"] for step in result["steps"]])

    def test_adopt_reuses_binary_listener_without_reinstall(self):
        transport = BinaryExporterTransport(listening=True)
        with patch.object(self.svc, "install_exporter", new=AsyncMock(side_effect=AssertionError("must not reinstall"))), \
                patch.object(self.svc, "_verify_scrape", new=AsyncMock(return_value={"has_metrics": True})):
            result = asyncio.run(self.svc.adopt_node(
                asset_id="nerv", address="10.0.0.5:9100", transport=transport, actor="t",
            ))
        self.assertTrue(result["ok"])
        self.assertFalse(transport.exec_calls)
        self.assertIn("register", [step["step"] for step in result["steps"]])

    def test_active_service_without_listener_is_not_detected_as_running(self):
        status = {"active": True, "installed": True, "port_9100": False, "running": False, "mode": "systemd"}
        transport = BinaryExporterTransport()
        with patch.object(self.svc, "node_exporter_status", new=AsyncMock(return_value=status)):
            result = asyncio.run(self.svc.detect_exporter("nerv", transport))
        self.assertFalse(result["running"])
        self.assertEqual(result["recommend"], "binary")

    def test_install_reuses_stopped_docker_container(self):
        transport = DockerExporterTransport(container_running=False)
        result = asyncio.run(self.svc.install_exporter(
            asset_id="nerv", method="auto", transport=transport, actor="t",
        ))
        self.assertTrue(result["ok"])
        self.assertEqual(transport.exec_calls, [("nerv", ["docker", "start", "node-exporter"])])
        self.assertTrue(result["status"]["running"])

    def test_docker_install_respects_non_private_listen_flag(self):
        transport = DockerExporterTransport()
        with self.assertRaises(PromConfigError):
            asyncio.run(self.svc.install_exporter(
                asset_id="nerv", method="docker", transport=transport, actor="t",
                listen_address="0.0.0.0:9100", allow_non_private=False,
            ))
        self.assertFalse(transport.exec_calls)

    def test_detect_does_not_select_corrupted_executable(self):
        transport = CorruptExporterTransport()
        with patch.object(self.svc, "package_binary", return_value="managed-package"):
            result = asyncio.run(self.svc.detect_exporter("nerv", transport))
        self.assertEqual(result["binary"], "")
        self.assertIn("/usr/local/bin/node_exporter", result["binary_error"])
        self.assertEqual(result["recommend"], "binary")
        self.assertEqual(result["reason"], "package_available")
        self.assertIn(("nerv", ["/usr/local/bin/node_exporter", "--version"]), transport.probe_calls)

    def test_package_checksum_mismatch_keeps_destination_untouched(self):
        transport = CorruptExporterTransport()
        transport.send_file = AsyncMock(return_value=NTResult(ok=True, output="sent", returncode=0))
        package = Path(self.tmp.name) / "node_exporter"
        package.write_bytes(b"complete replacement exporter package")
        with patch.object(self.svc, "package_binary", return_value=str(package)):
            with self.assertRaises(PromConfigError) as error:
                asyncio.run(self.svc.install_exporter(
                    asset_id="nerv", method="binary", transport=transport, actor="t",
                ))
        self.assertEqual(error.exception.code, "binary_checksum_failed")
        transport.send_file.assert_awaited_once_with("nerv", str(package), "/tmp/node_exporter", timeout=180)
        self.assertIn(("nerv", ["sha256sum", "/tmp/node_exporter"]), transport.probe_calls)
        self.assertFalse(any(tokens[0] in ("mv", "chmod", "chcon", "python3", "systemctl") for _, tokens in transport.exec_calls))

    def test_verify_scrape_waits_for_first_successful_scrape(self):
        address = "10.0.0.5:9100"
        pending = {"scrapeUrl": "http://" + address + "/metrics", "labels": {"instance": address}, "health": "unknown"}
        ready = dict(pending, health="up")
        prom = Mock()
        prom.targets = AsyncMock(side_effect=[[pending], [ready]])
        prom.query = AsyncMock(side_effect=[{"result": []}, {"result": [{"value": 1}]}])
        self.svc.prom = prom
        clock = [100.0]

        async def advance_clock(delay):
            clock[0] += delay

        with patch("ayana.promconfig.time.monotonic", side_effect=lambda: clock[0]), \
                patch("ayana.promconfig.asyncio.sleep", new=AsyncMock(side_effect=advance_clock)) as sleep:
            result = asyncio.run(self.svc._verify_scrape(address, asset_id="nerv", wait_sec=10.0))
        self.assertTrue(result["has_metrics"])
        self.assertEqual(result["health"], "up")
        self.assertEqual(result["samples"], 1)
        self.assertEqual(result["hint"], "")
        self.assertEqual(prom.targets.await_count, 2)
        self.assertEqual(prom.query.await_count, 2)
        sleep.assert_awaited_once_with(2.0)

    def test_verify_scrape_ready_target_returns_without_waiting(self):
        address = "10.0.0.5:9100"
        prom = Mock()
        prom.targets = AsyncMock(return_value=[{"labels": {"instance": address}, "health": "up"}])
        prom.query = AsyncMock(return_value={"result": [{"value": 1}]})
        self.svc.prom = prom
        with patch("ayana.promconfig.time.monotonic", return_value=100.0), \
                patch("ayana.promconfig.asyncio.sleep", new=AsyncMock()) as sleep:
            result = asyncio.run(self.svc._verify_scrape(address, wait_sec=30.0))
        self.assertTrue(result["has_metrics"])
        sleep.assert_not_awaited()
        prom.targets.assert_awaited_once()
        prom.query.assert_awaited_once_with('up{instance="10.0.0.5:9100"}')

    def test_verify_scrape_zero_wait_reports_no_metrics_after_one_attempt(self):
        address = "10.0.0.5:9100"
        prom = Mock()
        prom.targets = AsyncMock(return_value=[{"labels": {"instance": address}, "health": "unknown"}])
        prom.query = AsyncMock(return_value={"result": []})
        self.svc.prom = prom
        with patch("ayana.promconfig.time.monotonic", return_value=100.0), \
                patch("ayana.promconfig.asyncio.sleep", new=AsyncMock()) as sleep:
            result = asyncio.run(self.svc._verify_scrape(address, wait_sec=0.0))
        self.assertFalse(result["has_metrics"])
        self.assertTrue(result["found_target"])
        self.assertEqual(result["samples"], 0)
        self.assertTrue(result["hint"])
        sleep.assert_not_awaited()
        prom.targets.assert_awaited_once()
        prom.query.assert_awaited_once()

    def test_register_target(self):
        r = asyncio.run(
            self.svc.register_node_target(
                asset_id="nerv", address="10.0.0.5:9100", actor="t"
            )
        )
        self.assertTrue(r["ok"])
        items = json.loads(asyncio.run(self.fs.read_text("file_sd/ayana-nodes.json")))
        self.assertEqual(items[0]["labels"]["asset"], "nerv")
        self.assertEqual(items[0]["labels"]["job_type"], "node_exporter")


class TestSSHConfigFS(unittest.TestCase):
    def test_write_command_is_valid_python_and_preserves_content(self):
        transport = FakeTransport()
        fs = SSHConfigFS("nerv", transport, "/etc/prometheus")
        content = "# 中文配置\nvalue: '$value; `literal` & |'\n"
        asyncio.run(fs.write_text("file_sd/ayana-nodes.json", content))
        self.assertEqual(transport.exec_calls[0][1], ["mkdir", "-p", "/etc/prometheus/file_sd"])
        tokens = transport.exec_calls[1][1]
        self.assertEqual(tokens[:2], ["python3", "-c"])
        self.assertFalse(any(c in tokens[2] for c in " \t\r\n;|&$`"))
        remote = "/etc/prometheus/file_sd/ayana-nodes.json"
        original_open = open
        original_replace = os.replace
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "ayana-nodes.json"

            def sandbox_open(path, mode):
                self.assertRegex(path, "^" + remote.replace(".", r"\.") + r"\.tmp\.[0-9a-f]{8}$")
                self.assertEqual(mode, "wb")
                return original_open(str(output) + ".tmp", mode)

            def sandbox_replace(source, destination):
                self.assertTrue(source.startswith(remote + ".tmp."))
                self.assertEqual(destination, remote)
                original_replace(str(output) + ".tmp", output)

            with patch("builtins.open", side_effect=sandbox_open), patch("os.replace", side_effect=sandbox_replace) as replace:
                exec(tokens[2], {})
                replace.assert_called_once()
            self.assertEqual(output.read_text(encoding="utf-8"), content)
            self.assertFalse(Path(str(output) + ".tmp").exists())


class TestBuildService(unittest.TestCase):
    def test_local_mode(self):
        tmp = tempfile.TemporaryDirectory()
        db = None
        try:
            cfg = {"base_dir": tmp.name, "prometheus_config": {"local_dir": "prom"}}
            db = Database(Path(tmp.name) / "x.db")
            svc = build_prom_config_service(db, cfg)
            self.assertEqual(svc.fs.describe()["mode"], "local")
            self.assertIn("prom", svc.fs.describe()["base_dir"])
        finally:
            if db is not None:
                db.close()
            tmp.cleanup()

    def test_ssh_mode(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            cfg = {
                "base_dir": tmp.name,
                "prometheus_config": {"ssh_asset_id": "nerv", "remote_base": "/etc/prometheus"},
            }
            db = Database(Path(tmp.name) / "x.db")
            svc = build_prom_config_service(db, cfg, transport=FakeTransport())
            self.assertEqual(svc.fs.describe()["mode"], "ssh")
            self.assertEqual(svc.fs.describe()["asset_id"], "nerv")
            db.close()
        finally:
            tmp.cleanup()


class TestSecurityFailClosed(unittest.TestCase):
    """审查 P1：校验/重载失败必须失败关闭；路径/监听/规则无损。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name) / "prom"
        self.fs = LocalConfigFS(self.base)
        self.db = Database(Path(self.tmp.name) / "t.db")
        asyncio.run(self.fs.write_text("prometheus.yml", SAMPLE_PROM_YML))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_promtool_missing_fails_closed(self):
        svc = PromConfigService(self.db, self.fs, require_promtool=True)

        async def _reload_ok():
            return {"ok": True}

        svc._try_reload = _reload_ok
        # 主机可能安装 promtool 或 Docker；模拟所有候选程序缺失，覆盖真实失败关闭分支。
        with patch("ayana.promconfig.asyncio.create_subprocess_exec", new_callable=AsyncMock,
                   side_effect=FileNotFoundError("simulated missing executable")) as spawn:
            with self.assertRaises(PromConfigError) as ctx:
                asyncio.run(svc.add_target(address="10.0.0.5:9100", actor="t"))
        self.assertGreater(spawn.await_count, 0)
        self.assertEqual(ctx.exception.code, "promtool_failed")
        self.assertIn("promtool_not_found", str(ctx.exception))

    def test_reload_failure_rolls_back(self):
        svc = PromConfigService(self.db, self.fs, require_promtool=False)

        async def _reload_fail():
            return {"ok": False, "status": 403}

        svc._try_reload = _reload_fail
        before = asyncio.run(self.fs.read_text("prometheus.yml"))
        with self.assertRaises(PromConfigError):
            asyncio.run(svc.add_target(address="10.0.0.5:9100", actor="t"))
        after = asyncio.run(self.fs.read_text("prometheus.yml"))
        self.assertEqual(before, after)

    def test_listen_rejects_domain_and_public(self):
        for bad in ("example.com:9100", "0.0.0.0:9100", "8.8.8.8:9100", "1.2.3.4:9100 --x", "127.0.0.1:9100\n"):
            with self.assertRaises(PromConfigError):
                assert_safe_listen_address(bad)
        self.assertEqual(assert_safe_listen_address("[::1]:9100"), "[::1]:9100")
        with self.assertRaises(PromConfigError):
            assert_safe_listen_address("[2001:db8::1]:9100")

    def test_symlink_escape_rejected(self):
        outside = Path(self.tmp.name) / "outside"
        outside.mkdir()
        (outside / "secret.yml").write_text("password: hunter2")
        link = self.base / "rules"
        self.base.mkdir(exist_ok=True)
        try:
            link.symlink_to(outside)
        except OSError:
            self.skipTest("symlink not supported")
        with self.assertRaises(PromConfigError):
            asyncio.run(self.fs.read_text("rules/secret.yml"))

    def test_managed_rules_refuse_when_complex(self):
        # 已有复杂规则文件：禁止用模板覆盖
        asyncio.run(self.fs.write_text("rules/ayana-node-alerts.yml", "groups:\n  - name: x\n    rules:\n      - alert: A\n        expr: up\n        labels:\n          x: y\n          z: w\n"))
        # unknown keys → complex? labels are allowed. force unknown key
        asyncio.run(
            self.fs.write_text(
                "rules/ayana-node-alerts.yml",
                "groups:\n  - name: x\n    rules:\n      - alert: A\n        expr: up\n        keep_firing_for: 5m\n",
            )
        )
        svc = PromConfigService(self.db, self.fs, require_promtool=False)

        async def _reload_ok():
            return {"ok": True}

        svc._try_reload = _reload_ok
        with self.assertRaises(PromConfigError):
            asyncio.run(svc.apply_template(template_id="cpu_high", actor="t"))

    def test_secret_redaction(self):
        from ayana.promconfig import _redact_secrets

        s = _redact_secrets("username: u\npassword: hunter2\ntoken: abcdef\n")
        self.assertNotIn("hunter2", s)
        self.assertNotIn("abcdef", s)
        self.assertIn("***", s)

    def test_yaml_multiline_scalar_quoted(self):
        from ayana.promconfig import dump_simple_yaml

        text = dump_simple_yaml({"expr": "up == 0\nsecond_line"})
        self.assertIn('"up == 0\\nsecond_line"', text)


class TestCapabilitiesRegistered(unittest.TestCase):
    def test_prom_caps(self):
        from ayana.capabilities import CAPABILITIES

        for name in (
            "promconfig.read",
            "promconfig.write",
            "node_exporter.status",
            "node_exporter.manage",
        ):
            self.assertIn(name, CAPABILITIES)


if __name__ == "__main__":
    unittest.main()
