"""Real business observations remain visible independently of Node metrics."""
from __future__ import annotations

import copy
import json
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from aiohttp import web

from ayana.business import native_check_items, prometheus_checks, required_health
from ayana.checks import CheckService
from ayana.db import Database
from ayana.health import apply_required_checks
from ayana.monitor import HostMonitor
from ayana.prom import PromError
from ayana.web import WebApp


AT = 1_800_000_000.0


def sample(metric="probe_success", *, asset="demo", service="svc-a", value=1.0, age=15, **labels):
    return {"metric": {"__name__": metric, "asset": asset, "service": service, **labels},
            "sample_at": AT - age, "value": value}


class CatalogProm:
    """A selector-aware fake, so a wrong query cannot retrieve the right fixture."""
    def __init__(self, samples=(), *, failures=()):
        self.samples = copy.deepcopy(list(samples))
        self.failures = set(failures)
        self.calls = []

    async def query_range_vector(self, expression, *, at, window_sec):
        self.calls.append((expression, at, window_sec))
        metric = expression.split("{", 1)[0]
        if metric in self.failures:
            raise PromError("simulated upstream failure")
        selectors = [(key, operator, json.loads('"' + value + '"'))
                     for key, operator, value in re.findall(r'(\w+)(=~|=)"((?:\\.|[^"\\])*)"', expression)]
        result = []
        for row in self.samples:
            labels = row["metric"]
            if labels["__name__"] != metric:
                continue
            if any((re.fullmatch(value, str(labels.get(key, ""))) is None) if operator == "=~"
                   else labels.get(key) != value for key, operator, value in selectors):
                continue
            result.append(copy.deepcopy(row))
        return result

    async def query(self, expression):
        raise AssertionError("business freshness must use actual sample times")

    async def targets(self):
        return []


class PrometheusBusinessTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        clock = patch("ayana.business.time.time", return_value=AT)
        clock.start()
        self.addCleanup(clock.stop)
        # 发行版 REQUIRED_CHECKS 为空，测试本地注入
        apply_required_checks({})
        self.addCleanup(lambda: apply_required_checks({}))

    async def test_declared_object_uses_real_selector_and_is_not_duplicated(self):
        apply_required_checks({"demo": [{"object": "svc-a", "metric": "probe_success",
                                          "selector": {"service": "svc-a"}, "freshness_sec": 120}]})
        prom = CatalogProm([sample(), sample(service="svc-b", value=0)])
        rows, errors = await prometheus_checks(prom, {"id": "demo", "prom_asset": "demo"})
        self.assertEqual(errors, [])
        required = [row for row in rows if row["required"]]
        self.assertEqual(len(required), 1)
        self.assertEqual(required[0]["name"], "svc-a")
        self.assertEqual(required[0]["labels"]["service"], "svc-a")
        self.assertEqual(required[0]["state"], "ok")
        self.assertEqual(required[0]["last_at"], AT - 15)
        self.assertEqual(sum(row["labels"].get("service") == "svc-a" for row in rows), 1)
        other = next(row for row in rows if row["labels"].get("service") == "svc-b")
        self.assertFalse(other["required"])
        self.assertEqual(other["state"], "fail")
        self.assertEqual(required_health(rows), "healthy")

    async def test_custom_asset_alias_and_case_match_actual_probe_labels(self):
        prom = CatalogProm([sample(asset="EDGE-PROBE", service="app"),
                            sample(asset="neighbor", service="private-app")])
        rows, errors = await prometheus_checks(prom, {"id": "edge", "prom_asset": "edge-probe"})
        self.assertEqual(errors, [])
        self.assertEqual([row["name"] for row in rows], ["app"])
        self.assertEqual(rows[0]["asset_id"], "edge")
        self.assertEqual(rows[0]["source"], "prometheus")
        self.assertEqual(rows[0]["kind"], "probe")
        self.assertEqual(rows[0]["state"], "ok")

    async def test_registered_asset_id_and_prom_alias_can_coexist_during_relabeling(self):
        prom = CatalogProm([sample(asset="edge", service="legacy-app"),
                            sample(asset="EDGE-PROBE", service="new-app")])
        rows, errors = await prometheus_checks(prom, {"id": "edge", "prom_asset": "edge-probe"})
        self.assertEqual(errors, [])
        self.assertEqual({row["name"] for row in rows}, {"legacy-app", "new-app"})

    async def test_fresh_zero_value_is_failed_business_observation(self):
        apply_required_checks({"demo": [
            {"object": "svc-a", "metric": "probe_success", "selector": {"service": "svc-a"}, "freshness_sec": 120},
            {"object": "svc-b", "metric": "probe_success", "selector": {"service": "svc-b"}, "freshness_sec": 120},
        ]})
        rows, errors = await prometheus_checks(CatalogProm([sample(asset="demo", service="svc-a", value=0),
                                                            sample(asset="demo", service="svc-b", value=1)]), {"id": "demo"})
        self.assertEqual(errors, [])
        states = {row["name"]: row["state"] for row in rows}
        self.assertEqual(states, {"svc-a": "fail", "svc-b": "ok"})
        self.assertEqual(required_health(rows), "unhealthy")

    async def test_declared_missing_probe_remains_an_unobserved_row(self):
        apply_required_checks({"demo": [{"object": "svc-a", "metric": "probe_success",
                                          "selector": {"service": "svc-a"}, "freshness_sec": 120}]})
        rows, errors = await prometheus_checks(CatalogProm(), {"id": "demo"})
        self.assertEqual(errors, [])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["state"], "no_data")
        self.assertTrue(rows[0]["required"])
        self.assertEqual(required_health(rows), "unknown")

    async def test_latest_actual_sample_restores_probe_without_historical_failure_stickiness(self):
        prom = CatalogProm([sample(value=0, age=100), sample(value=1, age=15)])
        rows, errors = await prometheus_checks(prom, {"id": "demo"})
        self.assertEqual(errors, [])
        self.assertEqual(rows[0]["state"], "ok")
        self.assertEqual(rows[0]["value"], 1)
        self.assertEqual(rows[0]["last_at"], AT - 15)

    async def test_proxy_samples_use_real_time_and_remain_separate_from_missing_service_probe(self):
        apply_required_checks({"demo": [
            {"object": "svc-proxy", "metric": "proxy_up", "selector": {"service": "svc-proxy"},
             "freshness_sec": 120, "kind": "proxy"},
            {"object": "svc-a", "metric": "probe_success", "selector": {"service": "svc-a"},
             "freshness_sec": 120},
        ]})
        prom = CatalogProm([sample("proxy_up", asset="demo", service="svc-proxy", target="target-a"),
                            sample("proxy_up", asset="demo", service="svc-proxy", target="target-b")])
        rows, errors = await prometheus_checks(prom, {"id": "demo"})
        self.assertEqual(errors, [])
        states = {row["name"]: row["state"] for row in rows}
        self.assertEqual(states, {"svc-proxy": "ok", "svc-a": "no_data"})
        self.assertTrue(all(row["kind"] == "proxy" for row in rows if row["metric"] == "proxy_up"))
        self.assertEqual(required_health(rows), "unknown")

    async def test_proxy_target_name_does_not_cross_registered_asset_boundary(self):
        apply_required_checks({"demo": [{"object": "svc-proxy", "metric": "proxy_up",
                                          "selector": {"service": "svc-proxy"}, "freshness_sec": 120, "kind": "proxy"}]})
        prom = CatalogProm([sample("proxy_up", asset="demo", service="svc-proxy", target="target-a", value=1),
                            sample("proxy_up", asset="other-asset", service="svc-proxy", target="target-a", value=0, age=5)])
        rows, _ = await prometheus_checks(prom, {"id": "demo"})
        target_a = next(row for row in rows if row["name"] == "svc-proxy")
        self.assertEqual(target_a["state"], "ok")
        self.assertEqual(target_a["labels"]["asset"], "demo")

    async def test_stale_probe_is_not_freshened_by_query_evaluation(self):
        apply_required_checks({"demo": [{"object": "svc-a", "metric": "probe_success",
                                          "selector": {"service": "svc-a"}, "freshness_sec": 120}]})
        rows, _ = await prometheus_checks(CatalogProm([sample(age=240)]), {"id": "demo"})
        self.assertEqual(rows[0]["state"], "stale")
        self.assertEqual(rows[0]["last_at"], AT - 240)
        self.assertEqual(required_health(rows), "stale")

    async def test_nonfinite_sample_is_unknown_and_response_is_valid_json(self):
        for value, timestamp in ((float("nan"), AT - 15), (float("inf"), AT - 15),
                                 (1.0, float("nan")), (1.0, float("inf"))):
            with self.subTest(value=value, timestamp=timestamp):
                row = sample(value=value)
                row["sample_at"] = timestamp
                rows, errors = await prometheus_checks(CatalogProm([row]), {"id": "demo"})
                self.assertEqual(rows[0]["state"], "no_data")
                json.dumps({"items": rows, "errors": errors}, allow_nan=False)

    async def test_failed_metric_does_not_hide_other_available_proxy_observations(self):
        apply_required_checks({"demo": [
            {"object": "svc-proxy", "metric": "proxy_up", "selector": {"service": "svc-proxy"},
             "freshness_sec": 120, "kind": "proxy"},
            {"object": "svc-a", "metric": "probe_success", "selector": {"service": "svc-a"},
             "freshness_sec": 120},
        ]})
        prom = CatalogProm([sample("proxy_up", asset="demo", service="svc-proxy", target="target-a"),
                            sample("proxy_up", asset="demo", service="svc-proxy", target="target-b")], failures=["probe_success"])
        rows, errors = await prometheus_checks(prom, {"id": "demo"})
        self.assertEqual({row["name"]: row["state"] for row in rows},
                         {"svc-proxy": "ok", "svc-a": "collect_error"})
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]["source"], "prometheus")
        self.assertTrue(errors[0]["message"])
        self.assertEqual(required_health(rows), "collect_error")

    def test_native_state_adapter_is_read_only_and_uses_interval_freshness(self):
        records = [
            {"id": "recent", "enabled": True, "last_state": "ok", "last_at": AT - 15, "interval_sec": 60},
            {"id": "failed", "enabled": True, "last_state": "fail", "last_at": AT - 15, "interval_sec": 60},
            {"id": "old", "enabled": True, "last_state": "ok", "last_at": AT - 150, "interval_sec": 60},
            {"id": "slow", "enabled": True, "last_state": "ok", "last_at": AT - 150, "interval_sec": 120},
            {"id": "disabled", "enabled": False, "last_state": "fail", "last_at": AT - 15},
            {"id": "waiting", "enabled": True, "last_state": "unknown", "last_at": 0},
        ]
        original = copy.deepcopy(records)
        rows = native_check_items(records)
        self.assertEqual(records, original)
        self.assertEqual({row["id"]: row["state"] for row in rows},
                         {"recent": "ok", "failed": "fail", "old": "stale", "slow": "ok", "disabled": "disabled", "waiting": "no_data"})
        self.assertTrue(all(row["source"] == "ayana" for row in rows))

    def test_only_declared_checks_affect_required_health(self):
        self.assertEqual(required_health([{"required": False, "state": "fail"}]), "")
        self.assertEqual(required_health([{"required": True, "state": "ok"}, {"required": False, "state": "fail"}]), "healthy")


class BusinessAPITest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(Path(self.tmp.name) / "test.db")
        self.addCleanup(self.db.close)
        apply_required_checks({})
        self.addCleanup(lambda: apply_required_checks({}))
        for identifier in ("control", "asset-a", "asset-b", "private"):
            self.db.execute("INSERT INTO assets(id,display_name,prom_asset,read_alias,write_alias,enabled,created_at,updated_at) VALUES(?,?,?,?,?,1,1,1)",
                            (identifier, identifier.upper(), identifier, identifier, identifier + "-exec"))
        self.db.execute("INSERT INTO checks(id,asset_id,name,kind,params_json,interval_sec,last_state,last_at,created_at,updated_at) VALUES('chk_control','control','任务运行程序','service','{\"unit\":\"worker.service\"}',60,'ok',?,1,1)", (AT - 15,))
        self.transport = SimpleNamespace(probe=AsyncMock(side_effect=AssertionError("monitoring reads must not execute checks")))
        self.policy = Mock()
        self.policy.check.return_value = {"allowed": True}
        self.session = {"username": "reader", "is_admin": False}
        self.prom = CatalogProm([sample(asset="asset-a", service="svc-a")])
        self.incidents = Mock()
        self.incidents.list_incidents.return_value = []
        self.actions = Mock()
        self.actions.list_actions.return_value = []
        self.monitor = SimpleNamespace(
            hosts_status=AsyncMock(side_effect=lambda assets: [{"asset_id": asset["id"], "state": "no_data" if asset["id"] == "control" else "ok", "error": "", "summary": {}} for asset in assets]),
            host_overview=AsyncMock(side_effect=lambda identifier: {"asset_id": identifier, "state": "no_data" if identifier == "control" else "ok", "error": "", "metrics": {}}),
            host_history=AsyncMock(side_effect=lambda identifier, range_key: {"asset_id": identifier, "state": "no_data" if identifier == "control" else "ok", "error": "", "metrics": {}}),
        )
        self.app = WebApp(self.db, None, self.policy, self.incidents, None, self.actions, self.prom,
                          static_dir=Path(self.tmp.name), checks=CheckService(self.db, self.transport), host_monitor=self.monitor)
        self.app._require_auth = Mock(return_value=self.session)
        self.app._visible_asset_ids = Mock(return_value={"control", "asset-a"})
        self.app._check_read = Mock(return_value=self.session)
        clock = patch("ayana.business.time.time", return_value=AT)
        clock.start()
        self.addCleanup(clock.stop)

    def snapshot(self):
        tables = [row["name"] for row in self.db.query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        rows = {table: [tuple(row) for row in self.db.query('SELECT * FROM "' + table + '" ORDER BY rowid')] for table in tables}
        return {"rows": rows, "total_changes": self.db._connect().total_changes}

    async def get(self, identifier):
        response = await self.app.api_monitor_business(SimpleNamespace(match_info={"asset_id": identifier}))
        return response, json.loads(response.body)

    async def observed_states(self, identifier):
        hosts = json.loads((await self.app.api_monitor_hosts(SimpleNamespace())).body)
        request = SimpleNamespace(match_info={"asset_id": identifier}, rel_url=SimpleNamespace(query={}))
        detail = json.loads((await self.app.api_monitor_host(request)).body)
        overview = json.loads((await self.app.api_overview(SimpleNamespace())).body)
        strip = next(row for row in hosts["hosts"] if row["asset_id"] == identifier)
        home = next(row for row in overview["assets"] if row["id"] == identifier)
        return strip, detail, home, overview

    async def test_native_check_survives_absent_node_metrics_without_any_write_or_execution(self):
        before = self.snapshot()
        response, payload = await self.get("control")
        self.assertEqual(response.status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(len(payload["items"]), 1)
        row = payload["items"][0]
        self.assertEqual(row["id"], "chk_control")
        self.assertEqual(row["source"], "ayana")
        self.assertEqual(row["state"], "ok")
        self.assertEqual(self.snapshot(), before)
        self.transport.probe.assert_not_awaited()
        self.app.host_monitor.host_overview.assert_not_called()

    async def test_prometheus_failure_keeps_native_rows_and_readable_source_error(self):
        self.prom.failures.add("probe_success")
        before = self.snapshot()
        _, payload = await self.get("control")
        self.assertEqual(payload["items"][0]["source"], "ayana")
        self.assertEqual(payload["items"][0]["state"], "ok")
        self.assertEqual(payload["errors"][0]["source"], "prometheus")
        self.assertIn("Prometheus", payload["errors"][0]["message"])
        self.assertNotIn("simulated", payload["errors"][0]["message"])
        self.assertEqual(self.snapshot(), before)

    async def test_legacy_rule_denial_does_not_hide_registered_business_data(self):
        self.policy.check.return_value = {"allowed": False}
        before = self.snapshot()
        _, payload = await self.get("asset-a")
        self.assertEqual([row["source"] for row in payload["items"]], ["prometheus"])
        self.assertEqual(payload["errors"], [])
        self.policy.check.assert_not_called()
        self.assertEqual(self.snapshot(), before)

    async def test_native_permission_failure_does_not_hide_prometheus_source(self):
        self.app._check_read.side_effect = web.HTTPForbidden()
        before = self.snapshot()
        _, payload = await self.get("asset-a")
        self.assertEqual([row["source"] for row in payload["items"]], ["prometheus"])
        self.assertEqual(payload["items"][0]["state"], "ok")
        self.assertEqual(payload["errors"][0]["source"], "ayana")
        self.assertIn("权限", payload["errors"][0]["message"])
        self.assertEqual(self.snapshot(), before)

    async def test_invisible_or_missing_asset_cannot_read_any_source(self):
        for identifier, status in (("private", 403), ("does-not-exist", 404)):
            with self.subTest(identifier=identifier):
                before = self.snapshot()
                response, payload = await self.get(identifier)
                self.assertEqual(response.status, status)
                self.assertFalse(payload["ok"])
                self.assertTrue(payload["message"])
                self.assertEqual(self.prom.calls, [])
                self.app._check_read.assert_not_called()
                self.assertEqual(self.snapshot(), before)

    async def test_harbor_selector_restores_same_green_state_across_all_views(self):
        before = self.snapshot()
        strip, detail, home, _ = await self.observed_states("asset-a")
        self.assertEqual(strip["metric_state"], "ok")
        self.assertEqual(strip["health"]["state"], "ok")
        self.assertEqual(detail["health"]["state"], "ok")
        self.assertEqual(home["health_dot"]["state"], "ok")
        self.assertEqual(home["business_summary"], {"total": 1, "healthy": 1, "failed": 0, "unknown": 0})
        self.assertEqual(self.snapshot(), before)
        self.transport.probe.assert_not_awaited()

    async def test_control_native_business_is_visible_in_home_without_node_metrics(self):
        before = self.snapshot()
        _, business = await self.get("control")
        strip, detail, home, _ = await self.observed_states("control")
        self.assertEqual(business["items"][0]["state"], "ok")
        self.assertEqual(strip["metric_state"], "no_data")
        for health in (strip["health"], detail["health"], home["health_dot"]):
            self.assertEqual(health["state"], "warn")
            self.assertEqual(health["label"], "部分未观测")
            self.assertEqual(health["sources"]["checks"], ["ok"])
        self.assertEqual(home["business_summary"], {"total": 1, "healthy": 1, "failed": 0, "unknown": 0})
        self.assertEqual(self.snapshot(), before)

    async def test_proxy_sample_times_and_missing_service_have_consistent_all_view_states(self):
        self.app._visible_asset_ids.return_value = {"asset-b"}
        apply_required_checks({"asset-b": [
            {"object": "svc-proxy", "metric": "proxy_up", "selector": {"service": "svc-proxy"},
             "freshness_sec": 120, "kind": "proxy"},
            {"object": "svc-a", "metric": "probe_success", "selector": {"service": "svc-a"},
             "freshness_sec": 120},
        ]})
        self.addCleanup(lambda: apply_required_checks({}))
        proxy = [sample("proxy_up", asset="asset-b", service="svc-proxy", target="target-a"),
                 sample("proxy_up", asset="asset-b", service="svc-proxy", target="target-b")]
        for observed_service, expected in ((True, "ok"), (False, "warn")):
            with self.subTest(observed_service=observed_service):
                self.prom.samples = proxy + ([sample(asset="asset-b", service="svc-a")] if observed_service else [])
                self.app._business_cache = {}
                self.app._overview_cache = None
                before = self.snapshot()
                _, business = await self.get("asset-b")
                strip, detail, home, _ = await self.observed_states("asset-b")
                self.assertEqual(strip["health"]["state"], expected)
                self.assertEqual(detail["health"]["state"], expected)
                self.assertEqual(home["health_dot"]["state"], expected)
                self.assertEqual(home["business_summary"]["healthy"], 2 if observed_service else 1)
                for row in business["items"]:
                    if row["kind"] == "proxy":
                        self.assertEqual(row["state"], "ok")
                        self.assertEqual(row["last_at"], AT - 15)
                if not observed_service:
                    self.assertEqual(strip["health"]["label"], "部分未观测")
                self.assertEqual(self.snapshot(), before)

    async def test_discovered_nonrequired_probe_enters_home_summary_health_and_ratio(self):
        self.prom.samples.append(sample(asset="control", service="application-health", value=0))
        before = self.snapshot()
        strip, detail, home, overview = await self.observed_states("control")
        self.assertEqual(strip["health"]["state"], "bad")
        self.assertEqual(detail["health"]["state"], "bad")
        self.assertEqual(home["health_dot"]["state"], "bad")
        self.assertEqual(home["business_summary"], {"total": 2, "healthy": 1, "failed": 1, "unknown": 0})
        sources = {source["key"]: source for source in overview["health_ratio"]["sources"]}
        self.assertEqual(sources["metrics"]["total"], 2)
        self.assertEqual(sources["metrics"]["healthy"], 1)
        self.assertEqual(sources["checks"]["total"], 1)
        self.assertEqual(self.snapshot(), before)

    async def test_home_cache_rechecks_visible_asset_set_before_returning_data(self):
        before = self.snapshot()
        self.app._visible_asset_ids.return_value = {"control"}
        first = json.loads((await self.app.api_overview(SimpleNamespace())).body)
        self.app._visible_asset_ids.return_value = {"asset-a"}
        second = json.loads((await self.app.api_overview(SimpleNamespace())).body)
        self.assertEqual({asset["id"] for asset in first["assets"]}, {"control"})
        self.assertEqual({asset["id"] for asset in second["assets"]}, {"asset-a"})
        self.assertNotIn("control", json.dumps(second["assets"]))
        self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
