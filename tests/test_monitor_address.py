"""Monitoring registration resolves the same host as the asset list (no network)."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.web import WebApp


def make_app(*, asset=None, endpoints=()):
    app = WebApp.__new__(WebApp)
    app.ssh_store = Mock()
    app.ssh_store.list_endpoints.return_value = list(endpoints)
    app.ssh_store.role_kind.side_effect = lambda role: {"write": "write", "read": "read"}.get(role)
    app.transport = None
    app._require_auth = Mock(return_value={"username": "admin"})
    app._check_csrf = Mock()
    app._require_asset = Mock(return_value=asset or {"id": "yomi", "host": ""})
    app._policy_for = Mock(return_value={"allowed": True, "require_approval": False})
    app._ne_transport = Mock(return_value=object())
    service = SimpleNamespace(adopt_node=AsyncMock(return_value={"ok": True}))
    app._promconfig = Mock(return_value=service)
    return app, service


def endpoint(role, host, enabled=True):
    return {"role": role, "host": host, "enabled": enabled}


def payload(response):
    return json.loads(response.body)


class TestAssetMonitorHost(unittest.TestCase):
    def test_monitor_host_then_asset_host_take_precedence(self):
        app, _ = make_app(endpoints=[endpoint("write", "203.0.113.50")])
        asset = {"id": "yomi", "monitor_host": " monitor.example ", "host": "asset.example"}
        self.assertEqual(app._asset_monitor_host(asset), "monitor.example")
        asset["monitor_host"] = "   "
        self.assertEqual(app._asset_monitor_host(asset), "asset.example")
        app.ssh_store.list_endpoints.assert_not_called()

    def test_enabled_write_endpoint_precedes_read_and_other_roles(self):
        app, _ = make_app(endpoints=[
            endpoint("other", "other.example"),
            endpoint("read", "read.example"),
            endpoint("write", " 203.0.113.50 "),
        ])
        self.assertEqual(app._asset_monitor_host({"id": "yomi", "host": ""}), "203.0.113.50")
        app.ssh_store.list_endpoints.assert_called_once_with("yomi")

    def test_disabled_or_blank_write_endpoint_does_not_override_read(self):
        app, _ = make_app(endpoints=[
            endpoint("write", "disabled.example", False),
            endpoint("write", "   "),
            endpoint("other", "other.example"),
            endpoint("read", "read.example"),
        ])
        self.assertEqual(app._asset_monitor_host({"id": "yomi"}), "read.example")

    def test_registered_custom_role_is_available_as_last_fallback(self):
        app, _ = make_app(endpoints=[
            endpoint("read", "disabled.example", False),
            endpoint("custom", "custom.example"),
        ])
        app.ssh_store.role_kind.side_effect = lambda role: {"custom": "read"}.get(role)
        self.assertEqual(app._asset_monitor_host({"id": "yomi"}), "custom.example")

    def test_custom_write_precedes_custom_read(self):
        app, _ = make_app(endpoints=[
            endpoint("custom_read", "read.example"),
            endpoint("custom_write", "write.example"),
        ])
        app.ssh_store.role_kind.side_effect = lambda role: {
            "custom_read": "read", "custom_write": "write",
        }.get(role)
        self.assertEqual(app._asset_monitor_host({"id": "yomi"}), "write.example")

    def test_literal_read_precedes_registered_custom_write(self):
        app, _ = make_app(endpoints=[
            endpoint("custom_write", "custom.example"),
            endpoint("read", "literal.example"),
        ])
        app.ssh_store.role_kind.side_effect = lambda role: {
            "custom_write": "write", "read": "read",
        }.get(role)
        self.assertEqual(app._asset_monitor_host({"id": "yomi"}), "literal.example")

    def test_unknown_role_does_not_supply_monitor_host(self):
        app, _ = make_app(endpoints=[endpoint("unknown", "unknown.example")])
        self.assertEqual(app._asset_monitor_host({"id": "yomi"}), "")

    def test_role_lookup_failure_does_not_supply_monitor_host(self):
        app, _ = make_app(endpoints=[endpoint("unknown", "unknown.example")])
        app.ssh_store.role_kind.side_effect = ValueError("unknown role")
        self.assertEqual(app._asset_monitor_host({"id": "yomi"}), "")

    def test_explicit_endpoint_list_is_used_without_store_lookup(self):
        app, _ = make_app(endpoints=[endpoint("write", "registered.example")])
        self.assertEqual(
            app._asset_monitor_host({"id": "yomi"}, [endpoint("read", "provided.example")]),
            "provided.example",
        )
        self.assertEqual(app._asset_monitor_host({"id": "yomi"}, []), "")
        app.ssh_store.list_endpoints.assert_not_called()

    def test_transport_store_is_used_when_ssh_store_not_set(self):
        app, _ = make_app()
        store = app.ssh_store
        store.list_endpoints.return_value = [endpoint("write", "203.0.113.50")]
        app.ssh_store = None
        app.transport = SimpleNamespace(store=store)
        self.assertEqual(app._asset_monitor_host({"id": "yomi"}), "203.0.113.50")
        store.list_endpoints.assert_called_once_with("yomi")

    def test_no_configured_source_returns_empty_host(self):
        app, _ = make_app()
        app.ssh_store = None
        self.assertEqual(app._asset_monitor_host({"id": "yomi", "host": ""}), "")

    def test_only_disabled_endpoints_returns_empty_host(self):
        app, _ = make_app(endpoints=[endpoint("write", "disabled.example", False)])
        self.assertEqual(app._asset_monitor_host({"id": "yomi", "host": ""}), "")


class TestMonitoringAddressAPI(unittest.IsolatedAsyncioTestCase):
    async def test_empty_and_omitted_address_use_registered_write_host(self):
        for body in ({"asset_id": "yomi"}, {"asset_id": "yomi", "address": ""}):
            with self.subTest(body=body):
                app, service = make_app(endpoints=[endpoint("write", "203.0.113.50")])
                request = SimpleNamespace(json=AsyncMock(return_value=body))
                response = await app.api_promconfig_node_adopt(request)
                self.assertEqual(response.status, 200)
                self.assertTrue(payload(response)["ok"])
                service.adopt_node.assert_awaited_once()
                self.assertEqual(service.adopt_node.await_args.kwargs["address"], "203.0.113.50:9100")
                self.assertEqual(service.adopt_node.await_args.kwargs["asset_id"], "yomi")

    async def test_supplied_monitoring_address_is_preserved(self):
        app, service = make_app(endpoints=[endpoint("write", "203.0.113.50")])
        request = SimpleNamespace(json=AsyncMock(return_value={
            "asset_id": "yomi", "address": "metrics.example:19100",
        }))
        response = await app.api_promconfig_node_adopt(request)
        self.assertEqual(response.status, 200)
        self.assertEqual(service.adopt_node.await_args.kwargs["address"], "metrics.example:19100")
        app.ssh_store.list_endpoints.assert_not_called()

    async def test_ipv6_derived_address_has_brackets_once(self):
        for host in ("2001:db8::7", "[2001:db8::7]"):
            with self.subTest(host=host):
                app, service = make_app(asset={"id": "yomi", "host": host})
                request = SimpleNamespace(json=AsyncMock(return_value={"asset_id": "yomi"}))
                response = await app.api_promconfig_node_adopt(request)
                self.assertEqual(response.status, 200)
                self.assertEqual(service.adopt_node.await_args.kwargs["address"], "[2001:db8::7]:9100")

    async def test_unresolved_address_fails_before_service_or_transport(self):
        app, service = make_app(endpoints=[endpoint("write", "disabled.example", False)])
        request = SimpleNamespace(json=AsyncMock(return_value={"asset_id": "yomi", "address": ""}))
        response = await app.api_promconfig_node_adopt(request)
        self.assertEqual(response.status, 400)
        data = payload(response)
        self.assertEqual(data["error"], "address_required")
        self.assertTrue(any("\u4e00" <= char <= "\u9fff" for char in data["hint"]))
        app._promconfig.assert_not_called()
        app._ne_transport.assert_not_called()
        service.adopt_node.assert_not_awaited()

    async def test_permission_and_approval_gates_prevent_adoption(self):
        cases = (
            ("node_exporter.manage", {"allowed": False}, "denied"),
            ("node_exporter.manage", {"allowed": True, "require_approval": True}, "approval_required"),
            ("promconfig.write", {"allowed": False}, "denied"),
            ("promconfig.write", {"allowed": True, "require_approval": True}, "denied"),
        )
        for capability, blocked, error in cases:
            with self.subTest(capability=capability, decision=blocked):
                app, service = make_app(endpoints=[endpoint("write", "203.0.113.50")])
                app._policy_for.side_effect = lambda sess, cap, **kwargs: (
                    blocked if cap == capability else {"allowed": True, "require_approval": False}
                )
                request = SimpleNamespace(json=AsyncMock(return_value={"asset_id": "yomi"}))
                response = await app.api_promconfig_node_adopt(request)
                self.assertEqual(response.status, 403)
                self.assertEqual(payload(response)["error"], error)
                app.ssh_store.list_endpoints.assert_not_called()
                app._promconfig.assert_not_called()
                app._ne_transport.assert_not_called()
                service.adopt_node.assert_not_awaited()

    async def test_asset_list_and_adoption_resolve_same_monitor_host(self):
        asset = {"id": "yomi", "host": ""}
        app, service = make_app(asset=asset, endpoints=[
            endpoint("read", "read.example"), endpoint("write", "203.0.113.50"),
        ])
        app._visible_asset_ids = Mock(return_value={"yomi"})
        app.db = Mock()
        app.db.query.side_effect = [[asset], []]
        listed = await app.api_assets(SimpleNamespace())
        listed_asset = payload(listed)["assets"][0]
        self.assertEqual(listed_asset["host"], "203.0.113.50")
        self.assertEqual(listed_asset["monitor_host"], "203.0.113.50")
        request = SimpleNamespace(json=AsyncMock(return_value={"asset_id": "yomi"}))
        response = await app.api_promconfig_node_adopt(request)
        self.assertEqual(response.status, 200)
        self.assertEqual(
            service.adopt_node.await_args.kwargs["address"],
            f"{listed_asset['monitor_host']}:9100",
        )


if __name__ == "__main__":
    unittest.main()
