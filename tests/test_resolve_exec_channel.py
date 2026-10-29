"""P1-3 执行通道解析收敛测试。

验证 resolve_exec_channel 合并 main._checks_transport 与 web._ne_transport 后：
- SSH 端点优先
- 仅 local_assets 允许 LocalExec
- 无通道抛 ChannelUnavailable（不静默跨主机回退）
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from ayana.transport import ChannelUnavailable, resolve_exec_channel


class FakeEndpoint(dict):
    pass


class FakeStore:
    def __init__(self, endpoints: dict[str, dict]):
        self._eps = endpoints

    def get_endpoint(self, asset_id: str, role: str):
        return self._eps.get(f"{asset_id}/{role}")


class FakeSSH:
    def __init__(self, store):
        self.store = store


class ResolveExecChannelTest(unittest.TestCase):
    def test_ssh_endpoint_preferred(self):
        store = FakeStore({"web-01/read": {"enabled": True}})
        ssh = FakeSSH(store)
        ch = resolve_exec_channel("web-01", ssh, local_assets={"web-01"}, role="read")
        self.assertIs(ch, ssh)

    def test_local_assets_fallback(self):
        store = FakeStore({})
        ssh = FakeSSH(store)
        ch = resolve_exec_channel("local-1", ssh, local_assets={"local-1"}, role="read")
        self.assertIsNot(ch, ssh)
        self.assertTrue(hasattr(ch, "probe"))

    def test_no_channel_raises(self):
        store = FakeStore({})
        ssh = FakeSSH(store)
        with self.assertRaises(ChannelUnavailable):
            resolve_exec_channel("unknown", ssh, local_assets=set(), role="read")

    def test_ssh_none_local_allowed(self):
        ch = resolve_exec_channel("local-1", None, local_assets={"local-1"}, role="write")
        self.assertTrue(hasattr(ch, "exec"))

    def test_ssh_none_no_local_raises(self):
        with self.assertRaises(ChannelUnavailable):
            resolve_exec_channel("remote", None, local_assets=set(), role="write")

    def test_missing_selected_group_never_falls_back_to_other_role(self):
        # 账号组由用户指定；缺少指定组不能改用另一个组的账号。
        store = FakeStore({"web-01/write": {"enabled": True}})
        ssh = FakeSSH(store)
        with self.assertRaises(ChannelUnavailable):
            resolve_exec_channel("web-01", ssh, local_assets=set(), role="read")

    def test_disabled_endpoint_not_used(self):
        store = FakeStore({"web-01/read": {"enabled": False}})
        ssh = FakeSSH(store)
        with self.assertRaises(ChannelUnavailable):
            resolve_exec_channel("web-01", ssh, local_assets=set(), role="read")

    def test_ssh_endpoint_requires_enabled(self):
        store = FakeStore({"web-01/read": {"enabled": True}})
        ssh = FakeSSH(store)
        ch = resolve_exec_channel("web-01", ssh, local_assets=set(), role="read")
        self.assertIs(ch, ssh)


if __name__ == "__main__":
    unittest.main()
