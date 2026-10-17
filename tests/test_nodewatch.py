"""节点守望：签名、防重放、失联调查边界。"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.db import Database
from ayana.nodewatch import (
    STATUS_DOWN,
    STATUS_ONLINE,
    STATUS_SUSPECT,
    NodeWatchService,
    sign_payload,
    verify_payload,
)


class TestSign(unittest.TestCase):
    def test_roundtrip(self):
        payload = {"a": 1}
        ts = time.time()
        sig = sign_payload(
            secret="s", node_id="kanata", ts=ts, nonce="n1", seq=1, payload=payload
        )
        ok, err = verify_payload(
            secret="s",
            node_id="kanata",
            ts=ts,
            nonce="n1",
            seq=1,
            payload=payload,
            sig=sig,
            max_skew_sec=10,
        )
        self.assertTrue(ok, err)

    def test_bad_sig(self):
        ok, err = verify_payload(
            secret="s",
            node_id="kanata",
            ts=1000.0,
            nonce="n1",
            seq=1,
            payload={},
            sig="x" * 64,
            max_skew_sec=10,
        )
        self.assertFalse(ok)

    def test_ts_skew(self):
        sig = sign_payload(
            secret="s", node_id="k", ts=time.time() - 9999, nonce="n", seq=1, payload={}
        )
        ok, err = verify_payload(
            secret="s",
            node_id="k",
            ts=time.time() - 9999,
            nonce="n",
            seq=1,
            payload={},
            sig=sig,
            max_skew_sec=120,
        )
        self.assertFalse(ok)
        self.assertEqual(err, "ts_skew")


class TestHeartbeat(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(str(Path(self.tmp.name) / "t.db"))
        self.svc = NodeWatchService(
            self.db,
            config={
                "send": {"enabled": False},
                "recv": {
                    "enabled": True,
                    "shared_secret": "sec",
                    "allowed_nodes": ["kanata"],
                    "timeout_sec": 180,
                    "probes": [],
                },
            },
        )

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def _hb(self, **kw):
        body = {
            "node_id": "kanata",
            "ts": time.time(),
            "nonce": kw.pop("nonce", "n-" + str(time.time())),
            "seq": kw.pop("seq", 1),
            "payload": {"x": 1},
        }
        body["sig"] = sign_payload(
            secret="sec",
            node_id=body["node_id"],
            ts=body["ts"],
            nonce=body["nonce"],
            seq=body["seq"],
            payload=body["payload"],
        )
        body.update(kw)
        return body

    def test_accept(self):
        res = self.svc.handle_heartbeat(self._hb())
        self.assertTrue(res["ok"], res)
        peer = self.svc.get_peer("kanata")
        self.assertEqual(peer["status"], STATUS_ONLINE)

    def test_reject_replay(self):
        body = self._hb(nonce="fixed-nonce")
        self.assertTrue(self.svc.handle_heartbeat(body)["ok"])
        self.assertEqual(self.svc.handle_heartbeat(body)["error"], "replay")

    def test_reject_unknown_node(self):
        body = self._hb(node_id="evil")
        body["sig"] = sign_payload(
            secret="sec",
            node_id="evil",
            ts=body["ts"],
            nonce=body["nonce"],
            seq=body["seq"],
            payload=body["payload"],
        )
        self.assertFalse(self.svc.handle_heartbeat(body)["ok"])

    def test_recover_notifies(self):
        notes: list[str] = []

        class N:
            def enqueue(self, *a, **k):
                notes.append(str(k.get("body") or a))

        self.svc.notifier = N()
        self.svc.handle_heartbeat(self._hb())
        self.db.execute(
            "UPDATE node_watch_peers SET status=?, incident_open=1 WHERE node_id=?",
            (STATUS_DOWN, "kanata"),
        )
        self.svc.handle_heartbeat(self._hb(nonce="n2", seq=2))
        self.assertEqual(self.svc.get_peer("kanata")["status"], STATUS_ONLINE)
        self.assertTrue(any("恢复" in n for n in notes), notes)


class TestWatchTick(unittest.IsolatedAsyncioTestCase):
    async def test_timeout_without_probes_alerts_once(self):
        tmp = tempfile.TemporaryDirectory()
        db = Database(str(Path(tmp.name) / "t.db"))
        notes: list[str] = []

        class N:
            def enqueue(self, *a, **k):
                notes.append(str(k.get("body") or ""))

        svc = NodeWatchService(
            db,
            config={
                "recv": {
                    "enabled": True,
                    "shared_secret": "s",
                    "allowed_nodes": ["kanata"],
                    "timeout_sec": 1,
                    "probes": [],
                }
            },
            notifier=N(),
        )
        # 落库一条旧心跳
        body = {
            "node_id": "kanata",
            "ts": time.time(),
            "nonce": "x",
            "seq": 1,
            "payload": {},
        }
        body["sig"] = sign_payload(
            secret="s",
            node_id="kanata",
            ts=body["ts"],
            nonce=body["nonce"],
            seq=1,
            payload={},
        )
        svc.handle_heartbeat(body)
        db.execute("UPDATE node_watch_peers SET last_seen_at=? WHERE node_id=?", (time.time() - 60, "kanata"))

        await svc.watch_tick()
        self.assertEqual(len(notes), 1)
        self.assertIn("疑似失联", notes[0])
        await svc.watch_tick()
        self.assertEqual(len(notes), 1)  # 只告一次
        db.close()
        tmp.cleanup()

    async def test_probe_ok_means_channel_only(self):
        tmp = tempfile.TemporaryDirectory()
        db = Database(str(Path(tmp.name) / "t.db"))
        notes: list[str] = []

        class N:
            def enqueue(self, *a, **k):
                notes.append(str(k.get("body") or ""))

        svc = NodeWatchService(
            db,
            config={
                "recv": {
                    "enabled": True,
                    "shared_secret": "s",
                    "allowed_nodes": ["kanata"],
                    "timeout_sec": 1,
                    "probes": [{"kind": "http", "url": "http://127.0.0.1:1/health", "timeout_sec": 0.2}],
                }
            },
            notifier=N(),
        )
        # 人为改 run_probes 返回成功
        async def fake_probes():
            return {"configured": True, "any_ok": True, "all_failed": False, "results": [], "note": ""}

        svc.run_probes = fake_probes  # type: ignore
        body = {
            "node_id": "kanata",
            "ts": time.time(),
            "nonce": "y",
            "seq": 1,
            "payload": {},
        }
        body["sig"] = sign_payload(
            secret="s", node_id="kanata", ts=body["ts"], nonce="y", seq=1, payload={}
        )
        svc.handle_heartbeat(body)
        db.execute("UPDATE node_watch_peers SET last_seen_at=? WHERE node_id=?", (time.time() - 60, "kanata"))
        await svc.watch_tick()
        self.assertEqual(len(notes), 1)
        self.assertIn("心跳通道异常", notes[0])
        self.assertEqual(svc.get_peer("kanata")["status"], STATUS_SUSPECT)
        db.close()
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
