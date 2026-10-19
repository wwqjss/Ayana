"""节点守望：签名、防重放、失联调查边界。"""

from __future__ import annotations

import asyncio
import json
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
    _safe_heartbeat_url,
    build_invite,
    fingerprint_secret,
    parse_invite,
    sign_payload,
    verify_payload,
)


class TestInvite(unittest.TestCase):
    def test_build_parse_roundtrip(self):
        inv = build_invite(
            url="http://203.0.113.50:6200/api/node-watch/heartbeat",
            node_id="kanata",
            key="secret-abc",
            ttl_sec=600,
        )
        self.assertTrue(inv.startswith("AYANA-WATCH1."))
        res = parse_invite(inv)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["node_id"], "kanata")
        self.assertEqual(res["key"], "secret-abc")
        self.assertEqual(res["fp"], fingerprint_secret("secret-abc"))

    def test_expired(self):
        inv = build_invite(url="http://x/h", node_id="n", key="k", exp=1)
        res = parse_invite(inv)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"], "expired")

    def test_bad_prefix(self):
        self.assertFalse(parse_invite("hello")["ok"])


class TestPairing(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(str(Path(self.tmp.name) / "t.db"))
        self.svc = NodeWatchService(
            self.db,
            config={"send": {}, "recv": {"enabled": False}},
        )

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_generate_and_apply(self):
        gen = self.svc.generate_invite(
            node_id="kanata", url="http://yomi:6200/api/node-watch/heartbeat"
        )
        self.assertTrue(gen["ok"], gen)
        self.assertTrue(self.svc.enabled_recv())
        self.assertIn("kanata", self.svc.allowed_nodes())

        send_svc = NodeWatchService(self.db, config={"send": {}, "recv": {}})
        parsed = send_svc.parse_invite_text(gen["invite"])
        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["fp"], gen["fp"])

        bad = send_svc.apply_invite(gen["invite"], expected_fp="deadbeef")
        self.assertFalse(bad["ok"])
        self.assertEqual(bad["error"], "fp_mismatch")

        ok = send_svc.apply_invite(gen["invite"], expected_fp=gen["fp"])
        self.assertTrue(ok["ok"], ok)
        self.assertTrue(send_svc.enabled_send())
        self.assertEqual(send_svc.send_cfg["node_id"], "kanata")
        self.assertEqual(send_svc.send_secret(), send_svc.recv_secret() or send_svc.send_secret())
        self.assertEqual(send_svc.send_cfg["target_url"], "http://yomi:6200/api/node-watch/heartbeat")


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


class TestSettings(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg_path = str(Path(self.tmp.name) / "config.json")
        Path(self.cfg_path).write_text("{}", encoding="utf-8")
        self.db = Database(str(Path(self.tmp.name) / "t.db"))
        self.svc = NodeWatchService(
            self.db,
            config={"send": {"enabled": True, "interval_sec": 60}, "recv": {"enabled": False}},
            config_path=self.cfg_path,
        )

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_update_interval(self):
        res = self.svc.update_settings(interval_sec=15)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["interval_sec"], 15)
        self.assertEqual(self.svc.send_interval_sec(), 15)
        data = json.loads(Path(self.cfg_path).read_text(encoding="utf-8"))
        self.assertEqual(data["node_watch"]["send"]["interval_sec"], 15)

    def test_interval_floor(self):
        self.svc.update_settings(interval_sec=3)
        self.assertEqual(self.svc.send_interval_sec(), 10)

    def test_apply_invite_keeps_interval(self):
        recv = NodeWatchService(
            self.db,
            config={"send": {}, "recv": {"enabled": False}},
        )
        gen = recv.generate_invite(
            node_id="kanata", url="http://yomi:6200/api/node-watch/heartbeat"
        )
        ok = self.svc.apply_invite(gen["invite"], expected_fp=gen["fp"], interval_sec=30)
        self.assertTrue(ok["ok"], ok)
        self.assertEqual(self.svc.send_interval_sec(), 30)

    def test_overview_summary_levels(self):
        self.svc.update_settings(interval_sec=20)
        s = self.svc.overview_summary()
        self.assertEqual(s["level"], "warn")
        self.assertEqual(s["interval_sec"], 20)
        self.assertEqual(s["peer_count"], 0)
        self.svc.db.execute(
            "INSERT INTO node_watch_peers(node_id,status,incident_open,created_at,updated_at)"
            " VALUES(?,?,0,?,?)",
            ("kanata", STATUS_ONLINE, time.time(), time.time()),
        )
        s = self.svc.overview_summary()
        self.assertEqual(s["level"], "ok")
        self.assertEqual(s["online"], 1)
        self.svc.db.execute(
            "UPDATE node_watch_peers SET status=?, incident_open=1 WHERE node_id=?",
            (STATUS_DOWN, "kanata"),
        )
        s = self.svc.overview_summary()
        self.assertEqual(s["level"], "bad")
        self.assertEqual(s["down"], 1)

    def test_overview_sender_without_local_peers(self):
        send = NodeWatchService(
            self.db,
            config={
                "send": {
                    "enabled": True,
                    "node_id": "kanata",
                    "target_url": "http://yomi:6200/api/node-watch/heartbeat",
                    "interval_sec": 15,
                },
                "recv": {"enabled": False},
            },
        )
        s = send.overview_summary()
        self.assertEqual(s["level"], "warn")  # 尚未发送
        self.assertEqual(s["send_target"], "http://yomi:6200/api/node-watch/heartbeat")
        send._last_send = {"ok": True, "status": 200, "at": time.time()}
        s = send.overview_summary()
        self.assertEqual(s["level"], "ok")
        self.assertTrue(s["last_send"]["ok"])
        send._last_send = {"ok": False, "status": 400, "at": time.time()}
        s = send.overview_summary()
        self.assertEqual(s["level"], "bad")


class TestSecurity(unittest.TestCase):
    def test_safe_heartbeat_url(self):
        self.assertEqual(
            _safe_heartbeat_url("https://example.com:6200/api/node-watch/heartbeat"),
            "https://example.com:6200/api/node-watch/heartbeat",
        )
        with self.assertRaises(ValueError):
            _safe_heartbeat_url("file:///etc/passwd")
        with self.assertRaises(ValueError):
            _safe_heartbeat_url("http://user:pass@host/hb")
        with self.assertRaises(ValueError):
            _safe_heartbeat_url("not-a-url")

    def test_invite_ttl_clamped(self):
        tmp = tempfile.TemporaryDirectory()
        db = Database(str(Path(tmp.name) / "t.db"))
        svc = NodeWatchService(db, config={"send": {}, "recv": {}})
        gen = svc.generate_invite(
            node_id="kanata",
            url="http://203.0.113.50/hb",
            ttl_sec=999999,
        )
        self.assertTrue(gen["ok"], gen)
        self.assertLessEqual(gen["ttl_sec"], 3600)
        gen2 = svc.generate_invite(
            node_id="kanata",
            url="http://203.0.113.50/hb",
            ttl_sec=1,
        )
        self.assertGreaterEqual(gen2["ttl_sec"], 30)
        bad = svc.generate_invite(node_id="k", url="file:///etc/passwd")
        self.assertFalse(bad["ok"])
        db.close()
        tmp.cleanup()


class TestNotify(unittest.TestCase):
    def test_notify_enqueue_keyword_args(self):
        class FakeNotifier:
            def __init__(self):
                self.calls = []

            def enqueue(self, **kwargs):
                self.calls.append(kwargs)
                return True

        class FakeStore:
            def get_meta(self, channel_id):
                return {
                    "id": channel_id,
                    "kind": "wecom_aibot",
                    "config": {"targets": ["wrh_xyz"]},
                }

        tmp = tempfile.TemporaryDirectory()
        db = Database(str(Path(tmp.name) / "t.db"))
        notifier = FakeNotifier()
        store = FakeStore()
        svc = NodeWatchService(
            db,
            config={
                "send": {},
                "recv": {"enabled": True, "alert_channel_id": "nch_1"},
            },
            notifier=notifier,
            channel_store=store,
        )
        svc._notify("[节点守望] kanata 疑似失联")
        self.assertEqual(len(notifier.calls), 1)
        call = notifier.calls[0]
        self.assertIn("dedup_key", call)
        self.assertEqual(call["target"], "wrh_xyz")
        self.assertEqual(call["channel"], "wecom_aibot")
        self.assertEqual(call["channel_id"], "nch_1")
        self.assertIn("疑似失联", call["body"])
        db.close()
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
