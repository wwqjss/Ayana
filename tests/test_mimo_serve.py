"""mimo_serve：事件转译与客户端请求形状。"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.mimo_serve import translate_event, MimoServeClient  # noqa: E402


class TranslateEventTests(unittest.TestCase):
    def test_session_status(self):
        t = translate_event({
            "type": "session.status",
            "properties": {"sessionID": "ses_1", "status": {"type": "busy"}},
        })
        self.assertEqual(t["kind"], "status")
        self.assertEqual(t["status"], "busy")
        self.assertEqual(t["session_id"], "ses_1")

    def test_message_part_delta(self):
        t = translate_event({
            "type": "message.part.delta",
            "properties": {
                "sessionID": "ses_1",
                "partID": "prt_1",
                "messageID": "msg_1",
                "field": "text",
                "delta": "pong",
            },
        })
        self.assertEqual(t["kind"], "delta")
        self.assertEqual(t["delta"], "pong")

    def test_message_part_updated_tool(self):
        t = translate_event({
            "type": "message.part.updated",
            "properties": {
                "sessionID": "ses_1",
                "part": {
                    "id": "prt_2",
                    "messageID": "msg_2",
                    "type": "tool",
                    "tool": "host.exec",
                    "text": "uptime",
                    "state": {"status": "completed"},
                },
            },
        })
        self.assertEqual(t["kind"], "part")
        self.assertEqual(t["part_type"], "tool")
        self.assertEqual(t["tool"], "host.exec")

    def test_session_updated_title(self):
        t = translate_event({
            "type": "session.updated",
            "properties": {
                "sessionID": "ses_1",
                "info": {"title": "mysql 抖动", "time": {"updated": 123}},
            },
        })
        self.assertEqual(t["kind"], "session_updated")
        self.assertEqual(t["title"], "mysql 抖动")

    def test_unknown_passthrough(self):
        t = translate_event({"type": "something.else", "properties": {"sessionID": "s"}})
        self.assertEqual(t["kind"], "raw")


class ClientShapeTests(unittest.TestCase):
    def test_headers_basic_auth(self):
        import base64

        c = MimoServeClient(base_url="http://127.0.0.1:1", username="mimocode", password="pw")
        h = c._headers()
        expect = "Basic " + base64.b64encode(b"mimocode:pw").decode()
        self.assertEqual(h["Authorization"], expect)

    def test_base_url_strip(self):
        c = MimoServeClient(base_url="http://127.0.0.1:6290/")
        self.assertEqual(c.base_url, "http://127.0.0.1:6290")


if __name__ == "__main__":
    unittest.main()
