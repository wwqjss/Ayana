"""Smoke test: inject fake /ping event into Ops Agent WS and capture reply."""
import asyncio
import json
import sys

import aiohttp


async def test() -> int:
    url = "ws://127.0.0.1:6199/ws"
    headers = {"Authorization": "Bearer REDACTED-ONBOT-TOKEN"}
    async with aiohttp.ClientSession() as s:
        async with s.ws_connect(url, headers=headers) as ws:
            event = {
                "time": 1728000000,
                "self_id": REDACTED-ADMIN-QQ,
                "post_type": "message",
                "message_type": "private",
                "sub_type": "friend",
                "message_id": 999,
                "user_id": 3314622154,
                "message": [{"type": "text", "data": {"text": "/ping"}}],
                "raw_message": "/ping",
                "font": 0,
                "sender": {"user_id": 3314622154, "nickname": "test", "role": "friend"},
            }
            await ws.send_str(json.dumps(event, ensure_ascii=False))
            try:
                msg = await asyncio.wait_for(ws.receive(), timeout=5)
                print("REPLY:", msg.data)
                return 0
            except asyncio.TimeoutError:
                print("TIMEOUT: no reply")
                return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(test()))
