"""Exercise the provider adapter against a local HTTP server, without credentials."""
from __future__ import annotations

import asyncio
import unittest

from aiohttp import web
from aiohttp.test_utils import TestServer

from ayana.llm import LLMClient


class LLMTransportTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.requests = []
        self.status = 200
        self.delay = 0
        self.response = {"choices": [{"message": {"content": '{"fields":{}}'}, "finish_reason": "stop"}]}
        self.raw_response = None

        async def handler(request):
            self.requests.append({"body": await request.json(), "authorization": request.headers.get("Authorization")})
            if self.delay:
                await asyncio.sleep(self.delay)
            if self.raw_response is not None:
                return web.Response(text=self.raw_response, status=self.status)
            return web.json_response(self.response, status=self.status)

        app = web.Application()
        app.router.add_post("/v1/chat/completions", handler)
        self.server = TestServer(app)
        await self.server.start_server()
        self.client = LLMClient("placeholder-test-key", str(self.server.make_url("/v1")), "test-model", timeout=1)

    async def asyncTearDown(self):
        await self.server.close()

    async def test_json_request_uses_real_provider_contract_and_preserves_finish_reason(self):
        self.response["choices"][0]["finish_reason"] = "length"
        messages = [{"role": "user", "content": "监控网站服务"}]
        result = await self.client.chat_raw(messages, max_tokens=1600, json_mode=True, temperature=0.1)
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["finish_reason"], "length")
        self.assertEqual(result["content"], '{"fields":{}}')
        body = self.requests[0]["body"]
        self.assertEqual(body["messages"], messages)
        self.assertEqual(body["model"], "test-model")
        self.assertEqual(body["max_tokens"], 1600)
        self.assertEqual(body["response_format"], {"type": "json_object"})
        self.assertEqual(self.requests[0]["authorization"], "Bearer placeholder-test-key")

    async def test_http_failure_is_classified_without_logging_provider_body(self):
        self.status = 401
        self.raw_response = "sensitive-provider-response-do-not-log"
        with self.assertLogs("ayana.llm", level="WARNING") as logs:
            result = await self.client.chat_raw([])
        self.assertEqual(result["error"], "llm_http_error")
        self.assertEqual(result["status"], 401)
        self.assertIsNone(result["content"])
        self.assertNotIn(self.raw_response, " ".join(logs.output))
        self.assertIsNone(await self.client.chat([]))

    async def test_invalid_json_response_is_classified(self):
        self.raw_response = "a provider gateway page"
        result = await self.client.chat_raw([])
        self.assertEqual(result["error"], "llm_response_format")
        self.assertIsNone(result["content"])

    async def test_invalid_choice_shape_is_classified(self):
        for response in ({}, [], {"choices": []}, {"choices": {}}, {"choices": ["text"]}):
            with self.subTest(response=response):
                self.response = response
                result = await self.client.chat_raw([])
                self.assertEqual(result["error"], "llm_response_format")
                self.assertIsNone(result["content"])

    async def test_timeout_classification_is_available_to_assistant(self):
        self.delay = 0.08
        self.client.timeout = 0.01
        result = await self.client.chat_raw([])
        self.assertEqual(result["error"], "llm_timeout")
        self.assertIsNone(result["content"])

    async def test_disabled_provider_makes_no_http_request(self):
        self.client.api_key = ""
        result = await self.client.chat_raw([])
        self.assertEqual(result["error"], "llm_disabled")
        self.assertIsNone(result["content"])
        self.assertEqual(self.requests, [])


if __name__ == "__main__":
    unittest.main()
