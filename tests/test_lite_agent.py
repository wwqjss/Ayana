"""Headless loop/transport contracts; never contact a real provider or host."""
from __future__ import annotations

import asyncio
import copy
import json
import unittest

from aiohttp import web
from aiohttp.test_utils import TestServer

from ayana.lite_agent import LiteAgentRunner, LiteLLMClient
from ayana.llm import LLMClient


READ = {"name": "asset.get", "description": "Read one asset", "inputSchema": {
    "type": "object", "properties": {"asset_id": {"type": "string", "minLength": 1}},
    "required": ["asset_id"], "additionalProperties": False,
}}
WRITE = {"name": "host.exec", "description": "Execute through the trusted ledger", "inputSchema": {
    "type": "object", "properties": {"command": {"type": "string"},
                                      "channel": {"type": "string", "enum": ["read", "write"]}},
    "required": ["command"], "additionalProperties": False,
}}


def request(name="ayana_asset_get", args=None, ident="call_1", **extra):
    return {"id": ident, "type": "function", "function": {
        "name": name, "arguments": json.dumps(args if args is not None else {"asset_id": "host-1"}),
    }, **extra}


def turn(*calls, content=None, finish_reason="tool_calls", **extra):
    return {"message": {"role": "assistant", "content": content, "tool_calls": list(calls), **extra},
            "finish_reason": finish_reason}


def final(**fields):
    return turn(content=json.dumps({"status": "completed", "facts": [], "hypotheses": [],
                                    "unconfirmed": [], "next_steps": [], **fields}), finish_reason="stop")


class FakeClient:
    api_key = "test-provider-secret"

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    async def chat_tools(self, messages, **kwargs):
        self.requests.append(copy.deepcopy({"messages": messages, **kwargs}))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class LiteAgentRunnerTests(unittest.IsolatedAsyncioTestCase):
    async def run_agent(self, client, *, specs=None, callback=None, active=None, **budgets):
        self.dispatched = []
        self.events = []

        async def dispatch(name, args):
            self.dispatched.append((name, args))
            if callback:
                return await callback(name, args)
            return {"ok": True, "asset": args.get("asset_id", "host-1")}

        runner = LiteAgentRunner(client, **budgets)
        result = await runner.run("Investigate this incident", tools=[READ] if specs is None else specs,
                                  call_tool=dispatch, check_active=active or (lambda: None),
                                  on_event=lambda kind, payload: self.events.append((kind, payload)))
        return result

    async def test_raw_mcp_aliases_and_real_results_are_used_in_followup(self):
        client = FakeClient(turn(request()), final())
        result = await self.run_agent(client, max_tokens=87)
        self.assertEqual(self.dispatched, [("asset.get", {"asset_id": "host-1"})])
        self.assertEqual(client.requests[0]["tools"][0]["function"]["name"], "ayana_asset_get")
        self.assertEqual(client.requests[0]["max_tokens"], 87)
        feedback = client.requests[1]["messages"][-1]
        self.assertEqual(feedback["tool_call_id"], "call_1")
        self.assertEqual(json.loads(feedback["content"])["asset"], "host-1")
        self.assertEqual(result["lite_agent"], {"rounds": 2, "tool_calls": 1, "stop_reason": "completed"})

    async def test_openai_tools_keep_their_explicit_names(self):
        spec = {"type": "function", "function": {"name": "read_host", "parameters": READ["inputSchema"]}}
        client = FakeClient(turn(request("read_host")), final())
        await self.run_agent(client, specs=[spec])
        self.assertEqual(self.dispatched[0][0], "read_host")

    async def test_current_ayana_specs_are_accepted_without_an_extra_registry(self):
        from ayana.mcp_tools import TOOL_SPECS
        client = FakeClient(final())
        await self.run_agent(client, specs=TOOL_SPECS)
        self.assertEqual(len(client.requests[0]["tools"]), len(TOOL_SPECS))

    async def test_tool_batch_executes_serially_in_model_order(self):
        sequence = []

        async def dispatch(name, args):
            sequence.append("start:" + args["asset_id"])
            await asyncio.sleep(0)
            sequence.append("end:" + args["asset_id"])
            return {"ok": True}

        client = FakeClient(turn(request(args={"asset_id": "a"}),
                                      request(args={"asset_id": "b"}, ident="call_2")), final())
        await self.run_agent(client, callback=dispatch)
        self.assertEqual(sequence, ["start:a", "end:a", "start:b", "end:b"])

    async def test_no_tools_are_added_to_the_supplied_allowlist(self):
        client = FakeClient(turn(request("ayana_host_exec", {"command": "anything"})), final())
        await self.run_agent(client)
        self.assertEqual(self.dispatched, [])
        feedback = json.loads(client.requests[1]["messages"][-1]["content"])
        self.assertEqual(feedback["error"], "tool_not_available")
        self.assertFalse(feedback["executed"])

    async def test_invalid_arguments_are_not_dispatched_and_can_be_corrected(self):
        for arguments in ('{"asset_id":""}', '{"asset_id":"x","extra":1}',
                          '{"asset_id":3}', '[]', '{"asset_id":"x","asset_id":"y"}',
                          '{"asset_id":NaN}', '{"asset_id":1e309}', '{'):
            with self.subTest(arguments=arguments):
                invalid = request()
                invalid["function"]["arguments"] = arguments
                client = FakeClient(turn(invalid), turn(request(ident="call_2")), final())
                await self.run_agent(client)
                self.assertEqual(len(self.dispatched), 1)
                self.assertEqual(self.dispatched[0][1], {"asset_id": "host-1"})

    async def test_schema_bounds_arrays_and_boolean_integer_distinction(self):
        spec = {"name": "query", "inputSchema": {"type": "object", "required": ["n", "flags"],
            "properties": {"n": {"type": "integer", "minimum": 1, "maximum": 3},
                           "flags": {"type": "array", "minItems": 1, "maxItems": 2,
                                     "items": {"type": "boolean"}}}}}
        for args in ({"n": True, "flags": [True]}, {"n": 4, "flags": [True]},
                     {"n": 2, "flags": []}, {"n": 2, "flags": [1]}):
            with self.subTest(args=args):
                client = FakeClient(turn(request("ayana_query", args)), final())
                await self.run_agent(client, specs=[spec])
                self.assertEqual(self.dispatched, [])

    async def test_third_identical_failure_is_blocked_even_with_different_call_ids(self):
        async def failed(name, args):
            return {"ok": False, "error": "host_missing"}

        client = FakeClient(*(turn(request(ident=f"call_{n}")) for n in range(1, 4)))
        result = await self.run_agent(client, callback=failed)
        self.assertEqual(len(self.dispatched), 2)
        self.assertEqual(result["lite_agent"]["stop_reason"], "repeated_tool_failure")

    async def test_unknown_write_stops_without_followup_model_or_next_batch_tool(self):
        results = [{"ok": False, "exec_state": "unknown"}, {"ok": False, "detail": {"status": "unknown"}},
                   {"ok": False, "claim": {"status": "claimed"}}, {"ok": False, "error": "exec_error"},
                   {"ok": False, "error": "claim_failed"}, {"ok": False, "timed_out": True}]
        for tool_result in results:
            with self.subTest(result=tool_result):
                async def dispatch(name, args):
                    return tool_result

                client = FakeClient(turn(request("ayana_host_exec", {"command": "restart"}),
                                              request(ident="call_2")))
                result = await self.run_agent(client, specs=[READ, WRITE], callback=dispatch)
                self.assertEqual(len(self.dispatched), 1)
                self.assertEqual(len(client.requests), 1)
                self.assertEqual(result["status"], "partial")
                self.assertEqual(result["lite_agent"]["stop_reason"], "tool_result_unknown")

    async def test_read_unknown_observation_is_not_mistaken_for_unknown_write(self):
        async def dispatch(name, args):
            return {"ok": True, "status": "unknown"}

        client = FakeClient(turn(request("ayana_host_exec", {"command": "inspect", "channel": "read"})), final())
        result = await self.run_agent(client, specs=[WRITE], callback=dispatch)
        self.assertEqual(result["lite_agent"]["stop_reason"], "completed")

    async def test_explicit_pre_dispatch_rejection_can_be_corrected(self):
        async def dispatch(name, args):
            return {"ok": False, "error": "exec_error", "executed": False}

        client = FakeClient(turn(request("ayana_host_exec", {"command": "restart"})), final(status="partial"))
        result = await self.run_agent(client, specs=[WRITE], callback=dispatch)
        self.assertEqual(len(client.requests), 2)
        self.assertEqual(result["status"], "partial")

    async def test_unclassified_write_exception_is_unknown_and_sanitized(self):
        async def dispatch(name, args):
            raise RuntimeError("sensitive key test-provider-secret")

        client = FakeClient(turn(request("ayana_host_exec", {"command": "restart"})))
        result = await self.run_agent(client, specs=[WRITE], callback=dispatch)
        self.assertEqual(result["lite_agent"]["stop_reason"], "tool_result_unknown")
        self.assertNotIn("sensitive", json.dumps([result, self.events]))

    async def test_round_call_and_context_budgets_stop_safely(self):
        client = FakeClient(turn(request()))
        result = await self.run_agent(client, max_rounds=1)
        self.assertEqual(result["lite_agent"]["stop_reason"], "round_budget_exhausted")
        client = FakeClient(turn(request(), request(ident="call_2")))
        result = await self.run_agent(client, max_tool_calls=1)
        self.assertEqual(result["lite_agent"]["stop_reason"], "tool_budget_exhausted")
        self.assertEqual(self.dispatched, [])
        client = FakeClient(final())
        result = await self.run_agent(client, max_context_chars=10)
        self.assertEqual(result["lite_agent"]["stop_reason"], "context_budget_exhausted")
        self.assertEqual(client.requests, [])

    async def test_context_growth_stops_instead_of_dropping_prior_tool_facts(self):
        async def dispatch(name, args):
            return {"ok": True, "output": "evidence" * 2000}

        client = FakeClient(turn(request()))
        result = await self.run_agent(client, callback=dispatch, max_context_chars=5000)
        self.assertEqual(result["lite_agent"]["stop_reason"], "context_budget_exhausted")
        self.assertEqual(len(client.requests), 1)

    async def test_large_result_is_explicitly_marked_truncated(self):
        async def dispatch(name, args):
            return {"ok": True, "output": "x" * 18000}

        client = FakeClient(turn(request()), final())
        await self.run_agent(client, callback=dispatch)
        feedback = json.loads(client.requests[1]["messages"][-1]["content"])
        self.assertTrue(feedback["truncated"])
        self.assertTrue(feedback["original_ok"])

    async def test_reasoning_is_preserved_for_provider_but_never_in_events_or_conclusion(self):
        client = FakeClient(turn(request(), reasoning_content="private model reasoning"), final())
        result = await self.run_agent(client)
        self.assertEqual(client.requests[1]["messages"][-2]["reasoning_content"], "private model reasoning")
        self.assertNotIn("private model reasoning", json.dumps([result, self.events]))

    async def test_model_recovery_claim_never_becomes_verified(self):
        client = FakeClient(final(verified_recovered=True, reasoning_content="private reasoning"))
        result = await self.run_agent(client)
        self.assertFalse(result["verified_recovered"])
        self.assertNotIn("reasoning_content", result)

    async def test_truncated_or_filtered_response_never_dispatches_tools(self):
        for reason in ("length", "max_tokens", "content_filter", "unknown"):
            with self.subTest(reason=reason):
                result = await self.run_agent(FakeClient(turn(request(), finish_reason=reason)))
                self.assertEqual(self.dispatched, [])
                self.assertEqual(result["status"], "partial")

    async def test_duplicate_ids_in_batch_and_previous_turn_are_rejected(self):
        result = await self.run_agent(FakeClient(turn(request(), request())))
        self.assertEqual(self.dispatched, [])
        self.assertEqual(result["lite_agent"]["stop_reason"], "llm_response_format")
        client = FakeClient(turn(request()), turn(request()))
        result = await self.run_agent(client)
        self.assertEqual(len(self.dispatched), 1)
        self.assertEqual(result["lite_agent"]["stop_reason"], "llm_response_format")

    async def test_cancellation_propagates_from_model_and_tool(self):
        with self.assertRaises(asyncio.CancelledError):
            await self.run_agent(FakeClient(asyncio.CancelledError()))

        async def dispatch(name, args):
            raise asyncio.CancelledError()

        with self.assertRaises(asyncio.CancelledError):
            await self.run_agent(FakeClient(turn(request())), callback=dispatch)

    async def test_active_guard_runs_after_tool_before_next_batch_dispatch(self):
        stopped = False

        def guard():
            if stopped:
                raise RuntimeError("task cancelled")

        async def dispatch(name, args):
            nonlocal stopped
            stopped = True
            return {"ok": True}

        with self.assertRaisesRegex(RuntimeError, "task cancelled"):
            await self.run_agent(FakeClient(turn(request(), request(ident="call_2"))), callback=dispatch, active=guard)
        self.assertEqual(len(self.dispatched), 1)

    async def test_bad_conclusion_and_provider_errors_are_sanitized(self):
        for response in (final(status=[]), final(facts="bad"), final(hypotheses=["bad"]),
                         turn(content="not structured", finish_reason="stop"),
                         {"error": {"message": "test-provider-secret"}},
                         RuntimeError("test-provider-secret")):
            with self.subTest(response=response):
                result = await self.run_agent(FakeClient(response))
                self.assertEqual(result["status"], "partial")
                self.assertNotIn("test-provider-secret", json.dumps([result, self.events]))

    async def test_provider_key_is_redacted_from_tool_feedback_and_final_result(self):
        async def dispatch(name, args):
            return {"ok": True, "output": "test-provider-secret"}

        client = FakeClient(turn(request()), final(symptoms="test-provider-secret"))
        result = await self.run_agent(client, callback=dispatch)
        self.assertNotIn("test-provider-secret", client.requests[1]["messages"][-1]["content"])
        self.assertEqual(result["symptoms"], "[redacted]")

    async def test_plain_llm_client_is_adapted_without_mutating_it(self):
        client = LLMClient("key", "https://example.com/v1", "model", secure_network=True)
        runner = LiteAgentRunner(client)
        self.assertIsInstance(runner.client, LiteLLMClient)
        self.assertTrue(runner.client.secure_network)
        self.assertFalse(hasattr(client, "chat_tools"))


class LiteTransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.requests = []
        self.status = 200
        self.body = {"choices": [{"message": {"content": None, "tool_calls": [request()],
                                               "reasoning_content": "provider-only reasoning"},
                                  "finish_reason": "tool_calls"}]}
        self.headers = {}
        self.raw = None
        self.delay = 0

        async def handler(request):
            self.requests.append({"body": await request.json(), "authorization": request.headers.get("Authorization")})
            if self.delay:
                await asyncio.sleep(self.delay)
            if self.raw is not None:
                return web.Response(text=self.raw, status=self.status, headers=self.headers)
            return web.json_response(self.body, status=self.status, headers=self.headers)

        app = web.Application()
        app.router.add_post("/v1/chat/completions", handler)
        self.server = TestServer(app)
        await self.server.start_server()
        self.client = LiteLLMClient("local-test-secret", str(self.server.make_url("/v1")), "test-model", timeout=1)

    async def asyncTearDown(self):
        await self.server.close()

    async def test_function_call_request_and_response_preserve_standard_contract(self):
        tools = [{"type": "function", "function": {"name": "test", "parameters": {"type": "object"}}}]
        result = await self.client.chat_tools([{"role": "user", "content": "test"}], tools=tools, max_tokens=71)
        self.assertEqual(result["finish_reason"], "tool_calls")
        self.assertEqual(result["message"]["tool_calls"], [request()])
        self.assertEqual(result["message"]["reasoning_content"], "provider-only reasoning")
        self.assertEqual(self.requests[0]["body"]["tools"], tools)
        self.assertEqual(self.requests[0]["body"]["max_tokens"], 71)
        self.assertEqual(self.requests[0]["authorization"], "Bearer local-test-secret")

    async def test_http_errors_do_not_return_or_log_provider_body(self):
        for status, body, expected in (
            (401, {"error": {"message": "local-test-secret"}}, "llm_http_error"),
            (429, {"error": {"message": "local-test-secret"}}, "llm_rate_limited"),
            (400, {"error": {"code": "context_length_exceeded", "message": "local-test-secret"}}, "llm_context_limit"),
        ):
            self.status, self.body = status, body
            result = await self.client.chat_tools([], tools=[])
            self.assertEqual(result["error"], expected)
            self.assertNotIn("local-test-secret", json.dumps(result))

    async def test_redirect_is_never_followed(self):
        self.status = 307
        self.headers = {"Location": "/v1/chat/completions"}
        result = await self.client.chat_tools([], tools=[])
        self.assertEqual(result["error"], "llm_http_error")
        self.assertEqual(len(self.requests), 1)

    async def test_invalid_response_and_timeout_are_categorized(self):
        self.raw = "sensitive gateway error"
        result = await self.client.chat_tools([], tools=[])
        self.assertEqual(result["error"], "llm_response_format")
        self.raw = None
        self.delay = 0.05
        self.client.timeout = 0.001
        result = await self.client.chat_tools([], tools=[])
        self.assertEqual(result["error"], "llm_timeout")

    async def test_secure_network_and_disabled_provider_make_no_request(self):
        self.client.secure_network = True
        result = await self.client.chat_tools([], tools=[])
        self.assertEqual(result["error"], "llm_blocked_endpoint")
        self.client.api_key = ""
        result = await self.client.chat_tools([], tools=[])
        self.assertEqual(result["error"], "llm_disabled")
        self.assertEqual(self.requests, [])


if __name__ == "__main__":
    unittest.main()
