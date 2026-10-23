"""Role-scoped AI clients and a persistent, conservative spend ledger.

This module has no SSH, Policy, Action or voting authority.  Costs calculated
from provider usage and configured prices are estimates, never account charges.
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import ipaddress
import json
import math
import os
from typing import Any, Callable
from urllib.parse import urlsplit

from .credentials import _decrypt, _encrypt
from .db import Database, new_id, now
from .llm import LLMClient
from .transport import is_blocked_ssrf_host

ROLES = ("planner", "reviewer_kimi", "reviewer_deepseek")
ROLE_PROVIDERS = {"planner": "mimo", "reviewer_kimi": "kimi", "reviewer_deepseek": "deepseek"}
JSON_CONTRACT = (
    "\nOutput contract: return exactly one valid JSON object. Quote all property names and string values "
    "with double quotes; use JSON true/false/null. No Markdown fences, comments, explanation outside "
    "the object, trailing commas, nonfinite numbers, or duplicate property names."
)
MODEL_SOURCES = {
    "kimi": "https://platform.kimi.com/docs/get-api-key",
    "deepseek": "https://api-docs.deepseek.com/quick_start/pricing/",
    "mimo": "https://platform.xiaomimimo.com/",
}
DEFAULT_CONFIG = {
    "enabled": False, "budget_cny": 100.0, "warning_ratio": 0.8,
    "max_calls_per_incident": 60, "max_calls_per_generation": 30,
    "roles": {
        "planner": {"provider": "mimo", "base_url": "https://api.xiaomimimo.com/v1", "model": "mimo-v2.6-pro"},
        "reviewer_kimi": {"provider": "kimi", "base_url": "https://api.moonshot.cn/v1", "model": "kimi-k2.6"},
        "reviewer_deepseek": {"provider": "deepseek", "base_url": "https://api.deepseek.com", "model": "deepseek-v4-pro"},
    },
}
for _role in DEFAULT_CONFIG["roles"].values():
    _role.update(timeout=60.0, retries=0, input_cny_per_million=None, output_cny_per_million=None)


class ProviderError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _finite_number(value: Any, low: float, high: float) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and low <= value <= high


def _strict_object(content: str) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    result = json.loads(content, object_pairs_hook=unique,
                        parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite")))
    if not isinstance(result, dict):
        raise ValueError("object required")
    return result


class ProviderRegistry:
    """Runtime settings are admin-controlled; consumers only receive role clients.

    ``update_config`` is synchronous and raises ProviderError (a ValueError).
    The injected client factory is for local fault-injection tests only.
    """
    def __init__(self, db: Database, cfg: dict | None = None, *, client_factory: Callable | None = None):
        self.db = db
        self.cfg = cfg or {}
        self._allow_test_urls = client_factory is not None
        self._client_factory = client_factory or (lambda *a, **kw: LLMClient(*a, **kw, secure_network=True))
        self._master_key = (self.cfg.get("ai_credential_key") or os.environ.get("AYANA_AI_CREDENTIAL_KEY")
                            or self.cfg.get("ssh_credential_key") or os.environ.get("AYANA_SSH_CREDENTIAL_KEY", ""))
        self.ensure_schema()
        settings = copy.deepcopy(DEFAULT_CONFIG)
        self._merge(settings, self.cfg.get("autonomous_agent", {}))
        stored = self.db.query_one("SELECT value_json FROM ai_provider_config WHERE id=1")
        if stored:
            self._merge(settings, json.loads(stored["value_json"]))
        self._validate(settings, allow_test_urls=self._allow_test_urls)
        self._settings = settings

    def ensure_schema(self) -> None:
        statements = (
            "CREATE TABLE IF NOT EXISTS ai_provider_config (id INTEGER PRIMARY KEY CHECK(id=1), value_json TEXT NOT NULL, updated_at REAL NOT NULL)",
            "CREATE TABLE IF NOT EXISTS ai_provider_keys (role TEXT PRIMARY KEY, secret_enc BLOB NOT NULL, updated_at REAL NOT NULL)",
            "CREATE TABLE IF NOT EXISTS ai_provider_verifications (role TEXT PRIMARY KEY, config_digest TEXT NOT NULL, verified_at REAL NOT NULL, ok INTEGER NOT NULL, error TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS ai_calls (id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, generation INTEGER NOT NULL, role TEXT NOT NULL, provider TEXT NOT NULL, model TEXT NOT NULL, purpose TEXT NOT NULL DEFAULT '', started_at REAL NOT NULL, finished_at REAL, status TEXT NOT NULL, error TEXT NOT NULL DEFAULT '', input_tokens INTEGER, output_tokens INTEGER, cost_cny REAL, reserved_cny REAL NOT NULL DEFAULT 0, input_price REAL, output_price REAL, account_charge_cny REAL, config_digest TEXT NOT NULL DEFAULT '')",
            "CREATE INDEX IF NOT EXISTS idx_ai_calls_incident ON ai_calls(incident_id,generation)",
        )
        with self.db.tx() as conn:
            for sql in statements:
                conn.execute(sql)
            if "config_digest" not in {r["name"] for r in conn.execute("PRAGMA table_info(ai_calls)")}:
                conn.execute("ALTER TABLE ai_calls ADD COLUMN config_digest TEXT NOT NULL DEFAULT ''")

    @staticmethod
    def _merge(target: dict, patch: dict) -> None:
        if not isinstance(patch, dict):
            raise ProviderError("invalid_config")
        for key, value in patch.items():
            if isinstance(value, dict) and isinstance(target.get(key), dict):
                ProviderRegistry._merge(target[key], value)
            else:
                target[key] = copy.deepcopy(value)

    @staticmethod
    def _validate(settings: dict, *, allow_test_urls: bool = False) -> None:
        allowed = set(DEFAULT_CONFIG)
        if set(settings) != allowed or type(settings["enabled"]) is not bool:
            raise ProviderError("invalid_config")
        if not _finite_number(settings["budget_cny"], 0, 1_000_000):
            raise ProviderError("invalid_budget")
        if not _finite_number(settings["warning_ratio"], 0.01, 1):
            raise ProviderError("invalid_warning_ratio")
        for key in ("max_calls_per_incident", "max_calls_per_generation"):
            if type(settings[key]) is not int or not 1 <= settings[key] <= 1000:
                raise ProviderError("invalid_call_limit")
        if not isinstance(settings["roles"], dict) or set(settings["roles"]) != set(ROLES):
            raise ProviderError("invalid_roles")
        role_fields = set(DEFAULT_CONFIG["roles"]["planner"])
        for role, value in settings["roles"].items():
            if not isinstance(value, dict) or set(value) != role_fields or value["provider"] != ROLE_PROVIDERS[role]:
                raise ProviderError("invalid_role_config")
            if not isinstance(value["base_url"], str) or len(value["base_url"]) > 512:
                raise ProviderError("invalid_base_url")
            url = urlsplit(value["base_url"])
            test_endpoint = allow_test_urls and url.hostname in ("localhost", "127.0.0.1", "::1")
            if (url.scheme not in ("https", "http") or not url.hostname or url.username or url.password
                    or url.query or url.fragment or (url.scheme == "http" and not test_endpoint)
                    or (is_blocked_ssrf_host(url.hostname, purpose="webhook") and not test_endpoint)):
                raise ProviderError("invalid_base_url")
            try:
                if not ipaddress.ip_address(url.hostname).is_global and not test_endpoint:
                    raise ProviderError("invalid_base_url")
            except ValueError as exc:
                if isinstance(exc, ProviderError):
                    raise
            if not isinstance(value["model"], str) or not value["model"].strip() or len(value["model"]) > 150:
                raise ProviderError("invalid_model")
            if not _finite_number(value["timeout"], 0.01, 600):
                raise ProviderError("invalid_timeout")
            if type(value["retries"]) is not int or not 0 <= value["retries"] <= 2:
                raise ProviderError("invalid_retries")
            for price in ("input_cny_per_million", "output_cny_per_million"):
                if value[price] is not None and not _finite_number(value[price], 0, 1_000_000):
                    raise ProviderError("invalid_price")
        seats = []
        for role in ("reviewer_kimi", "reviewer_deepseek"):
            value = settings["roles"][role]
            parsed = urlsplit(value["base_url"])
            address = parsed._replace(scheme=parsed.scheme.lower(), netloc=parsed.netloc.lower(),
                                      path=parsed.path.rstrip("/")).geturl()
            seats.append((address, value["model"].strip().casefold()))
        if seats[0] == seats[1]:
            raise ProviderError("independent_reviewer_required")

    def _api_key(self, role: str) -> str:
        stored = self.db.query_one("SELECT secret_enc FROM ai_provider_keys WHERE role=?", (role,))
        if stored:
            if not self._master_key:
                raise ProviderError("missing_encryption_key")
            try:
                return _decrypt(self._master_key, bytes(stored["secret_enc"])).decode("utf-8")
            except Exception:
                raise ProviderError("credential_unavailable") from None
        key_name = f"ai_{role}_api_key"
        value = os.environ.get(f"AYANA_{key_name.upper()}") or self.cfg.get(key_name, "")
        return value if isinstance(value, str) else ""

    def client(self, role: str) -> LLMClient:
        if role not in ROLES:
            raise ProviderError("unknown_role")
        conf = self._settings["roles"][role]
        return self._client_factory(self._api_key(role), conf["base_url"], conf["model"], timeout=conf["timeout"])

    def public_config(self) -> dict:
        result = copy.deepcopy(self._settings)
        for role, value in result["roles"].items():
            key = ""
            try:
                key = self._api_key(role)
                value["key_configured"] = bool(key)
                value["credential_error"] = ""
            except ProviderError as exc:
                value["key_configured"] = False
                value["credential_error"] = exc.code
            digest = self._identity(value, key) if value["key_configured"] else ""
            verified = self.db.query_one("SELECT finished_at FROM ai_calls WHERE role=? AND config_digest=? AND config_digest<>''"
                                         " AND (status='succeeded' OR (status='usage_unknown' AND error='usage_missing'))"
                                         " ORDER BY finished_at DESC LIMIT 1", (role, digest))
            discovered = self.db.query_one("SELECT * FROM ai_provider_verifications WHERE role=? AND config_digest=?", (role, digest))
            newest_success = bool(verified and (not discovered or verified["finished_at"] > discovered["verified_at"]))
            value["account_verified"] = newest_success or bool(discovered and discovered["ok"])
            value["verification_error"] = discovered["error"] if discovered and not newest_success else ""
            value["model_source"] = MODEL_SOURCES[value["provider"]]
        return result

    def update_config(self, patch: dict, actor: str = "web") -> dict:
        if not isinstance(patch, dict):
            raise ProviderError("invalid_config")
        clean = copy.deepcopy(patch)
        secrets = {}
        roles = clean.get("roles", {})
        if not isinstance(roles, dict):
            raise ProviderError("invalid_roles")
        for role, value in roles.items():
            if role not in ROLES or not isinstance(value, dict):
                raise ProviderError("invalid_role_config")
            has_key = "api_key" in value
            secret = value.pop("api_key", "")
            clear = value.pop("clear_api_key", False)
            if type(clear) is not bool or not isinstance(secret, str) or len(secret) > 4096 or "\n" in secret or "\r" in secret:
                raise ProviderError("invalid_api_key")
            if clear and secret:
                raise ProviderError("conflicting_api_key")
            if clear or (has_key and secret):
                if not self._master_key:
                    raise ProviderError("missing_encryption_key")
                secrets[role] = _encrypt(self._master_key, ("" if clear else secret).encode("utf-8"))
        updated = copy.deepcopy(self._settings)
        self._merge(updated, clean)
        self._validate(updated, allow_test_urls=self._allow_test_urls)
        with self.db.tx() as conn:
            conn.execute("INSERT OR REPLACE INTO ai_provider_config(id,value_json,updated_at) VALUES(1,?,?)", (json.dumps(updated, ensure_ascii=False), now()))
            for role, encrypted in secrets.items():
                conn.execute("INSERT OR REPLACE INTO ai_provider_keys(role,secret_enc,updated_at) VALUES(?,?,?)", (role, encrypted, now()))
            self.db.audit("web_user", actor, "ai_provider_config_updated", detail={"fields": sorted(clean), "key_roles": sorted(secrets)}, channel="web")
        self._settings = updated
        return self.public_config()

    async def verify_account(self, role: str) -> dict:
        """Admin-triggered read-only /models; never invokes a paid completion."""
        if role not in ROLES:
            raise ProviderError("unknown_role")
        conf = copy.deepcopy(self._settings["roles"][role])
        try:
            key = self._api_key(role)
            if not key:
                return {"ok": False, "error": "provider_unconfigured", "role": role, "models": []}
            digest = self._identity(conf, key)
            client = self._client_factory(key, conf["base_url"], conf["model"], timeout=conf["timeout"])
            result = await client.list_models()
            models = result.get("models", []) if isinstance(result, dict) else []
            if not isinstance(models, list) or any(not isinstance(model, str) or len(model) > 150 for model in models):
                models = []
                result = {"ok": False, "error": "llm_response_format"}
            models = [model for model in models if key not in model]
            ok = result.get("ok") is True and conf["model"] in models
            known_errors = {"llm_disabled", "llm_http_error", "llm_timeout", "llm_connection_error", "llm_response_format", "llm_blocked_endpoint"}
            error = "" if ok else ("model_not_available" if result.get("ok") else result.get("error"))
            if error not in known_errors | {"", "model_not_available"}:
                error = "account_verification_failed"
            if not self._record_account_verification(role, conf, key, ok, error):
                return {"ok": False, "error": "provider_configuration_changed", "role": role, "models": []}
            return {"ok": ok, "error": error, "role": role, "model": conf["model"], "models": models[:200]}
        except ProviderError as exc:
            return {"ok": False, "error": exc.code, "role": role, "models": []}
        except asyncio.CancelledError:
            raise
        except Exception:
            return {"ok": False, "error": "account_verification_failed", "role": role, "models": []}

    def _record_account_verification(self, role: str, conf: dict, key: str, ok: bool, error: str) -> bool:
        digest = self._identity(conf, key)
        if self._identity(self._settings["roles"][role], self._api_key(role)) != digest:
            return False
        self.db.execute("INSERT OR REPLACE INTO ai_provider_verifications(role,config_digest,verified_at,ok,error) VALUES(?,?,?,?,?)",
                        (role, digest, now(), int(ok), error))
        return True

    @staticmethod
    def _identity(conf: dict, key: str) -> str:
        # Local identity marker invalidates account verification on key, endpoint
        # or model changes. Neither the marker nor the key is sent to the UI.
        return hashlib.sha256(json.dumps([conf["base_url"], conf["model"], key]).encode()).hexdigest()

    def _reserve(self, role: str, incident_id: str, generation: int, conf: dict, input_bound: int, max_tokens: int, purpose: str, identity: str = "") -> str:
        reserve = (input_bound * conf["input_cny_per_million"] + max_tokens * conf["output_cny_per_million"]) / 1_000_000
        call_id = new_id("aicall")
        with self.db.tx() as conn:
            if not conn.in_transaction:
                conn.execute("BEGIN IMMEDIATE")
            count = conn.execute("SELECT COUNT(*) n, SUM(CASE WHEN generation=? THEN 1 ELSE 0 END) gen FROM ai_calls WHERE incident_id=?", (generation, incident_id)).fetchone()
            if count["n"] >= self._settings["max_calls_per_incident"] or (count["gen"] or 0) >= self._settings["max_calls_per_generation"]:
                raise ProviderError("call_limit_exhausted")
            spend = conn.execute("SELECT COALESCE(SUM(COALESCE(cost_cny,0)+reserved_cny),0) n FROM ai_calls").fetchone()["n"]
            if spend + reserve > self._settings["budget_cny"]:
                raise ProviderError("budget_exhausted")
            conn.execute("INSERT INTO ai_calls(id,incident_id,generation,role,provider,model,purpose,started_at,status,reserved_cny,input_price,output_price,config_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                         (call_id, incident_id, generation, role, conf["provider"], conf["model"], purpose[:100], now(), "reserved", reserve, conf["input_cny_per_million"], conf["output_cny_per_million"], identity))
        return call_id

    def _finish(self, call_id: str, raw: dict | None, error: str = "") -> dict:
        usage = (raw or {}).get("raw", {}).get("usage") if isinstance((raw or {}).get("raw"), dict) else None
        tokens = None
        if isinstance(usage, dict):
            inp, out = usage.get("prompt_tokens"), usage.get("completion_tokens")
            if type(inp) is int and type(out) is int and 0 <= inp <= 100_000_000 and 0 <= out <= 100_000_000:
                tokens = (inp, out)
        with self.db.tx() as conn:
            row = conn.execute("SELECT * FROM ai_calls WHERE id=?", (call_id,)).fetchone()
            if tokens is not None:
                cost = (tokens[0] * row["input_price"] + tokens[1] * row["output_price"]) / 1_000_000
                conn.execute("UPDATE ai_calls SET status=?,error=?,finished_at=?,input_tokens=?,output_tokens=?,cost_cny=?,reserved_cny=0 WHERE id=?",
                             ("failed" if error else "succeeded", error, now(), *tokens, cost, call_id))
            else:
                cost = None
                conn.execute("UPDATE ai_calls SET status=?,error=?,finished_at=? WHERE id=?", ("usage_unknown", error or "usage_missing", now(), call_id))
        return {"usage": {"input_tokens": tokens[0], "output_tokens": tokens[1]} if tokens else None,
                "cost_cny": cost, "cost_basis": "provider_usage_configured_price" if tokens else "unknown", "account_charge_cny": None}

    def _request_gate(self, role: str, conf: dict, key: str) -> str:
        """A runtime stop/credential rotation also stops retries and stale output."""
        if not self._settings["enabled"]:
            return "agent_disabled"
        try:
            if self._settings["roles"][role] != conf or self._api_key(role) != key:
                return "provider_configuration_changed"
        except ProviderError as exc:
            return exc.code
        return ""

    async def call_json(self, role: str, messages: list[dict], *, incident_id: str, generation: int = 1, max_tokens: int = 1600, purpose: str = "") -> dict:
        """Strict JSON object result. Role-specific semantic schemas belong to callers.

        A retry consumes a separate ledger entry and reservation. A timeout can
        still have been billed, so its reservation is never silently released.
        """
        base = {"ok": False, "data": None, "call_id": None, "usage": None, "cost_cny": None}
        if role not in ROLES:
            return {**base, "error": "unknown_role"}
        if not self._settings["enabled"]:
            return {**base, "error": "agent_disabled"}
        if (not isinstance(incident_id, str) or not incident_id or type(generation) is not int or generation < 1
                or type(max_tokens) is not int or not 1 <= max_tokens <= 32768
                or not isinstance(messages, list) or not messages or len(messages) > 100
                or any(not isinstance(m, dict) or set(m) != {"role", "content"} or m["role"] not in ("system", "user", "assistant") or not isinstance(m["content"], str) for m in messages)):
            return {**base, "error": "invalid_request"}
        # Reinforce the transport's JSON mode with a syntactically valid output
        # contract, without changing caller-owned messages or weakening parsing.
        messages = [dict(message) for message in messages]
        for message in messages:
            if message["role"] == "system":
                message["content"] += JSON_CONTRACT
                break
        else:
            messages.insert(0, {"role": "system", "content": JSON_CONTRACT.lstrip()})
        encoded = json.dumps(messages, ensure_ascii=False).encode("utf-8")
        if len(encoded) > 500_000:
            return {**base, "error": "input_too_large"}
        conf = copy.deepcopy(self._settings["roles"][role])
        if conf["input_cny_per_million"] is None or conf["output_cny_per_million"] is None:
            return {**base, "error": "price_unknown"}
        try:
            key = self._api_key(role)
            client = self._client_factory(key, conf["base_url"], conf["model"], timeout=conf["timeout"])
            if not client.enabled:
                return {**base, "error": "provider_unconfigured"}
        except ProviderError as exc:
            return {**base, "error": exc.code}
        # UTF-8 byte count plus framing is deliberately a reservation bound,
        # never written as provider-reported token consumption.
        input_bound = len(encoded) + 64 * len(messages) + 64
        for attempt in range(conf["retries"] + 1):
            gate = self._request_gate(role, conf, key)
            if gate:
                return {**base, "error": gate}
            try:
                call_id = self._reserve(role, incident_id, generation, conf, input_bound, max_tokens, purpose,
                                        self._identity(conf, key))
            except ProviderError as exc:
                return {**base, "error": exc.code}
            raw = None
            error = ""
            data = None
            format_error = None
            try:
                raw = await client.chat_raw(messages, max_tokens=max_tokens, json_mode=True, temperature=1.0)
                if not isinstance(raw, dict):
                    error = "llm_response_format"
                elif raw.get("error"):
                    allowed = {"llm_disabled", "llm_http_error", "llm_timeout", "llm_connection_error", "llm_response_format", "llm_blocked_endpoint"}
                    error = raw["error"] if raw["error"] in allowed else "llm_call_failed"
                elif raw.get("finish_reason") != "stop" or not isinstance(raw.get("content"), str):
                    error = "llm_incomplete"
                else:
                    try:
                        data = _strict_object(raw["content"])
                    except (ValueError, TypeError, RecursionError) as exc:
                        error = "llm_invalid_json"
                        if isinstance(exc, json.JSONDecodeError):
                            format_error = {"category": "json_decode_error", "offset": exc.pos,
                                            "line": exc.lineno, "column": exc.colno}
                        else:
                            categories = {"duplicate key": "duplicate_key", "object required": "object_required",
                                          "nonfinite": "nonfinite_number"}
                            format_error = {"category": categories.get(str(exc), "invalid_json_structure")}
            except asyncio.CancelledError:
                self._finish(call_id, None, "call_cancelled")
                raise
            except Exception:
                error = "llm_call_failed"
            # Never persist model content, raw provider error bodies or secrets.
            result = {**base, "ok": not error, "data": data if not error else None,
                      "error": error, "call_id": call_id, **self._finish(call_id, raw if isinstance(raw, dict) else None, error)}
            if format_error:
                result["format_error"] = format_error
            if error == "llm_http_error" and isinstance(raw, dict) and raw.get("status") in (401, 403, 404):
                self._record_account_verification(role, conf, key, False, error)
            gate = self._request_gate(role, conf, key)
            if gate:
                return {**result, "ok": False, "data": None, "error": gate}
            if not error or error not in {"llm_timeout", "llm_connection_error", "llm_http_error", "llm_call_failed"} or attempt == conf["retries"]:
                return result
        return result

    def recover_inflight(self) -> int:
        """Call once at application startup, before starting model tasks.

        Interrupted paid requests remain unknown and retain their budget hold;
        this never replays a request or an Action.
        """
        return self.db.execute("UPDATE ai_calls SET status='interrupted_usage_unknown',error='process_interrupted',finished_at=? WHERE status='reserved'", (now(),)).rowcount

    def usage_summary(self, incident_id: str | None = None) -> dict:
        where = " WHERE incident_id=?" if incident_id else ""
        params = (incident_id,) if incident_id else ()
        rows = [dict(r) for r in self.db.query("SELECT * FROM ai_calls" + where + " ORDER BY started_at", params)]
        for row in rows:
            row.pop("config_digest", None)
        def aggregate(items):
            known = sum(r["cost_cny"] or 0 for r in items)
            unknown = sum(r["cost_cny"] is None for r in items)
            return {"calls": len(items), "input_tokens": sum(r["input_tokens"] or 0 for r in items),
                    "output_tokens": sum(r["output_tokens"] or 0 for r in items), "cost_cny": known,
                    "reserved_cny": sum(r["reserved_cny"] for r in items), "unknown_usage_calls": unknown,
                    "complete": unknown == 0, "account_charge_cny": None, "cost_basis": "provider_usage_configured_price"}
        total_row = self.db.query_one("SELECT COALESCE(SUM(COALESCE(cost_cny,0)+reserved_cny),0) spend FROM ai_calls")
        committed = total_row["spend"]
        budget = self._settings["budget_cny"]
        return {"overall": aggregate(rows), "by_role": {role: aggregate([r for r in rows if r["role"] == role]) for role in ROLES},
                "by_provider": {provider: aggregate([r for r in rows if r["provider"] == provider]) for provider in ROLE_PROVIDERS.values()},
                "budget": {"budget_cny": budget, "committed_cny": committed, "remaining_cny": max(0, budget - committed),
                           "warning": committed >= budget * self._settings["warning_ratio"], "exhausted": committed >= budget,
                           "account_balance_cny": None}, "calls": rows}
