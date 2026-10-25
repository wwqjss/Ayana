"""Import compatibility for retired planner/reviewer model execution.

No provider configuration, credential loading, budget reservation, account
verification or network implementation remains. Historical costs are read by
legacy_history and the shared manual LLM service remains independent.
"""
from __future__ import annotations

from .legacy_history import RetiredAutonomyError

ROLES = ("planner", "reviewer_kimi", "reviewer_deepseek")
ProviderError = RetiredAutonomyError


class ProviderRegistry:
    """Removed model service. Even bypassing construction grants no capability."""

    def __init__(self, *args, **kwargs):
        raise RetiredAutonomyError()

    def ensure_schema(self, *args, **kwargs):
        raise RetiredAutonomyError()

    def client(self, *args, **kwargs):
        raise RetiredAutonomyError()

    def public_config(self, *args, **kwargs):
        raise RetiredAutonomyError()

    def update_config(self, *args, **kwargs):
        raise RetiredAutonomyError()

    async def verify_account(self, *args, **kwargs):
        raise RetiredAutonomyError()

    async def call_json(self, *args, **kwargs):
        raise RetiredAutonomyError()

    def recover_inflight(self, *args, **kwargs):
        raise RetiredAutonomyError()

    def usage_summary(self, *args, **kwargs):
        raise RetiredAutonomyError()
