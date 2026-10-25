"""Import compatibility for the permanently retired pre-P4.4 autonomous engine.

Historical data is available through legacy_history. This module performs no
planning, model calls, investigation, voting, recovery or action execution.
"""
from __future__ import annotations

from .legacy_history import RetiredAutonomyError


class AutonomyEngine:
    """Removed execution service. Direct construction and calls fail closed."""

    def __init__(self, *args, **kwargs):
        raise RetiredAutonomyError()

    async def tick(self, *args, **kwargs):
        raise RetiredAutonomyError()

    def poll_verifications(self, *args, **kwargs):
        raise RetiredAutonomyError()

    def recover_inflight(self, *args, **kwargs):
        raise RetiredAutonomyError()

    def ready_incident_ids(self, *args, **kwargs):
        raise RetiredAutonomyError()

    def snapshot(self, *args, **kwargs):
        raise RetiredAutonomyError()

    def release_manual_barrier(self, *args, **kwargs):
        raise RetiredAutonomyError()
